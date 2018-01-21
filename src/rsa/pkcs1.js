import { RSA_reset, RSA_encrypt, RSA_decrypt } from './rsa';
import { Random_getValues } from '../random/random';
import { is_buffer, is_bytes, is_number, is_string, string_to_bytes } from '../utils';
import { IllegalArgumentError, IllegalStateError, SecurityError } from '../errors';

export function RSA_OAEP(options) {
  options = options || {};

  if (!options.hash) throw new SyntaxError("option 'hash' is required");

  if (!options.hash.HASH_SIZE) throw new SyntaxError("option 'hash' supplied doesn't seem to be a valid hash function");

  this.hash = options.hash;

  this.label = null;

  this.reset(options);
}

function RSA_OAEP_reset(options) {
  options = options || {};

  var label = options.label;
  if (label !== undefined) {
    if (is_buffer(label) || is_bytes(label)) {
      label = new Uint8Array(label);
    } else if (is_string(label)) {
      label = string_to_bytes(label);
    } else {
      throw new TypeError('unexpected label type');
    }

    this.label = label.length > 0 ? label : null;
  } else {
    this.label = null;
  }

  RSA_reset.call(this, options);
}

function RSA_OAEP_encrypt(data) {
  if (!this.key) throw new IllegalStateError('no key is associated with the instance');

  var key_size = Math.ceil(this.key[0].bitLength / 8),
    hash_size = this.hash.HASH_SIZE,
    data_length = data.byteLength || data.length || 0,
    ps_length = key_size - data_length - 2 * hash_size - 2;

  if (data_length > key_size - 2 * this.hash.HASH_SIZE - 2) throw new IllegalArgumentError('data too large');

  var message = new Uint8Array(key_size),
    seed = message.subarray(1, hash_size + 1),
    data_block = message.subarray(hash_size + 1);

  if (is_bytes(data)) {
    data_block.set(data, hash_size + ps_length + 1);
  } else if (is_buffer(data)) {
    data_block.set(new Uint8Array(data), hash_size + ps_length + 1);
  } else if (is_string(data)) {
    data_block.set(string_to_bytes(data), hash_size + ps_length + 1);
  } else {
    throw new TypeError('unexpected data type');
  }

  data_block.set(
    this.hash
      .reset()
      .process(this.label || '')
      .finish().result,
    0,
  );
  data_block[hash_size + ps_length] = 1;

  Random_getValues(seed);

  var data_block_mask = RSA_MGF1_generate.call(this, seed, data_block.length);
  for (var i = 0; i < data_block.length; i++) data_block[i] ^= data_block_mask[i];

  var seed_mask = RSA_MGF1_generate.call(this, data_block, seed.length);
  for (var i = 0; i < seed.length; i++) seed[i] ^= seed_mask[i];

  RSA_encrypt.call(this, message);

  return this;
}

function RSA_OAEP_decrypt(data) {
  if (!this.key) throw new IllegalStateError('no key is associated with the instance');

  var key_size = Math.ceil(this.key[0].bitLength / 8),
    hash_size = this.hash.HASH_SIZE,
    data_length = data.byteLength || data.length || 0;

  if (data_length !== key_size) throw new IllegalArgumentError('bad data');

  RSA_decrypt.call(this, data);

  var z = this.result[0],
    seed = this.result.subarray(1, hash_size + 1),
    data_block = this.result.subarray(hash_size + 1);

  if (z !== 0) throw new SecurityError('decryption failed');

  var seed_mask = RSA_MGF1_generate.call(this, data_block, seed.length);
  for (var i = 0; i < seed.length; i++) seed[i] ^= seed_mask[i];

  var data_block_mask = RSA_MGF1_generate.call(this, seed, data_block.length);
  for (var i = 0; i < data_block.length; i++) data_block[i] ^= data_block_mask[i];

  var lhash = this.hash
    .reset()
    .process(this.label || '')
    .finish().result;
  for (var i = 0; i < hash_size; i++) {
    if (lhash[i] !== data_block[i]) throw new SecurityError('decryption failed');
  }

  var ps_end = hash_size;
  for (; ps_end < data_block.length; ps_end++) {
    var psz = data_block[ps_end];
    if (psz === 1) break;
    if (psz !== 0) throw new SecurityError('decryption failed');
  }
  if (ps_end === data_block.length) throw new SecurityError('decryption failed');

  this.result = data_block.subarray(ps_end + 1);

  return this;
}

function RSA_MGF1_generate(seed, length) {
  seed = seed || '';
  length = length || 0;

  var hash_size = this.hash.HASH_SIZE;
  //    if ( length > (hash_size * 0x100000000) )
  //        throw new IllegalArgumentError("mask length too large");

  var mask = new Uint8Array(length),
    counter = new Uint8Array(4),
    chunks = Math.ceil(length / hash_size);
  for (var i = 0; i < chunks; i++) {
    (counter[0] = i >>> 24), (counter[1] = (i >>> 16) & 255), (counter[2] = (i >>> 8) & 255), (counter[3] = i & 255);

    var submask = mask.subarray(i * hash_size);

    var chunk = this.hash
      .reset()
      .process(seed)
      .process(counter)
      .finish().result;
    if (chunk.length > submask.length) chunk = chunk.subarray(0, submask.length);

    submask.set(chunk);
  }

  return mask;
}

export function RSA_PSS(options) {
  options = options || {};

  if (!options.hash) throw new SyntaxError("option 'hash' is required");

  if (!options.hash.HASH_SIZE) throw new SyntaxError("option 'hash' supplied doesn't seem to be a valid hash function");

  this.hash = options.hash;

  this.saltLength = 4;

  this.reset(options);
}

function RSA_PSS_reset(options) {
  options = options || {};

  RSA_reset.call(this, options);

  var slen = options.saltLength;
  if (slen !== undefined) {
    if (!is_number(slen) || slen < 0) throw new TypeError('saltLength should be a non-negative number');

    if (this.key !== null && Math.ceil((this.key[0].bitLength - 1) / 8) < this.hash.HASH_SIZE + slen + 2)
      throw new SyntaxError('saltLength is too large');

    this.saltLength = slen;
  } else {
    this.saltLength = 4;
  }
}

function RSA_PSS_sign(data) {
  if (!this.key) throw new IllegalStateError('no key is associated with the instance');

  var key_bits = this.key[0].bitLength,
    hash_size = this.hash.HASH_SIZE,
    message_length = Math.ceil((key_bits - 1) / 8),
    salt_length = this.saltLength,
    ps_length = message_length - salt_length - hash_size - 2;

  var message = new Uint8Array(message_length),
    h_block = message.subarray(message_length - hash_size - 1, message_length - 1),
    d_block = message.subarray(0, message_length - hash_size - 1),
    d_salt = d_block.subarray(ps_length + 1);

  var m_block = new Uint8Array(8 + hash_size + salt_length),
    m_hash = m_block.subarray(8, 8 + hash_size),
    m_salt = m_block.subarray(8 + hash_size);

  m_hash.set(
    this.hash
      .reset()
      .process(data)
      .finish().result,
  );

  if (salt_length > 0) Random_getValues(m_salt);

  d_block[ps_length] = 1;
  d_salt.set(m_salt);

  h_block.set(
    this.hash
      .reset()
      .process(m_block)
      .finish().result,
  );

  var d_block_mask = RSA_MGF1_generate.call(this, h_block, d_block.length);
  for (var i = 0; i < d_block.length; i++) d_block[i] ^= d_block_mask[i];

  message[message_length - 1] = 0xbc;

  var zbits = 8 * message_length - key_bits + 1;
  if (zbits % 8) message[0] &= 0xff >>> zbits;

  RSA_decrypt.call(this, message);

  return this;
}

function RSA_PSS_verify(signature, data) {
  if (!this.key) throw new IllegalStateError('no key is associated with the instance');

  var key_bits = this.key[0].bitLength,
    hash_size = this.hash.HASH_SIZE,
    message_length = Math.ceil((key_bits - 1) / 8),
    salt_length = this.saltLength,
    ps_length = message_length - salt_length - hash_size - 2;

  RSA_encrypt.call(this, signature);

  var message = this.result;
  if (message[message_length - 1] !== 0xbc) throw new SecurityError('bad signature');

  var h_block = message.subarray(message_length - hash_size - 1, message_length - 1),
    d_block = message.subarray(0, message_length - hash_size - 1),
    d_salt = d_block.subarray(ps_length + 1);

  var zbits = 8 * message_length - key_bits + 1;
  if (zbits % 8 && message[0] >>> (8 - zbits)) throw new SecurityError('bad signature');

  var d_block_mask = RSA_MGF1_generate.call(this, h_block, d_block.length);
  for (var i = 0; i < d_block.length; i++) d_block[i] ^= d_block_mask[i];

  if (zbits % 8) message[0] &= 0xff >>> zbits;

  for (var i = 0; i < ps_length; i++) {
    if (d_block[i] !== 0) throw new SecurityError('bad signature');
  }
  if (d_block[ps_length] !== 1) throw new SecurityError('bad signature');

  var m_block = new Uint8Array(8 + hash_size + salt_length),
    m_hash = m_block.subarray(8, 8 + hash_size),
    m_salt = m_block.subarray(8 + hash_size);

  m_hash.set(
    this.hash
      .reset()
      .process(data)
      .finish().result,
  );
  m_salt.set(d_salt);

  var h_block_verify = this.hash
    .reset()
    .process(m_block)
    .finish().result;
  for (var i = 0; i < hash_size; i++) {
    if (h_block[i] !== h_block_verify[i]) throw new SecurityError('bad signature');
  }

  return this;
}

function RSA_PKCS1_v1_5(options) {
  options = options || {};

  if (!options.hash) throw new SyntaxError("option 'hash' is required");

  if (!options.hash.HASH_SIZE) throw new SyntaxError("option 'hash' supplied doesn't seem to be a valid hash function");

  this.hash = options.hash;

  this.reset(options);
}

function RSA_PKCS1_v1_5_reset(options) {
  options = options || {};

  RSA_reset.call(this, options);
}

var HASH_PREFIXES = {
  sha1: new Uint8Array([0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]),
  sha256: new Uint8Array([
    0x30,
    0x31,
    0x30,
    0x0d,
    0x06,
    0x09,
    0x60,
    0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
    0x01,
    0x05,
    0x00,
    0x04,
    0x20,
  ]),
  sha384: new Uint8Array([
    0x30,
    0x41,
    0x30,
    0x0d,
    0x06,
    0x09,
    0x60,
    0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
    0x02,
    0x05,
    0x00,
    0x04,
    0x30,
  ]),
  sha512: new Uint8Array([
    0x30,
    0x51,
    0x30,
    0x0d,
    0x06,
    0x09,
    0x60,
    0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
    0x03,
    0x05,
    0x00,
    0x04,
    0x40,
  ]),
};

function getHashPrefix(hash) {
  var hashName = hash.constructor.NAME;
  var prefix = HASH_PREFIXES[hashName];
  if (!prefix) {
    throw new Error("Cannot get hash prefix for hash algorithm '" + hashName + "'");
  }
  return prefix;
}

function RSA_PKCS1_v1_5_sign(data) {
  if (!this.key) {
    throw new IllegalStateError('no key is associated with the instance');
  }
  var prefix = getHashPrefix(this.hash);
  var hash_size = this.hash.HASH_SIZE;

  var t_len = prefix.length + hash_size;
  var k = (this.key[0].bitLength + 7) >> 3;
  if (k < t_len + 11) {
    throw new Error('Message too long');
  }

  var m_hash = new Uint8Array(hash_size);
  m_hash.set(
    this.hash
      .reset()
      .process(data)
      .finish().result,
  );

  // EM = 0x00 || 0x01 || PS || 0x00 || T
  var em = new Uint8Array(k);
  var i = 0;
  em[i++] = 0; // 0x00
  em[i++] = 1; // 0x01
  // PS
  for (i; i < k - t_len - 1; i++) {
    em[i] = 0xff;
  }
  em[i++] = 0;
  em.set(prefix, i); // 0x00
  // T
  em.set(m_hash, em.length - hash_size);

  RSA_decrypt.call(this, em);

  return this;
}

function RSA_PKCS1_v1_5_verify(signature, data) {
  if (!this.key) {
    throw new IllegalStateError('no key is associated with the instance');
  }
  var prefix = getHashPrefix(this.hash);
  var hash_size = this.hash.HASH_SIZE;

  var t_len = prefix.length + hash_size;
  var k = (this.key[0].bitLength + 7) >> 3;
  if (k < t_len + 11) {
    throw new SecurityError('Bad signature');
  }

  RSA_encrypt.call(this, signature);

  var m_hash = new Uint8Array(hash_size);
  m_hash.set(
    this.hash
      .reset()
      .process(data)
      .finish().result,
  );

  var res = 1;
  // EM = 0x00 || 0x01 || PS || 0x00 || T
  var decryptedSignature = this.result;
  var i = 0;
  res &= decryptedSignature[i++] === 0; // 0x00
  res &= decryptedSignature[i++] === 1; // 0x01
  // PS
  for (i; i < k - t_len - 1; i++) {
    res &= decryptedSignature[i] === 0xff;
  }
  res &= decryptedSignature[i++] === 0; // 0x00
  // T
  var j = 0;
  var n = i + prefix.length;
  // prefix
  for (i; i < n; i++) {
    res &= decryptedSignature[i] === prefix[j++];
  }
  j = 0;
  n = i + m_hash.length;
  // hash
  for (i; i < n; i++) {
    res &= decryptedSignature[i] === m_hash[j++];
  }

  if (!res) {
    throw new SecurityError('Bad signature');
  }

  return this;
}

var RSA_OAEP_prototype = RSA_OAEP.prototype;
RSA_OAEP_prototype.reset = RSA_OAEP_reset;
RSA_OAEP_prototype.encrypt = RSA_OAEP_encrypt;
RSA_OAEP_prototype.decrypt = RSA_OAEP_decrypt;

var RSA_PSS_prototype = RSA_PSS.prototype;
RSA_PSS_prototype.reset = RSA_PSS_reset;
RSA_PSS_prototype.sign = RSA_PSS_sign;
RSA_PSS_prototype.verify = RSA_PSS_verify;

var RSA_PKCS1_v1_5_prototype = RSA_PKCS1_v1_5.prototype;
RSA_PKCS1_v1_5_prototype.reset = RSA_PKCS1_v1_5_reset;
RSA_PKCS1_v1_5_prototype.sign = RSA_PKCS1_v1_5_sign;
RSA_PKCS1_v1_5_prototype.verify = RSA_PKCS1_v1_5_verify;
