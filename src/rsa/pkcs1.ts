import { RSA } from './rsa';
import { IllegalArgumentError, IllegalStateError, SecurityError } from '../other/errors';
import { Sha512 } from '../hash/sha512/sha512';
import { Sha1 } from '../hash/sha1/sha1';
import { Sha256 } from '../hash/sha256/sha256';
import { BigNumber } from '../bignum/bignum';
import { getRandomValues } from '../other/get-random-values';

export class RSA_OAEP {
  private readonly rsa: RSA;
  private readonly label: Uint8Array | null;
  private readonly hash: Sha1 | Sha256 | Sha512;

  constructor(key: Uint8Array[], hash: Sha1 | Sha256 | Sha512, label?: Uint8Array) {
    this.rsa = new RSA(key);

    this.hash = hash;

    if (label !== undefined) {
      this.label = label.length > 0 ? label : null;
    } else {
      this.label = null;
    }
  }

  encrypt(data: Uint8Array): Uint8Array {
    const key_size = Math.ceil(this.rsa.key[0].bitLength / 8);
    const hash_size = this.hash.HASH_SIZE;
    const data_length = data.byteLength || data.length || 0;
    const ps_length = key_size - data_length - 2 * hash_size - 2;

    if (data_length > key_size - 2 * this.hash.HASH_SIZE - 2) throw new IllegalArgumentError('data too large');

    const message = new Uint8Array(key_size);
    const seed = message.subarray(1, hash_size + 1);
    const data_block = message.subarray(hash_size + 1);

    data_block.set(data, hash_size + ps_length + 1);

    data_block.set(this.hash.process(this.label || new Uint8Array(0)).finish().result as Uint8Array, 0);
    data_block[hash_size + ps_length] = 1;

    getRandomValues(seed);

    const data_block_mask = this.RSA_MGF1_generate(seed, data_block.length);
    for (let i = 0; i < data_block.length; i++) data_block[i] ^= data_block_mask[i];

    const seed_mask = this.RSA_MGF1_generate(data_block, seed.length);
    for (let i = 0; i < seed.length; i++) seed[i] ^= seed_mask[i];

    this.rsa.encrypt(new BigNumber(message));

    return new Uint8Array(this.rsa.result);
  }

  decrypt(data: Uint8Array): Uint8Array {
    if (!this.rsa.key) throw new IllegalStateError('no key is associated with the instance');

    const key_size = Math.ceil(this.rsa.key[0].bitLength / 8);
    const hash_size = this.hash.HASH_SIZE;
    const data_length = data.byteLength || data.length || 0;

    if (data_length !== key_size) throw new IllegalArgumentError('bad data');

    this.rsa.decrypt(new BigNumber(data));

    const z = this.rsa.result[0];
    const seed = this.rsa.result.subarray(1, hash_size + 1);
    const data_block = this.rsa.result.subarray(hash_size + 1);

    if (z !== 0) throw new SecurityError('decryption failed');

    const seed_mask = this.RSA_MGF1_generate(data_block, seed.length);
    for (let i = 0; i < seed.length; i++) seed[i] ^= seed_mask[i];

    const data_block_mask = this.RSA_MGF1_generate(seed, data_block.length);
    for (let i = 0; i < data_block.length; i++) data_block[i] ^= data_block_mask[i];

    const lhash = this.hash
      .reset()
      .process(this.label || new Uint8Array(0))
      .finish().result as Uint8Array;
    for (let i = 0; i < hash_size; i++) {
      if (lhash[i] !== data_block[i]) throw new SecurityError('decryption failed');
    }

    let ps_end = hash_size;
    for (; ps_end < data_block.length; ps_end++) {
      const psz = data_block[ps_end];
      if (psz === 1) break;
      if (psz !== 0) throw new SecurityError('decryption failed');
    }
    if (ps_end === data_block.length) throw new SecurityError('decryption failed');

    this.rsa.result = data_block.subarray(ps_end + 1);

    return new Uint8Array(this.rsa.result);
  }

  RSA_MGF1_generate(seed: Uint8Array, length: number = 0): Uint8Array {
    const hash_size = this.hash.HASH_SIZE;
    //    if ( length > (hash_size * 0x100000000) )
    //        throw new IllegalArgumentError("mask length too large");

    const mask = new Uint8Array(length);
    const counter = new Uint8Array(4);
    const chunks = Math.ceil(length / hash_size);
    for (let i = 0; i < chunks; i++) {
      (counter[0] = i >>> 24), (counter[1] = (i >>> 16) & 255), (counter[2] = (i >>> 8) & 255), (counter[3] = i & 255);

      const submask = mask.subarray(i * hash_size);

      let chunk = this.hash
        .reset()
        .process(seed)
        .process(counter)
        .finish().result as Uint8Array;
      if (chunk.length > submask.length) chunk = chunk.subarray(0, submask.length);

      submask.set(chunk);
    }

    return mask;
  }
}

export class RSA_PSS {
  private readonly rsa: RSA;
  private readonly saltLength: number;
  private readonly hash: Sha1 | Sha256 | Sha512;

  constructor(key: Uint8Array[], hash: Sha1 | Sha256 | Sha512, saltLength: number = 4) {
    this.rsa = new RSA(key);

    this.hash = hash;
    this.saltLength = saltLength;

    if (this.saltLength < 0) throw new TypeError('saltLength should be a non-negative number');

    if (
      this.rsa.key !== null &&
      Math.ceil((this.rsa.key[0].bitLength - 1) / 8) < this.hash.HASH_SIZE + this.saltLength + 2
    )
      throw new SyntaxError('saltLength is too large');
  }

  sign(data: Uint8Array): Uint8Array {
    const key_bits = this.rsa.key[0].bitLength;
    const hash_size = this.hash.HASH_SIZE;
    const message_length = Math.ceil((key_bits - 1) / 8);
    const salt_length = this.saltLength;
    const ps_length = message_length - salt_length - hash_size - 2;

    const message = new Uint8Array(message_length);
    const h_block = message.subarray(message_length - hash_size - 1, message_length - 1);
    const d_block = message.subarray(0, message_length - hash_size - 1);
    const d_salt = d_block.subarray(ps_length + 1);

    const m_block = new Uint8Array(8 + hash_size + salt_length);
    const m_hash = m_block.subarray(8, 8 + hash_size);
    const m_salt = m_block.subarray(8 + hash_size);

    m_hash.set(this.hash.process(data).finish().result as Uint8Array);

    if (salt_length > 0) getRandomValues(m_salt);

    d_block[ps_length] = 1;
    d_salt.set(m_salt);

    h_block.set(this.hash
      .reset()
      .process(m_block)
      .finish().result as Uint8Array);

    const d_block_mask = this.RSA_MGF1_generate(h_block, d_block.length);
    for (let i = 0; i < d_block.length; i++) d_block[i] ^= d_block_mask[i];

    message[message_length - 1] = 0xbc;

    const zbits = 8 * message_length - key_bits + 1;
    if (zbits % 8) message[0] &= 0xff >>> zbits;

    this.rsa.decrypt(new BigNumber(message));

    return this.rsa.result;
  }

  verify(signature: Uint8Array, data: Uint8Array): void {
    const key_bits = this.rsa.key[0].bitLength;
    const hash_size = this.hash.HASH_SIZE;
    const message_length = Math.ceil((key_bits - 1) / 8);
    const salt_length = this.saltLength;
    const ps_length = message_length - salt_length - hash_size - 2;

    this.rsa.encrypt(new BigNumber(signature));

    const message = this.rsa.result;
    if (message[message_length - 1] !== 0xbc) throw new SecurityError('bad signature');

    const h_block = message.subarray(message_length - hash_size - 1, message_length - 1);
    const d_block = message.subarray(0, message_length - hash_size - 1);
    const d_salt = d_block.subarray(ps_length + 1);

    const zbits = 8 * message_length - key_bits + 1;
    if (zbits % 8 && message[0] >>> (8 - zbits)) throw new SecurityError('bad signature');

    const d_block_mask = this.RSA_MGF1_generate(h_block, d_block.length);
    for (let i = 0; i < d_block.length; i++) d_block[i] ^= d_block_mask[i];

    if (zbits % 8) message[0] &= 0xff >>> zbits;

    for (let i = 0; i < ps_length; i++) {
      if (d_block[i] !== 0) throw new SecurityError('bad signature');
    }
    if (d_block[ps_length] !== 1) throw new SecurityError('bad signature');

    const m_block = new Uint8Array(8 + hash_size + salt_length);
    const m_hash = m_block.subarray(8, 8 + hash_size);
    const m_salt = m_block.subarray(8 + hash_size);

    m_hash.set(this.hash
      .reset()
      .process(data)
      .finish().result as Uint8Array);
    m_salt.set(d_salt);

    const h_block_verify = this.hash
      .reset()
      .process(m_block)
      .finish().result as Uint8Array;
    for (let i = 0; i < hash_size; i++) {
      if (h_block[i] !== h_block_verify[i]) throw new SecurityError('bad signature');
    }
  }

  RSA_MGF1_generate(seed: Uint8Array, length: number = 0): Uint8Array {
    const hash_size = this.hash.HASH_SIZE;
    //    if ( length > (hash_size * 0x100000000) )
    //        throw new IllegalArgumentError("mask length too large");

    const mask = new Uint8Array(length);
    const counter = new Uint8Array(4);
    const chunks = Math.ceil(length / hash_size);
    for (let i = 0; i < chunks; i++) {
      (counter[0] = i >>> 24), (counter[1] = (i >>> 16) & 255), (counter[2] = (i >>> 8) & 255), (counter[3] = i & 255);

      const submask = mask.subarray(i * hash_size);

      let chunk = this.hash
        .reset()
        .process(seed)
        .process(counter)
        .finish().result as Uint8Array;
      if (chunk.length > submask.length) chunk = chunk.subarray(0, submask.length);

      submask.set(chunk);
    }

    return mask;
  }
}

export class RSA_PKCS1_v1_5 {
  private readonly rsa: RSA;
  private readonly hash: Sha1 | Sha256 | Sha512;
  constructor(key: Uint8Array[], hash: Sha1 | Sha256 | Sha512) {
    this.rsa = new RSA(key);
    this.hash = hash;
  }

  sign(data: Uint8Array): Uint8Array {
    if (!this.rsa.key) {
      throw new IllegalStateError('no key is associated with the instance');
    }
    const prefix = getHashPrefix(this.hash);
    const hash_size = this.hash.HASH_SIZE;

    const t_len = prefix.length + hash_size;
    const k = (this.rsa.key[0].bitLength + 7) >> 3;
    if (k < t_len + 11) {
      throw new Error('Message too long');
    }

    const m_hash = new Uint8Array(hash_size);
    m_hash.set(this.hash.process(data).finish().result as Uint8Array);

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    const em = new Uint8Array(k);
    let i = 0;
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

    this.rsa.decrypt(new BigNumber(em));

    return this.rsa.result;
  }

  verify(signature: Uint8Array, data: Uint8Array): void {
    const prefix = getHashPrefix(this.hash);
    const hash_size = this.hash.HASH_SIZE;

    const t_len = prefix.length + hash_size;
    const k = (this.rsa.key[0].bitLength + 7) >> 3;
    if (k < t_len + 11) {
      throw new SecurityError('Bad signature');
    }

    this.rsa.encrypt(new BigNumber(signature));

    const m_hash = new Uint8Array(hash_size);
    m_hash.set(this.hash.process(data).finish().result as Uint8Array);

    let res = 1;
    // EM = 0x00 || 0x01 || PS || 0x00 || T
    const decryptedSignature = this.rsa.result;
    let i = 0;
    res &= decryptedSignature[i++] === 0 ? 1 : 0; // 0x00
    res &= decryptedSignature[i++] === 1 ? 1 : 0; // 0x01
    // PS
    for (i; i < k - t_len - 1; i++) {
      res &= decryptedSignature[i] === 0xff ? 1 : 0;
    }
    res &= decryptedSignature[i++] === 0 ? 1 : 0; // 0x00
    // T
    let j = 0;
    let n = i + prefix.length;
    // prefix
    for (i; i < n; i++) {
      res &= decryptedSignature[i] === prefix[j++] ? 1 : 0;
    }
    j = 0;
    n = i + m_hash.length;
    // hash
    for (i; i < n; i++) {
      res &= decryptedSignature[i] === m_hash[j++] ? 1 : 0;
    }

    if (!res) {
      throw new SecurityError('Bad signature');
    }
  }
}

const HASH_PREFIXES: {
  sha1: Uint8Array;
  sha256: Uint8Array;
  sha384: Uint8Array;
  sha512: Uint8Array;
  [key: string]: Uint8Array;
} = {
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

function getHashPrefix(hash: Sha1 | Sha256 | Sha512): Uint8Array {
  const prefix = HASH_PREFIXES[hash.NAME];
  if (!prefix) {
    throw new Error("Cannot get hash prefix for hash algorithm '" + hash.NAME + "'");
  }
  return prefix;
}
