import {hmac_constructor, _hmac_key, _hmac_init_verify} from './hmac';
import {_sha1_hash_size, get_sha1_instance, sha1_constructor} from '../hash/sha1/sha1';
import {is_string, string_to_bytes} from '../utils';
import {IllegalStateError} from '../errors';

export class hmac_sha1_constructor extends hmac_constructor {
  constructor(options ) {
    options = options || {};

    if ( !( options.hash instanceof sha1_constructor ) )
      options.hash = get_sha1_instance();

    super(options);
  }

  reset(options ) {
    options = options || {};

    this.result = null;
    this.hash.reset();

    var password = options.password;
    if ( password !== undefined ) {
      if ( is_string(password) )
        password = string_to_bytes(password);

      var key = this.key = _hmac_key( this.hash, password );
      this.hash.reset().asm.hmac_init(
        (key[0]<<24)|(key[1]<<16)|(key[2]<<8)|(key[3]),
        (key[4]<<24)|(key[5]<<16)|(key[6]<<8)|(key[7]),
        (key[8]<<24)|(key[9]<<16)|(key[10]<<8)|(key[11]),
        (key[12]<<24)|(key[13]<<16)|(key[14]<<8)|(key[15]),
        (key[16]<<24)|(key[17]<<16)|(key[18]<<8)|(key[19]),
        (key[20]<<24)|(key[21]<<16)|(key[22]<<8)|(key[23]),
        (key[24]<<24)|(key[25]<<16)|(key[26]<<8)|(key[27]),
        (key[28]<<24)|(key[29]<<16)|(key[30]<<8)|(key[31]),
        (key[32]<<24)|(key[33]<<16)|(key[34]<<8)|(key[35]),
        (key[36]<<24)|(key[37]<<16)|(key[38]<<8)|(key[39]),
        (key[40]<<24)|(key[41]<<16)|(key[42]<<8)|(key[43]),
        (key[44]<<24)|(key[45]<<16)|(key[46]<<8)|(key[47]),
        (key[48]<<24)|(key[49]<<16)|(key[50]<<8)|(key[51]),
        (key[52]<<24)|(key[53]<<16)|(key[54]<<8)|(key[55]),
        (key[56]<<24)|(key[57]<<16)|(key[58]<<8)|(key[59]),
        (key[60]<<24)|(key[61]<<16)|(key[62]<<8)|(key[63])
      );
    }
    else {
      this.hash.asm.hmac_reset();
    }

    var verify = options.verify;
    if ( verify !== undefined ) {
      _hmac_init_verify.call( this, verify );
    }
    else {
      this.verify = null;
    }

    return this;
  }

  finish() {
    if ( this.key === null )
      throw new IllegalStateError("no key is associated with the instance");

    if ( this.result !== null )
      throw new IllegalStateError("state must be reset before processing new data");

    var hash = this.hash,
      asm = this.hash.asm,
      heap = this.hash.heap;

    asm.hmac_finish( hash.pos, hash.len, 0 );

    var verify = this.verify;
    var result = new Uint8Array(_sha1_hash_size);
    result.set( heap.subarray( 0, _sha1_hash_size ) );

    if ( verify ) {
      if ( verify.length === result.length ) {
        var diff = 0;
        for ( var i = 0; i < verify.length; i++ ) {
          diff |= ( verify[i] ^ result[i] );
        }
        this.result = !diff;
      } else {
        this.result = false;
      }
    }
    else {
      this.result = result;
    }

    return this;
  }
}

hmac_sha1_constructor.BLOCK_SIZE = sha1_constructor.BLOCK_SIZE;
hmac_sha1_constructor.HMAC_SIZE = sha1_constructor.HASH_SIZE;

var hmac_sha1_instance = null;

export function get_hmac_sha1_instance () {
  if ( hmac_sha1_instance === null ) hmac_sha1_instance = new hmac_sha1_constructor();
  return hmac_sha1_instance;
}
