import {AES_asm} from './aes.asm';
import {_heap_init, _heap_write, is_bytes, is_number} from '../utils';
import {IllegalArgumentError, SecurityError} from '../errors';

export class AES {
  constructor(key, iv, padding, heap, asm) {
    this.nonce = null;
    this.counter = 0;
    this.counterSize = 0;

    this.heap = _heap_init( Uint8Array, heap ).subarray( AES_asm.HEAP_DATA );
    this.asm = asm || AES_asm( null, this.heap.buffer );
    this.mode = null;
    this.key = null;

    this.AES_reset( key, iv, padding );
  }

  /**
   * @param {Uint8Array} key
   */
  AES_set_key ( key ) {
    if ( key !== undefined ) {
      if ( !is_bytes(key) ) {
        throw new TypeError("unexpected key type");
      }

      var keylen = key.length;
      if ( keylen !== 16 && keylen !== 24 && keylen !== 32 )
        throw new IllegalArgumentError("illegal key size");

      var keyview = new DataView( key.buffer, key.byteOffset, key.byteLength );
      this.asm.set_key(
        keylen >> 2,
        keyview.getUint32(0),
        keyview.getUint32(4),
        keyview.getUint32(8),
        keyview.getUint32(12),
        keylen > 16 ? keyview.getUint32(16) : 0,
        keylen > 16 ? keyview.getUint32(20) : 0,
        keylen > 24 ? keyview.getUint32(24) : 0,
        keylen > 24 ? keyview.getUint32(28) : 0
      );

      this.key = key;
    }
    else if ( !this.key ) {
      throw new Error("key is required");
    }
  }

  /**
   * This should be mixin instead of inheritance
   *
   * @param {Uint8Array} nonce
   * @param {number} [counter]
   * @param {number} [size]
   */
  AES_CTR_set_options ( nonce, counter, size ) {
    if ( size !== undefined ) {
      if ( size < 8 || size > 48 )
        throw new IllegalArgumentError("illegal counter size");

      this.counterSize = size;

      var mask = Math.pow( 2, size ) - 1;
      this.asm.set_mask( 0, 0, (mask / 0x100000000)|0, mask|0 );
    }
    else {
      this.counterSize = size = 48;
      this.asm.set_mask( 0, 0, 0xffff, 0xffffffff );
    }

    if ( nonce !== undefined ) {
      if ( !is_bytes(nonce) ) {
        throw new TypeError("unexpected nonce type");
      }

      var len = nonce.length;
      if ( !len || len > 16 )
        throw new IllegalArgumentError("illegal nonce size");

      this.nonce = nonce;

      var view = new DataView( new ArrayBuffer(16) );
      new Uint8Array(view.buffer).set(nonce);

      this.asm.set_nonce( view.getUint32(0), view.getUint32(4), view.getUint32(8), view.getUint32(12) );
    }
    else {
      throw new Error("nonce is required");
    }

    if ( counter !== undefined ) {
      if ( !is_number(counter) )
        throw new TypeError("unexpected counter type");

      if ( counter < 0 || counter >= Math.pow( 2, size ) )
        throw new IllegalArgumentError("illegal counter value");

      this.counter = counter;

      this.asm.set_counter( 0, 0, (counter / 0x100000000)|0, counter|0 );
    }
    else {
      this.counter = 0;
    }
  }

  /**
   * @param {Uint8Array} iv
   */
  AES_set_iv ( iv ) {
    if ( iv !== undefined ) {
      if ( !is_bytes(iv) ) {
        throw new TypeError("unexpected iv type");
      }

      if ( iv.length !== 16 )
        throw new IllegalArgumentError("illegal iv size");

      var ivview = new DataView( iv.buffer, iv.byteOffset, iv.byteLength );

      this.iv = iv;
      this.asm.set_iv( ivview.getUint32(0), ivview.getUint32(4), ivview.getUint32(8), ivview.getUint32(12) );
    }
    else {
      this.iv = null;
      this.asm.set_iv( 0, 0, 0, 0 );
    }
  }

  /**
   * @param {boolean} padding
   */
  AES_set_padding ( padding ) {
    if ( padding !== undefined ) {
      this.padding = !!padding;
    }
    else {
      this.padding = true;
    }
  }

  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} [iv]
   * @param {boolean} [padding]
   */
  AES_reset ( key, iv, padding ) {
    this.result = null;
    this.pos = 0;
    this.len = 0;

    this.AES_set_key( key );
    this.AES_set_iv( iv );
    this.AES_set_padding( padding );

    return this;
  }


  /**
   * @param {Uint8Array} data
   */
  AES_Encrypt_process ( data ) {
    if ( !is_bytes(data) )
      throw new TypeError("data isn't of expected type");

    var asm = this.asm,
      heap = this.heap,
      amode = AES_asm.ENC[this.mode],
      hpos = AES_asm.HEAP_DATA,
      pos = this.pos,
      len = this.len,
      dpos = 0,
      dlen = data.length || 0,
      rpos = 0,
      rlen = (len + dlen) & -16,
      wlen = 0;

    var result = new Uint8Array(rlen);

    while ( dlen > 0 ) {
      wlen = _heap_write( heap, pos+len, data, dpos, dlen );
      len  += wlen;
      dpos += wlen;
      dlen -= wlen;

      wlen = asm.cipher( amode, hpos + pos, len );

      if ( wlen ) result.set( heap.subarray( pos, pos + wlen ), rpos );
      rpos += wlen;

      if ( wlen < len ) {
        pos += wlen;
        len -= wlen;
      } else {
        pos = 0;
        len = 0;
      }
    }

    this.result = result;
    this.pos = pos;
    this.len = len;

    return this;
  }

  /**
   * @param {Uint8Array} data
   */
  AES_Encrypt_finish ( data ) {
    var presult = null,
      prlen = 0;

    if ( data !== undefined ) {
      presult = this.AES_Encrypt_process( data ).result;
      prlen = presult.length;
    }

    var asm = this.asm,
      heap = this.heap,
      amode = AES_asm.ENC[this.mode],
      hpos = AES_asm.HEAP_DATA,
      pos = this.pos,
      len = this.len,
      plen = 16 - len % 16,
      rlen = len;

    if ( this.hasOwnProperty('padding') ) {
      if ( this.padding ) {
        for ( var p = 0; p < plen; ++p ) heap[ pos + len + p ] = plen;
        len += plen;
        rlen = len;
      }
      else if ( len % 16 ) {
        throw new IllegalArgumentError("data length must be a multiple of the block size");
      }
    }
    else {
      len += plen;
    }

    var result = new Uint8Array( prlen + rlen );

    if ( prlen ) result.set( presult );

    if ( len ) asm.cipher( amode, hpos + pos, len );

    if ( rlen ) result.set( heap.subarray( pos, pos + rlen ), prlen );

    this.result = result;
    this.pos = 0;
    this.len = 0;

    return this;
  }

  /**
   * @param {Uint8Array} data
   */
  AES_Decrypt_process ( data ) {
    if ( !is_bytes(data) )
      throw new TypeError("data isn't of expected type");

    var asm = this.asm,
      heap = this.heap,
      amode = AES_asm.DEC[this.mode],
      hpos = AES_asm.HEAP_DATA,
      pos = this.pos,
      len = this.len,
      dpos = 0,
      dlen = data.length || 0,
      rpos = 0,
      rlen = (len + dlen) & -16,
      plen = 0,
      wlen = 0;

    if ( this.padding ) {
      plen = len + dlen - rlen || 16;
      rlen -= plen;
    }

    var result = new Uint8Array(rlen);

    while ( dlen > 0 ) {
      wlen = _heap_write( heap, pos+len, data, dpos, dlen );
      len  += wlen;
      dpos += wlen;
      dlen -= wlen;

      wlen = asm.cipher( amode, hpos + pos, len - ( !dlen ? plen : 0 ) );

      if ( wlen ) result.set( heap.subarray( pos, pos + wlen ), rpos );
      rpos += wlen;

      if ( wlen < len ) {
        pos += wlen;
        len -= wlen;
      } else {
        pos = 0;
        len = 0;
      }
    }

    this.result = result;
    this.pos = pos;
    this.len = len;

    return this;
  }

  /**
   * @param {Uint8Array} data
   */
  AES_Decrypt_finish ( data ) {
    var presult = null,
      prlen = 0;

    if ( data !== undefined ) {
      presult = this.AES_Decrypt_process( data ).result;
      prlen = presult.length;
    }

    var asm = this.asm,
      heap = this.heap,
      amode = AES_asm.DEC[this.mode],
      hpos = AES_asm.HEAP_DATA,
      pos = this.pos,
      len = this.len,
      rlen = len;

    if ( len > 0 ) {
      if ( len % 16 ) {
        if ( this.hasOwnProperty('padding') ) {
          throw new IllegalArgumentError("data length must be a multiple of the block size");
        } else {
          len += 16 - len % 16;
        }
      }

      asm.cipher( amode, hpos + pos, len );

      if ( this.hasOwnProperty('padding') && this.padding ) {
        var pad = heap[ pos + rlen - 1 ];
        if ( pad < 1 || pad > 16 || pad > rlen )
          throw new SecurityError("bad padding");

        var pcheck = 0;
        for ( var i = pad; i > 1; i-- ) pcheck |= pad ^ heap[ pos + rlen - i ];
        if ( pcheck )
          throw new SecurityError("bad padding");

        rlen -= pad;
      }
    }

    var result = new Uint8Array( prlen + rlen );

    if ( prlen > 0 ) {
      result.set( presult );
    }

    if ( rlen > 0 ) {
      result.set( heap.subarray( pos, pos + rlen ), prlen );
    }

    this.result = result;
    this.pos = 0;
    this.len = 0;

    return this;
  }
}




