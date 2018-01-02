/**
 * Counter with CBC-MAC (CCM)
 *
 * Due to JS limitations (52 bits of Number precision) maximum encrypted message length
 * is limited to ~4 PiB ( 2^52 - 16 ) per `nonce`-`key` pair.
 * That also limits `lengthSize` parameter maximum value to 7 (not 8 as described in RFC3610).
 *
 * Additional authenticated data `adata` maximum length is choosen to be no more than 65279 bytes ( 2^16 - 2^8 ),
 * wich is considered enough for the most of use-cases.
 *
 * And one more important thing: in case of progressive ciphering of a data stream (in other
 * words when data can't be held in-memory at a whole and are ciphered chunk-by-chunk)
 * you have to know the `dataLength` in advance and pass that value to the cipher options.
 */

import { AES_asm} from '../aes.asm'
import { AES } from '../aes'
import {_heap_write, is_bytes, is_number} from '../../utils';
import {IllegalArgumentError, IllegalStateError, SecurityError} from '../../errors';

var _AES_CCM_adata_maxLength = 65279,            // 2^16 - 2^8
    _AES_CCM_data_maxLength = 4503599627370480;  // 2^52 - 2^4

export class AES_CCM extends AES {
  constructor(key, nonce, adata, tagSize, dataLength, heap, asm ) {
    super(key, undefined, undefined, heap, asm);
    this.tagSize    = 16;
    this.lengthSize = 4;
    this.nonce      = null;
    this.adata      = null;
    this.iv         = null;
    this.counter    = 1;
    this.dataLength = -1;

    this.AES_CCM_reset(key, undefined, nonce, adata, undefined, undefined, tagSize, dataLength);

    this.mode       = 'CCM';
    this.BLOCK_SIZE = 16;
  }

  encrypt(data) {
    return this.AES_CCM_encrypt(data);
  }
  decrypt(data) {
    return this.AES_CCM_decrypt(data);
  }

  AES_CCM_reset ( key, iv, nonce, adata, counter, lengthSize, tagSize, dataLength) {

    this.AES_reset(key, iv);

    if ( tagSize !== undefined ) {
      if ( !is_number(tagSize) )
        throw new TypeError("tagSize must be a number");

      if ( tagSize < 4 || tagSize > 16 || tagSize & 1 )
        throw new IllegalArgumentError("illegal tagSize value");

      this.tagSize = tagSize;
    }
    else {
      this.tagSize = 16;
    }

    if ( nonce !== undefined ) {
      if ( !is_bytes(nonce)) {
        throw new TypeError("unexpected nonce type");
      }

      if ( nonce.length < 8 || nonce.length > 13 )
        throw new IllegalArgumentError("illegal nonce length");

      this.nonce = nonce;
      this.lengthSize = lengthSize = 15 - nonce.length;

      nonce = new Uint8Array( nonce.length + 1 );
      nonce[0] = lengthSize - 1, nonce.set( this.nonce, 1 );
    }
    else {
      throw new Error("nonce is required");
    }

    // Either counter, iv
    if ( iv !== undefined ) {
      if ( adata !== undefined )
        throw new IllegalStateError("you should specify either adata or iv, not both");

      if ( !is_number(counter) )
        throw new TypeError("counter must be a number");

      if ( counter < 1 || counter >= ( Math.pow( 2, 8*lengthSize ) - 16 ) )
        throw new IllegalArgumentError("illegal counter value");

      this.counter = counter;
    }
    // Or adata, dataLength
    else if ( adata !== undefined && adata !== null ) {
      if ( !is_bytes(adata) ) {
        throw new TypeError("unexpected adata type");
      }

      if ( adata.length > _AES_CCM_adata_maxLength )
        throw new IllegalArgumentError("illegal adata length");

      if ( !is_number(dataLength) )
        throw new TypeError("dataLength must be a number");

      if ( dataLength < 0 || dataLength > _AES_CCM_data_maxLength || dataLength > ( Math.pow( 2, 8*lengthSize ) - 16 ) )
        throw new IllegalArgumentError("illegal dataLength value");

      this.adata = adata.length ? adata : null;
      this.dataLength = dataLength;
      this.counter = counter = 1;

      this.AES_CCM_calculate_iv();
      iv = this.iv;
    }
    // Assume adata is empty, check dataLength
    else {
      if ( !is_number(dataLength) )
        throw new TypeError("dataLength must be a number");

      if ( dataLength < 0 || dataLength > _AES_CCM_data_maxLength || dataLength > ( Math.pow( 2, 8*lengthSize ) - 16 ) )
        throw new IllegalArgumentError("illegal dataLength value");

      this.adata = null;
      this.dataLength = dataLength;
      this.counter = counter = 1;

      this.AES_CCM_calculate_iv();
      iv = this.iv;
    }

    this.AES_set_iv( iv );
    this.AES_CTR_set_options( nonce, counter, 8*lengthSize );

    return this;
  }

  AES_CCM_calculate_iv () {
    var nonce = this.nonce,
      adata = this.adata,
      tagSize = this.tagSize,
      lengthSize = this.lengthSize,
      dataLength = this.dataLength;

    var data = new Uint8Array( 16 + ( adata ? 2 + adata.length : 0 ) );

    // B0: flags(adata?, M', L'), nonce, len(data)
    data[0] = ( adata ? 64 : 0 ) | ( (tagSize-2)<<2 ) | ( lengthSize-1 );
    data.set( nonce, 1 );
    if (lengthSize > 6) data[9]  = ( dataLength / 0x100000000 )>>>16&15;
    if (lengthSize > 5) data[10] = ( dataLength / 0x100000000 )>>>8&255;
    if (lengthSize > 4) data[11] = ( dataLength / 0x100000000 )&255;
    if (lengthSize > 3) data[12] = dataLength>>>24;
    if (lengthSize > 2) data[13] = dataLength>>>16&255;
    data[14] = dataLength>>>8&255;
    data[15] = dataLength&255;

    // B*: len(adata), adata
    if ( adata ) {
      data[16] = adata.length>>>8&255;
      data[17] = adata.length&255;
      data.set( adata, 18 );
    }

    this._cbc_mac_process( data );
    this.asm.get_state( AES_asm.HEAP_DATA );

    this.iv = new Uint8Array( this.heap.subarray( 0, 16 ) );
  }

  _cbc_mac_process ( data ) {
    var heap = this.heap,
      asm  = this.asm,
      dpos = 0,
      dlen = data.length || 0,
      wlen = 0;

    while ( dlen > 0 ) {
      wlen = _heap_write( heap, 0, data, dpos, dlen );
      while ( wlen & 15 ) heap[ wlen++ ] = 0;
      dpos += wlen;
      dlen -= wlen;

      asm.mac( AES_asm.MAC.CBC, AES_asm.HEAP_DATA, wlen );
    }
  }

  AES_CCM_decrypt ( data ) {
    this.dataLength = data.length || 0;

    var result1 = this.AES_CCM_Decrypt_process( data ).result;
    var result2 = this.AES_CCM_Decrypt_finish().result;

    var result = new Uint8Array( result1.length + result2.length );
    if ( result1.length ) result.set(result1);
    if ( result2.length ) result.set( result2, result1.length );
    this.result = result;

    return this;
  }

  AES_CCM_encrypt ( data ) {
    this.dataLength = data.length || 0;

    var result1 = this.AES_CCM_Encrypt_process( data ).result;
    var result2 = this.AES_CCM_Encrypt_finish().result;

    var result = new Uint8Array( result1.length + result2.length );
    if ( result1.length ) result.set(result1);
    if ( result2.length ) result.set( result2, result1.length );
    this.result = result;

    return this;
  }

  AES_CCM_Encrypt_process ( data ) {
    if ( !is_bytes(data) )
      throw new TypeError("data isn't of expected type");

    var dpos = 0,
      dlen = data.length || 0,
      asm = this.asm,
      heap = this.heap,
      counter = this.counter,
      pos = this.pos,
      len = this.len,
      rpos = 0,
      rlen = ( len + dlen ) & -16,
      wlen = 0;

    if ( ((counter-1)<<4) + len + dlen > _AES_CCM_data_maxLength ) // ??? should check against lengthSize
      throw new RangeError("counter overflow");

    var result = new Uint8Array(rlen);

    while ( dlen > 0 ) {
      wlen = _heap_write( heap, pos+len, data, dpos, dlen );
      len  += wlen;
      dpos += wlen;
      dlen -= wlen;

      wlen = asm.mac( AES_asm.MAC.CBC, AES_asm.HEAP_DATA + pos, len );
      wlen = asm.cipher( AES_asm.ENC.CTR, AES_asm.HEAP_DATA + pos, wlen );

      if ( wlen ) result.set( heap.subarray( pos, pos + wlen ), rpos );
      counter += (wlen>>>4);
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
    this.counter = counter;
    this.pos = pos;
    this.len = len;

    return this;
  }

  AES_CCM_Encrypt_finish () {
    var asm = this.asm,
      heap = this.heap,
      tagSize = this.tagSize,
      pos = this.pos,
      len = this.len,
      wlen = 0;

    var result = new Uint8Array( len + tagSize );

    for ( var i = len; i & 15; i++ ) heap[ pos + i ] = 0;

    wlen = asm.mac( AES_asm.MAC.CBC, AES_asm.HEAP_DATA + pos, i );
    wlen = asm.cipher( AES_asm.ENC.CTR, AES_asm.HEAP_DATA + pos, i );
    if ( len ) result.set( heap.subarray( pos, pos + len ) );

    asm.set_counter( 0, 0, 0, 0 );
    asm.get_iv( AES_asm.HEAP_DATA );
    asm.cipher( AES_asm.ENC.CTR, AES_asm.HEAP_DATA, 16 );
    result.set( heap.subarray( 0, tagSize ), len );

    this.result = result;
    this.counter = 1;
    this.pos = 0;
    this.len = 0;

    return this;
  }

  AES_CCM_Decrypt_process ( data ) {
    if ( !is_bytes(data) )
      throw new TypeError("data isn't of expected type");

    var dpos = 0,
      dlen = data.length || 0,
      asm = this.asm,
      heap = this.heap,
      counter = this.counter,
      tagSize = this.tagSize,
      pos = this.pos,
      len = this.len,
      rpos = 0,
      rlen = len + dlen > tagSize ? ( len + dlen - tagSize ) & -16 : 0,
      tlen = len + dlen - rlen,
      wlen = 0;

    if ( ((counter-1)<<4) + len + dlen > _AES_CCM_data_maxLength )
      throw new RangeError("counter overflow");

    var result = new Uint8Array(rlen);

    while ( dlen > tlen ) {
      wlen = _heap_write( heap, pos+len, data, dpos, dlen-tlen );
      len  += wlen;
      dpos += wlen;
      dlen -= wlen;

      wlen = asm.cipher( AES_asm.DEC.CTR, AES_asm.HEAP_DATA + pos, wlen );
      wlen = asm.mac( AES_asm.MAC.CBC, AES_asm.HEAP_DATA + pos, wlen );

      if ( wlen ) result.set( heap.subarray( pos, pos+wlen ), rpos );
      counter += (wlen>>>4);
      rpos += wlen;

      pos = 0;
      len = 0;
    }

    if ( dlen > 0 ) {
      len += _heap_write( heap, 0, data, dpos, dlen );
    }

    this.result = result;
    this.counter = counter;
    this.pos = pos;
    this.len = len;

    return this;
  }

  AES_CCM_Decrypt_finish () {
    var asm = this.asm,
      heap = this.heap,
      tagSize = this.tagSize,
      pos = this.pos,
      len = this.len,
      rlen = len - tagSize,
      wlen = 0;

    if ( len < tagSize )
      throw new IllegalStateError("authentication tag not found");

    var result = new Uint8Array(rlen),
      atag = new Uint8Array( heap.subarray( pos+rlen, pos+len ) );

    wlen = asm.cipher( AES_asm.DEC.CTR, AES_asm.HEAP_DATA + pos, (rlen + 15) & -16 );
    result.set( heap.subarray( pos, pos + rlen ) );

    for ( var i = rlen; i & 15; i++ ) heap[ pos + i ] = 0;
    wlen = asm.mac( AES_asm.MAC.CBC, AES_asm.HEAP_DATA + pos, i );

    asm.set_counter( 0, 0, 0, 0 );
    asm.get_iv( AES_asm.HEAP_DATA );
    asm.cipher( AES_asm.ENC.CTR, AES_asm.HEAP_DATA, 16 );

    var acheck = 0;
    for ( var i = 0; i < tagSize; ++i ) acheck |= atag[i] ^ heap[i];
    if ( acheck )
      throw new SecurityError("data integrity check failed");

    this.result = result;
    this.counter = 1;
    this.pos = 0;
    this.len = 0;

    return this;
  }

  reset() {

  }
}

export class AES_CCM_Encrypt extends AES_CCM {
  constructor(key, nonce, adata, tagSize, dataLength, heap, asm ) {
    super(key, nonce, adata, tagSize, dataLength, heap, asm );
  }
  process(data) {
    return this.AES_CCM_Encrypt_process(data);
  }
  finish() {
    return this.AES_CCM_Encrypt_finish();
  }
}

export class AES_CCM_Decrypt extends AES_CCM {
  constructor(key, nonce, adata, tagSize, dataLength, heap, asm ) {
    super(key, nonce, adata, tagSize, dataLength, heap, asm );
  }
  process(data) {
    return this.AES_CCM_Decrypt_process(data);
  }
  finish() {
    return this.AES_CCM_Decrypt_finish();
  }
}

