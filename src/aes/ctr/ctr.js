/**
 * Counter Mode (CTR)
 */

import {AES} from '../aes';
import {is_bytes, is_number} from '../../utils';
import {IllegalArgumentError} from '../../errors';

export class AES_CTR extends AES {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} nonce
   * @param {Uint8Array} [heap]
   * @param {Uint8Array} [asm]
   */
  constructor(key, nonce, heap, asm) {
    super(key, undefined, undefined, heap, asm);
    this.reset(key, nonce);

    this.AES_CTR_set_options(nonce);
    delete this.padding;

    this.mode = 'CTR';
    this.BLOCK_SIZE = 16;
  }

  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} nonce
   * @param {number} [counter]
   * @param {number} [counterSize]
   * @returns {AES_CTR}
   */
  reset(key, nonce, counter, counterSize) {
    this.AES_reset(key, undefined, undefined);

    this.AES_CTR_set_options(nonce, counter, counterSize);

    return this;
  }

  /**
   * @param {Uint8Array} nonce
   * @param {number} [counter]
   * @param {number} [size]
   * @constructor
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
   * @param {Uint8Array} data
   * @returns {AES_CTR}
   */
  encrypt(data) {
    return this.AES_Encrypt_finish(data);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_CTR}
   */
  decrypt(data) {
    return this.AES_Encrypt_finish(data);
  }
}

export class AES_CTR_Crypt extends AES_CTR {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} nonce
   * @param {Uint8Array} [heap]
   * @param {Uint8Array} [asm]
   */
  constructor(key, nonce, heap, asm) {
    super(key, nonce, heap, asm);
    this.BLOCK_SIZE = 16;
  }

  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} nonce
   * @param {number} [counter]
   * @param {number} [counterSize]
   * @returns {AES_CTR_Crypt}
   */
  reset(key, nonce, counter, counterSize) {
    this.AES_reset(key, undefined, undefined);

    this.AES_CTR_set_options(nonce, counter, counterSize);

    return this;
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_CTR_Crypt}
   */
  process(data) {
    return this.AES_Encrypt_process(data);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_CTR_Crypt}
   */
  finish(data) {
    return this.AES_Encrypt_finish(data);
  }
}
