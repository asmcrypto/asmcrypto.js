/**
 * Counter Mode (CTR)
 */

import {AES} from '../aes';

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
