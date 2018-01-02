/**
 * Output Feedback (OFB)
 */

import {AES} from '../aes';

export class AES_OFB extends AES {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} iv
   * @param {Uint8Array} [heap]
   * @param {Uint8Array} [asm]
   */
  constructor(key, iv, heap, asm) {
    super(key, iv, false, heap, asm);

    this.mode = 'OFB';
    this.BLOCK_SIZE = 16;
  }

  /**
   * @param {Uint8Array} data
   * @return {AES_OFB}
   */
  encrypt(data) {
    return this.AES_Encrypt_finish(data);
  }

  /**
   * @param {Uint8Array} data
   * @return {AES_OFB}
   */
  decrypt(data) {
    return this.AES_Encrypt_finish(data);
  }
}

export class AES_OFB_Crypt extends AES_OFB {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} iv
   * @param {Uint8Array} [heap]
   * @param {Uint8Array} [asm]
   */
  constructor(key, iv, heap, asm) {
    super(key, iv, heap, asm);
    this.BLOCK_SIZE = 16;
  }

  /**
   * @param {Uint8Array} data
   * @return {AES_OFB_Crypt}
   */
  process(data) {
    return this.AES_Encrypt_process(data);
  }

  /**
   * @param {Uint8Array} data
   * @return {AES_OFB_Crypt}
   */
  finish(data) {
    return this.AES_Encrypt_finish(data);
  }
}

