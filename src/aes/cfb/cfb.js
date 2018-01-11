/**
 * Cipher Feedback Mode (CFB)
 */

import {AES} from '../aes';

export class AES_CFB extends AES {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} [iv]
   * @param {Uint8Array} [heap]
   * @param {Uint8Array} [asm]
   */
  constructor(key, iv, heap, asm) {
    super(key, iv, true, heap, asm);
    delete this.padding;

    this.mode = 'CFB';
    this.BLOCK_SIZE = 16;
  }

  encrypt(data) {
    return this.AES_Encrypt_finish(data);
  }

  decrypt(data) {
    return this.AES_Decrypt_finish(data);
  }
}

export class AES_CFB_Encrypt extends AES_CFB {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} [iv=null]
   * @param {Uint8Array} [heap]
   * @param {Uint8Array} [asm]
   */
  constructor(key, iv, heap, asm) {
    super(key, iv, heap, asm);
  }

  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} [iv]
   * @param {boolean} [padding]
   * @returns {AES_CFB_Encrypt}
   */
  reset(key, iv, padding) {
    return this.AES_reset(key, iv, padding);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_CFB_Encrypt}
   */
  process(data) {
    return this.AES_Encrypt_process(data);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_CFB_Encrypt}
   */
  finish(data) {
    return this.AES_Encrypt_finish(data);
  }
}

export class AES_CFB_Decrypt extends AES_CFB{
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} [iv=null]
   * @param {Uint8Array} [heap]
   * @param {Uint8Array} [asm]
   */
  constructor(key, iv, heap, asm) {
    super(key, iv, heap, asm);
  }

  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} [iv]
   * @param {boolean} [padding]
   * @returns {AES_CFB_Decrypt}
   */
  reset(key, iv, padding) {
    return this.AES_reset(key, iv, padding);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_CFB_Decrypt}
   */
  process(data) {
    return this.AES_Decrypt_process(data);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_CFB_Decrypt}
   */
  finish(data) {
    return this.AES_Decrypt_finish(data);
  }
}

