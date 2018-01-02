/**
 * Cipher Block Chaining Mode (CBC)
 */
import {AES} from '../aes';

export class AES_CBC extends AES {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} [iv=null]
   * @param {boolean} [padding=true]
   * @param {Uint8Array} [heap]
   * @param {Uint8Array} [asm]
   */
  constructor(key, iv = null, padding = true, heap, asm) {
    super(key, iv, padding, heap, asm);

    this.mode = 'CBC';
    this.BLOCK_SIZE = 16;
  }

  encrypt(data) {
    return this.AES_Encrypt_finish(data);
  }

  decrypt(data) {
    return this.AES_Decrypt_finish(data);
  }
}

export class AES_CBC_Encrypt extends AES_CBC {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} [iv=null]
   * @param {boolean} [padding=true]
   * @param {Uint8Array} [heap]
   * @param {Uint8Array} [asm]
   */
  constructor(key, iv, padding, heap, asm) {
    super(key, iv, padding, heap, asm);
  }

  /**
   * @param {Uint8Array} key
   * @returns {AES_CBC_Encrypt}
   */
  reset(key) {
    return this.AES_reset(key, null, true);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_CBC_Encrypt}
   */
  process(data) {
    return this.AES_Encrypt_process(data);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_CBC_Encrypt}
   */
  finish(data) {
    return this.AES_Encrypt_finish(data);
  }
}

export class AES_CBC_Decrypt extends AES_CBC {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} [iv=null]
   * @param {boolean} [padding=true]
   * @param {Uint8Array} [heap]
   * @param {Uint8Array} [asm]
   */
  constructor(key, iv, padding, heap, asm) {
    super(key, iv, padding, heap, asm);
  }

  /**
   * @param {Uint8Array} key
   * @returns {AES_CBC_Decrypt}
   */
  reset(key) {
    return this.AES_reset(key, null, true);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_CBC_Decrypt}
   */
  process(data) {
    return this.AES_Decrypt_process(data);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_CBC_Decrypt}
   */
  finish(data) {
    return this.AES_Decrypt_finish(data);
  }
}

