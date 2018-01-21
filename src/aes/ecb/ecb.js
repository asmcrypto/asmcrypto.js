import { AES } from '../aes';

/**
 * Electronic Code Book Mode (ECB)
 */
export class AES_ECB extends AES {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} [heap]
   * @param {Uint8Array} [asm]
   */
  constructor(key, heap, asm) {
    super(key, undefined, false, heap, asm);

    this.mode = 'ECB';
    this.BLOCK_SIZE = 16;
  }

  encrypt(data) {
    return this.AES_Encrypt_finish(data);
  }

  decrypt(data) {
    return this.AES_Decrypt_finish(data);
  }
}

export class AES_ECB_Encrypt extends AES_ECB {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} [heap]
   * @param {Uint8Array} [asm]
   */
  constructor(key, heap, asm) {
    super(key, heap, asm);
  }

  /**
   * @param {Uint8Array} key
   * @returns {AES_ECB_Encrypt}
   */
  reset(key) {
    return this.AES_reset(key, null, true);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_ECB_Encrypt}
   */
  process(data) {
    return this.AES_Encrypt_process(data);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_ECB_Encrypt}
   */
  finish(data) {
    return this.AES_Encrypt_finish(data);
  }
}

export class AES_ECB_Decrypt extends AES_ECB {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} [heap]
   * @param {Uint8Array} [asm]
   */
  constructor(key, heap, asm) {
    super(key, heap, asm);
  }

  /**
   * @param {Uint8Array} key
   * @returns {AES_ECB_Decrypt}
   */
  reset(key) {
    return this.AES_reset(key, null, true);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_ECB_Decrypt}
   */
  process(data) {
    return this.AES_Decrypt_process(data);
  }

  /**
   * @param {Uint8Array} data
   * @returns {AES_ECB_Decrypt}
   */
  finish(data) {
    return this.AES_Decrypt_finish(data);
  }
}
