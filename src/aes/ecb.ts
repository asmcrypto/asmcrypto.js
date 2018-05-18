import { AES } from './aes';

export class AES_ECB extends AES {
  static encrypt(data: Uint8Array, key: Uint8Array, padding: boolean = false): Uint8Array {
    return new AES_ECB(key, padding).encrypt(data).result as Uint8Array;
  }

  static decrypt(data: Uint8Array, key: Uint8Array, padding: boolean = false): Uint8Array {
    return new AES_ECB(key, padding).decrypt(data).result as Uint8Array;
  }

  constructor(key: Uint8Array, padding: boolean = false) {
    super(key, undefined, padding, 'ECB');
  }

  encrypt(data: Uint8Array): this {
    this.AES_Encrypt_process(data);
    return this.AES_Encrypt_finish();
  }

  decrypt(data: Uint8Array): this {
    this.AES_Decrypt_process(data);
    return this.AES_Decrypt_finish();
  }
}
