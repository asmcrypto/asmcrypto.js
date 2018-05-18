import { AES } from './aes';

export class AES_CBC extends AES {
  static encrypt(data: Uint8Array, key: Uint8Array, padding: boolean = true, iv?: Uint8Array): Uint8Array {
    return new AES_CBC(key, iv, padding).encrypt(data).result as Uint8Array;
  }

  static decrypt(data: Uint8Array, key: Uint8Array, padding: boolean = true, iv?: Uint8Array): Uint8Array {
    return new AES_CBC(key, iv, padding).decrypt(data).result as Uint8Array;
  }

  constructor(key: Uint8Array, iv?: Uint8Array, padding: boolean = true) {
    super(key, iv, padding, 'CBC');
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
