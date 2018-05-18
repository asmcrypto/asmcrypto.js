import { AES } from './aes';

export class AES_OFB extends AES {
  static encrypt(data: Uint8Array, key: Uint8Array, iv?: Uint8Array): Uint8Array {
    return new AES_OFB(key, iv).encrypt(data).result as Uint8Array;
  }

  static decrypt(data: Uint8Array, key: Uint8Array, iv?: Uint8Array): Uint8Array {
    return new AES_OFB(key, iv).decrypt(data).result as Uint8Array;
  }

  constructor(key: Uint8Array, iv?: Uint8Array) {
    super(key, iv, false, 'OFB');
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
