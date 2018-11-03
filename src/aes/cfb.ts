import { AES } from './aes';
import { joinBytes } from '../other/utils';

export class AES_CFB {
  private aes: AES;

  static encrypt(data: Uint8Array, key: Uint8Array, iv?: Uint8Array): Uint8Array {
    return new AES_CFB(key, iv).encrypt(data);
  }

  static decrypt(data: Uint8Array, key: Uint8Array, iv?: Uint8Array): Uint8Array {
    return new AES_CFB(key, iv).decrypt(data);
  }

  constructor(key: Uint8Array, iv?: Uint8Array, aes?: AES) {
    this.aes = aes ? aes : new AES(key, iv, true, 'CFB');
    delete this.aes.padding;
  }

  encrypt(data: Uint8Array): Uint8Array {
    const r1 = this.aes.AES_Encrypt_process(data);
    const r2 = this.aes.AES_Encrypt_finish();

    return joinBytes(r1, r2);
  }

  decrypt(data: Uint8Array): Uint8Array {
    const r1 = this.aes.AES_Decrypt_process(data);
    const r2 = this.aes.AES_Decrypt_finish();

    return joinBytes(r1, r2);
  }
}
