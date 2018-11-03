import { AES } from './aes';
import { joinBytes } from '../other/utils';

export class AES_CBC {
  private aes: AES;

  static encrypt(data: Uint8Array, key: Uint8Array, padding: boolean = true, iv?: Uint8Array): Uint8Array {
    return new AES_CBC(key, iv, padding).encrypt(data);
  }

  static decrypt(data: Uint8Array, key: Uint8Array, padding: boolean = true, iv?: Uint8Array): Uint8Array {
    return new AES_CBC(key, iv, padding).decrypt(data);
  }

  constructor(key: Uint8Array, iv?: Uint8Array, padding: boolean = true, aes?: AES) {
    this.aes = aes ? aes : new AES(key, iv, padding, 'CBC');
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
