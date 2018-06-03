import { AES } from './aes';
import { joinBytes } from '../other/utils';

export class AES_ECB extends AES {
  static encrypt(data: Uint8Array, key: Uint8Array, padding: boolean = false): Uint8Array {
    return new AES_ECB(key, padding).encrypt(data);
  }

  static decrypt(data: Uint8Array, key: Uint8Array, padding: boolean = false): Uint8Array {
    return new AES_ECB(key, padding).decrypt(data);
  }

  constructor(key: Uint8Array, padding: boolean = false) {
    super(key, undefined, padding, 'ECB');
  }

  encrypt(data: Uint8Array): Uint8Array {
    const r1 = this.AES_Encrypt_process(data);
    const r2 = this.AES_Encrypt_finish();

    return joinBytes(r1, r2);
  }

  decrypt(data: Uint8Array): Uint8Array {
    const r1 = this.AES_Decrypt_process(data);
    const r2 = this.AES_Decrypt_finish();

    return joinBytes(r1, r2);
  }
}
