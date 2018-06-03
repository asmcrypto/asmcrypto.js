import { AES } from './aes';
import { joinBytes } from '../other/utils';

export class AES_OFB extends AES {
  static encrypt(data: Uint8Array, key: Uint8Array, iv?: Uint8Array): Uint8Array {
    return new AES_OFB(key, iv).encrypt(data);
  }

  static decrypt(data: Uint8Array, key: Uint8Array, iv?: Uint8Array): Uint8Array {
    return new AES_OFB(key, iv).decrypt(data);
  }

  constructor(key: Uint8Array, iv?: Uint8Array) {
    super(key, iv, false, 'OFB');
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
