import { AES } from './aes';
import { IllegalArgumentError } from '../other/errors';
import { joinBytes } from '../other/utils';

export class AES_CTR {
  private aes: AES;

  static encrypt(data: Uint8Array, key: Uint8Array, nonce: Uint8Array): Uint8Array {
    return new AES_CTR(key, nonce).encrypt(data);
  }

  static decrypt(data: Uint8Array, key: Uint8Array, nonce: Uint8Array): Uint8Array {
    return new AES_CTR(key, nonce).encrypt(data);
  }

  constructor(key: Uint8Array, nonce: Uint8Array, aes?: AES) {
    this.aes = aes ? aes : new AES(key, undefined, false, 'CTR');
    delete this.aes.padding;

    this.AES_CTR_set_options(nonce);
  }

  encrypt(data: Uint8Array): Uint8Array {
    const r1 = this.aes.AES_Encrypt_process(data);
    const r2 = this.aes.AES_Encrypt_finish();

    return joinBytes(r1, r2);
  }

  decrypt(data: Uint8Array): Uint8Array {
    const r1 = this.aes.AES_Encrypt_process(data);
    const r2 = this.aes.AES_Encrypt_finish();

    return joinBytes(r1, r2);
  }

  private AES_CTR_set_options(nonce: Uint8Array, counter?: number, size?: number): void {
    if (size !== undefined) {
      if (size < 8 || size > 48) throw new IllegalArgumentError('illegal counter size');

      let mask = Math.pow(2, size) - 1;
      this.aes.asm.set_mask(0, 0, (mask / 0x100000000) | 0, mask | 0);
    } else {
      size = 48;
      this.aes.asm.set_mask(0, 0, 0xffff, 0xffffffff);
    }

    if (nonce !== undefined) {
      let len = nonce.length;
      if (!len || len > 16) throw new IllegalArgumentError('illegal nonce size');

      let view = new DataView(new ArrayBuffer(16));
      new Uint8Array(view.buffer).set(nonce);

      this.aes.asm.set_nonce(view.getUint32(0), view.getUint32(4), view.getUint32(8), view.getUint32(12));
    } else {
      throw new Error('nonce is required');
    }

    if (counter !== undefined) {
      if (counter < 0 || counter >= Math.pow(2, size)) throw new IllegalArgumentError('illegal counter value');

      this.aes.asm.set_counter(0, 0, (counter / 0x100000000) | 0, counter | 0);
    }
  }
}
