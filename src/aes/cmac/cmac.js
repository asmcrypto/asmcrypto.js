import { AES_ECB } from '../ecb/ecb';
import { AES_CBC_Encrypt } from '../cbc/cbc';
import { bytes_to_hex, hex_to_bytes } from '../../utils';

/**
 * @param {Uint8Array} data
 */
function mul2(data) {
  const t = data[0] & 0x80;
  for (var i = 0; i < 15; i++) {
    data[i] = (data[i] << 1) ^ ((data[i+1] & 0x80) ? 1 : 0);
  }
  data[15] = (data[15] << 1) ^ (t ? 0x87 : 0);
}

export class AES_CMAC {
  /**
   * @param {Uint8Array} key
   */
  constructor(key) {
    this.k = new AES_ECB(key).encrypt(new Uint8Array(16)).result;
    mul2(this.k);
    this.cbc = new AES_CBC_Encrypt(key, new Uint8Array(16), false);

    this.buffer = new Uint8Array(16);
    this.bufferLength = 0;
    this.result = null;
  }

  /**
   * @param {Uint8Array} data
   */
  process(data) {
    if (this.bufferLength + data.length > 16) {
      this.cbc.process(this.buffer.subarray(0, this.bufferLength));
      const offset = ((this.bufferLength + data.length - 1) & ~15) - this.bufferLength;
      this.cbc.process(data.subarray(0, offset));
      this.buffer.set(data.subarray(offset));
      this.bufferLength = data.length - offset;
    } else {
      this.buffer.set(data, this.bufferLength);
      this.bufferLength += data.length;
    }
    return this;
  }

  finish() {
    if (this.bufferLength !== 16) {
      this.buffer[this.bufferLength] = 0x80;
      for (let i = this.bufferLength + 1; i < 16; i++) {
        this.buffer[i] = 0;
      }
      mul2(this.k);
    }

    for (let i = 0; i < 16; i++) {
      this.buffer[i] ^= this.k[i];
    }

    this.result = this.cbc.process(this.buffer).result;
    return this;
  }
}
