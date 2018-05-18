import { AES_ECB } from './ecb';
import { AES_CBC } from './cbc';

function mul2(data: Uint8Array): void {
  const t = data[0] & 0x80;
  for (let i = 0; i < 15; i++) {
    data[i] = (data[i] << 1) ^ (data[i + 1] & 0x80 ? 1 : 0);
  }
  data[15] = (data[15] << 1) ^ (t ? 0x87 : 0);
}

export class AES_CMAC {
  private readonly k: Uint8Array;
  private readonly cbc: AES_CBC;
  private readonly buffer: Uint8Array;
  private bufferLength = 0;
  public result!: Uint8Array | null;

  static bytes(data: Uint8Array, key: Uint8Array): Uint8Array {
    return new AES_CMAC(key).process(data).finish().result as Uint8Array;
  }

  constructor(key: Uint8Array) {
    this.k = new AES_ECB(key).encrypt(new Uint8Array(16)).result as Uint8Array;
    mul2(this.k);
    this.cbc = new AES_CBC(key, new Uint8Array(16), false);

    this.buffer = new Uint8Array(16);
    this.result = null;
  }

  process(data: Uint8Array): this {
    if (this.bufferLength + data.length > 16) {
      this.cbc.encrypt(this.buffer.subarray(0, this.bufferLength));
      const offset = ((this.bufferLength + data.length - 1) & ~15) - this.bufferLength;
      this.cbc.encrypt(data.subarray(0, offset));
      this.buffer.set(data.subarray(offset));
      this.bufferLength = data.length - offset;
    } else {
      this.buffer.set(data, this.bufferLength);
      this.bufferLength += data.length;
    }
    return this;
  }

  finish(): this {
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

    this.result = this.cbc.encrypt(this.buffer).result;
    return this;
  }
}
