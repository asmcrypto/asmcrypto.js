import { AES_asm, AES_mode } from './aes.asm';
import { _heap_init, _heap_write, is_bytes } from '../other/utils';
import { IllegalArgumentError, SecurityError } from '../other/errors';

const heap_pool = [];
const asm_pool = [];

export abstract class AES {
  protected readonly heap: Uint8Array;
  protected readonly asm: AES_asm;
  private readonly mode: string;
  protected padding: boolean; // TODO: This should be `private readonly`, hacking for AES-CFB?!
  protected pos: number = 0;
  protected len: number = 0;

  protected constructor(key: Uint8Array, iv: Uint8Array | undefined, padding = true, mode: AES_mode) {
    this.mode = mode;

    // The AES object state
    this.pos = 0;
    this.len = 0;

    this.key = key;
    this.iv = iv;
    this.padding = padding;

    // The AES "worker"
    this.acquire_asm();
  }

  protected acquire_asm() {
    if (this.heap === undefined && this.asm === undefined) {
      this.heap = heap_pool.pop() || _heap_init().subarray(AES_asm.HEAP_DATA);
      this.asm = asm_pool.pop() || AES_asm(null, this.heap.buffer);
      this.reset(this.key, this.iv);
    }
  }

  protected release_asm() {
    this.iv = this.heap.slice(0, this.asm.get_iv(AES_asm.HEAP_DATA));

    heap_pool.push(this.heap);
    asm_pool.push(this.asm);
    this.heap = undefined;
    this.asm = undefined;
  }

  protected reset(key, iv) {
    // Key
    const keylen = key.length;
    if (keylen !== 16 && keylen !== 24 && keylen !== 32) throw new IllegalArgumentError('illegal key size');

    const keyview = new DataView(key.buffer, key.byteOffset, key.byteLength);
    this.asm.set_key(
      keylen >> 2,
      keyview.getUint32(0),
      keyview.getUint32(4),
      keyview.getUint32(8),
      keyview.getUint32(12),
      keylen > 16 ? keyview.getUint32(16) : 0,
      keylen > 16 ? keyview.getUint32(20) : 0,
      keylen > 24 ? keyview.getUint32(24) : 0,
      keylen > 24 ? keyview.getUint32(28) : 0,
    );

    // IV
    if (iv !== undefined) {
      if (iv.length !== 16) throw new IllegalArgumentError('illegal iv size');

      let ivview = new DataView(iv.buffer, iv.byteOffset, iv.byteLength);

      this.asm.set_iv(ivview.getUint32(0), ivview.getUint32(4), ivview.getUint32(8), ivview.getUint32(12));
    } else {
      this.asm.set_iv(0, 0, 0, 0);
    }
  }

  AES_Encrypt_process(data: Uint8Array): Uint8Array {
    if (!is_bytes(data)) throw new TypeError("data isn't of expected type");

    this.acquire_asm();

    let asm = this.asm;
    let heap = this.heap;
    let amode = AES_asm.ENC[this.mode];
    let hpos = AES_asm.HEAP_DATA;
    let pos = this.pos;
    let len = this.len;
    let dpos = 0;
    let dlen = data.length || 0;
    let rpos = 0;
    let rlen = (len + dlen) & -16;
    let wlen = 0;

    let result = new Uint8Array(rlen);

    while (dlen > 0) {
      wlen = _heap_write(heap, pos + len, data, dpos, dlen);
      len += wlen;
      dpos += wlen;
      dlen -= wlen;

      wlen = asm.cipher(amode, hpos + pos, len);

      if (wlen) result.set(heap.subarray(pos, pos + wlen), rpos);
      rpos += wlen;

      if (wlen < len) {
        pos += wlen;
        len -= wlen;
      } else {
        pos = 0;
        len = 0;
      }
    }

    this.pos = pos;
    this.len = len;

    return result;
  }

  AES_Encrypt_finish(): Uint8Array {
    this.acquire_asm();

    let asm = this.asm;
    let heap = this.heap;
    let amode = AES_asm.ENC[this.mode];
    let hpos = AES_asm.HEAP_DATA;
    let pos = this.pos;
    let len = this.len;
    let plen = 16 - (len % 16);
    let rlen = len;

    if (this.hasOwnProperty('padding')) {
      if (this.padding) {
        for (let p = 0; p < plen; ++p) {
          heap[pos + len + p] = plen;
        }
        len += plen;
        rlen = len;
      } else if (len % 16) {
        throw new IllegalArgumentError('data length must be a multiple of the block size');
      }
    } else {
      len += plen;
    }

    const result = new Uint8Array(rlen);

    if (len) asm.cipher(amode, hpos + pos, len);

    if (rlen) result.set(heap.subarray(pos, pos + rlen));

    this.pos = 0;
    this.len = 0;

    this.release_asm();

    return result;
  }

  AES_Decrypt_process(data: Uint8Array): Uint8Array {
    if (!is_bytes(data)) throw new TypeError("data isn't of expected type");

    this.acquire_asm();

    let asm = this.asm;
    let heap = this.heap;
    let amode = AES_asm.DEC[this.mode];
    let hpos = AES_asm.HEAP_DATA;
    let pos = this.pos;
    let len = this.len;
    let dpos = 0;
    let dlen = data.length || 0;
    let rpos = 0;
    let rlen = (len + dlen) & -16;
    let plen = 0;
    let wlen = 0;

    if (this.padding) {
      plen = len + dlen - rlen || 16;
      rlen -= plen;
    }

    const result = new Uint8Array(rlen);

    while (dlen > 0) {
      wlen = _heap_write(heap, pos + len, data, dpos, dlen);
      len += wlen;
      dpos += wlen;
      dlen -= wlen;

      wlen = asm.cipher(amode, hpos + pos, len - (!dlen ? plen : 0));

      if (wlen) result.set(heap.subarray(pos, pos + wlen), rpos);
      rpos += wlen;

      if (wlen < len) {
        pos += wlen;
        len -= wlen;
      } else {
        pos = 0;
        len = 0;
      }
    }

    this.pos = pos;
    this.len = len;

    return result;
  }

  AES_Decrypt_finish(): Uint8Array {
    this.acquire_asm();

    let asm = this.asm;
    let heap = this.heap;
    let amode = AES_asm.DEC[this.mode];
    let hpos = AES_asm.HEAP_DATA;
    let pos = this.pos;
    let len = this.len;
    let rlen = len;

    if (len > 0) {
      if (len % 16) {
        if (this.hasOwnProperty('padding')) {
          throw new IllegalArgumentError('data length must be a multiple of the block size');
        } else {
          len += 16 - (len % 16);
        }
      }

      asm.cipher(amode, hpos + pos, len);

      if (this.hasOwnProperty('padding') && this.padding) {
        let pad = heap[pos + rlen - 1];
        if (pad < 1 || pad > 16 || pad > rlen) throw new SecurityError('bad padding');

        let pcheck = 0;
        for (let i = pad; i > 1; i--) pcheck |= pad ^ heap[pos + rlen - i];
        if (pcheck) throw new SecurityError('bad padding');

        rlen -= pad;
      }
    }

    const result = new Uint8Array(rlen);

    if (rlen > 0) {
      result.set(heap.subarray(pos, pos + rlen));
    }

    this.pos = 0;
    this.len = 0;

    this.release_asm();

    return result;
  }
}
