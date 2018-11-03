/**
 * Counter with CBC-MAC (CCM)
 *
 * Due to JS limitations (52 bits of Number precision) maximum encrypted message length
 * is limited to ~4 PiB ( 2^52 - 16 ) per `nonce`-`key` pair.
 * That also limits `lengthSize` parameter maximum value to 7 (not 8 as described in RFC3610).
 *
 * Additional authenticated data `adata` maximum length is chosen to be no more than 65279 bytes ( 2^16 - 2^8 ),
 * which is considered enough for the most of use-cases.
 *
 * And one more important thing: in case of progressive ciphering of a data stream (in other
 * words when data can't be held in-memory at a whole and are ciphered chunk-by-chunk)
 * you have to know the `dataLength` in advance and pass that value to the cipher options.
 */

import { AES_asm } from './aes.asm';
import { AES } from './aes';
import { _heap_write } from '../other/utils';
import { IllegalArgumentError, IllegalStateError, SecurityError } from '../other/errors';

const _AES_CCM_adata_maxLength = 65279; // 2^16 - 2^8
const _AES_CCM_data_maxLength = 4503599627370480; // 2^52 - 2^4

export class AES_CCM {
  private readonly tagSize: number;
  private readonly lengthSize: number;
  private nonce: Uint8Array;
  private readonly adata: Uint8Array | undefined;
  private counter: number = 1;
  private dataLength: number = -1;
  private aes: AES;

  static encrypt(
    clear: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    adata: Uint8Array | undefined,
    tagsize: number = 16,
  ): Uint8Array {
    return new AES_CCM(key, nonce, adata, tagsize, clear.length).encrypt(clear);
  }
  static decrypt(
    cipher: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    adata: Uint8Array | undefined,
    tagsize: number = 16,
  ): Uint8Array {
    return new AES_CCM(key, nonce, adata, tagsize, cipher.length - tagsize).decrypt(cipher);
  }

  constructor(
    key: Uint8Array,
    nonce: Uint8Array,
    adata: Uint8Array | undefined,
    tagSize: number = 16,
    dataLength: number,
    aes?: AES,
  ) {
    this.aes = aes ? aes : new AES(key, undefined, undefined, 'CCM');

    // Tag size
    if (tagSize < 4 || tagSize > 16 || tagSize & 1) throw new IllegalArgumentError('illegal tagSize value');
    this.tagSize = tagSize;

    // Nonce
    this.nonce = nonce;

    if (nonce.length < 8 || nonce.length > 13) throw new IllegalArgumentError('illegal nonce length');
    this.lengthSize = 15 - nonce.length;
    nonce = new Uint8Array(nonce.length + 1);
    nonce[0] = this.lengthSize - 1;
    nonce.set(this.nonce, 1);

    if (dataLength < 0 || dataLength > _AES_CCM_data_maxLength || dataLength > Math.pow(2, 8 * this.lengthSize) - 16)
      throw new IllegalArgumentError('illegal dataLength value');

    if (adata !== undefined) {
      if (adata.length > _AES_CCM_adata_maxLength) throw new IllegalArgumentError('illegal adata length');

      this.adata = adata.length ? adata : undefined;
    }

    this.dataLength = dataLength;
    this.counter = 1;

    this.AES_CCM_calculate_iv();
    this.AES_CTR_set_options(nonce, this.counter, 8 * this.lengthSize);
  }

  encrypt(data: Uint8Array): Uint8Array {
    this.dataLength = data.length || 0;

    const result1 = this.AES_CCM_Encrypt_process(data);
    const result2 = this.AES_CCM_Encrypt_finish();

    const result = new Uint8Array(result1.length + result2.length);
    if (result1.length) result.set(result1);
    if (result2.length) result.set(result2, result1.length);

    return result;
  }

  decrypt(data: Uint8Array): Uint8Array {
    this.dataLength = data.length || 0;

    const result1 = this.AES_CCM_Decrypt_process(data);
    const result2 = this.AES_CCM_Decrypt_finish();

    const result = new Uint8Array(result1.length + result2.length);
    if (result1.length) result.set(result1);
    if (result2.length) result.set(result2, result1.length);

    return result;
  }

  AES_CCM_calculate_iv(): void {
    const nonce = this.nonce;
    const adata = this.adata;
    const tagSize = this.tagSize;
    const lengthSize = this.lengthSize;
    const dataLength = this.dataLength;

    const data = new Uint8Array(16 + (adata ? 2 + adata.length : 0));

    // B0: flags(adata?, M', L'), nonce, len(data)
    data[0] = (adata ? 64 : 0) | ((tagSize - 2) << 2) | (lengthSize - 1);
    data.set(nonce, 1);
    if (lengthSize > 6) data[9] = ((dataLength / 0x100000000) >>> 16) & 15;
    if (lengthSize > 5) data[10] = ((dataLength / 0x100000000) >>> 8) & 255;
    if (lengthSize > 4) data[11] = (dataLength / 0x100000000) & 255;
    if (lengthSize > 3) data[12] = dataLength >>> 24;
    if (lengthSize > 2) data[13] = (dataLength >>> 16) & 255;
    data[14] = (dataLength >>> 8) & 255;
    data[15] = dataLength & 255;

    // B*: len(adata), adata
    if (adata) {
      data[16] = (adata.length >>> 8) & 255;
      data[17] = adata.length & 255;
      data.set(adata, 18);
    }

    this._cbc_mac_process(data);
    this.aes.asm.get_state(AES_asm.HEAP_DATA);

    const iv = new Uint8Array(this.aes.heap.subarray(0, 16));
    const ivview = new DataView(iv.buffer, iv.byteOffset, iv.byteLength);
    this.aes.asm.set_iv(ivview.getUint32(0), ivview.getUint32(4), ivview.getUint32(8), ivview.getUint32(12));
  }

  _cbc_mac_process(data: Uint8Array): void {
    const heap = this.aes.heap;
    const asm = this.aes.asm;
    let dpos = 0;
    let dlen = data.length || 0;
    let wlen = 0;

    while (dlen > 0) {
      wlen = _heap_write(heap, 0, data, dpos, dlen);
      while (wlen & 15) heap[wlen++] = 0;
      dpos += wlen;
      dlen -= wlen;

      asm.mac(AES_asm.MAC.CBC, AES_asm.HEAP_DATA, wlen);
    }
  }

  AES_CCM_Encrypt_process(data: Uint8Array): Uint8Array {
    const asm = this.aes.asm;
    const heap = this.aes.heap;

    let dpos = 0;
    let dlen = data.length || 0;
    let counter = this.counter;
    let pos = this.aes.pos;
    let len = this.aes.len;

    const rlen = (len + dlen) & -16;
    let rpos = 0;
    let wlen = 0;

    if (((counter - 1) << 4) + len + dlen > _AES_CCM_data_maxLength)
      // ??? should check against lengthSize
      throw new RangeError('counter overflow');

    const result = new Uint8Array(rlen);

    while (dlen > 0) {
      wlen = _heap_write(heap, pos + len, data, dpos, dlen);
      len += wlen;
      dpos += wlen;
      dlen -= wlen;

      wlen = asm.mac(AES_asm.MAC.CBC, AES_asm.HEAP_DATA + pos, len);
      wlen = asm.cipher(AES_asm.ENC.CTR, AES_asm.HEAP_DATA + pos, wlen);

      if (wlen) result.set(heap.subarray(pos, pos + wlen), rpos);
      counter += wlen >>> 4;
      rpos += wlen;

      if (wlen < len) {
        pos += wlen;
        len -= wlen;
      } else {
        pos = 0;
        len = 0;
      }
    }

    this.counter = counter;
    this.aes.pos = pos;
    this.aes.len = len;

    return result;
  }

  AES_CCM_Encrypt_finish(): Uint8Array {
    const asm = this.aes.asm;
    const heap = this.aes.heap;
    const tagSize = this.tagSize;
    const pos = this.aes.pos;
    const len = this.aes.len;

    const result = new Uint8Array(len + tagSize);

    let i = len;
    for (; i & 15; i++) heap[pos + i] = 0;

    asm.mac(AES_asm.MAC.CBC, AES_asm.HEAP_DATA + pos, i);
    asm.cipher(AES_asm.ENC.CTR, AES_asm.HEAP_DATA + pos, i);
    if (len) result.set(heap.subarray(pos, pos + len));

    asm.set_counter(0, 0, 0, 0);
    asm.get_iv(AES_asm.HEAP_DATA);
    asm.cipher(AES_asm.ENC.CTR, AES_asm.HEAP_DATA, 16);
    result.set(heap.subarray(0, tagSize), len);

    this.counter = 1;
    this.aes.pos = 0;
    this.aes.len = 0;

    return result;
  }

  AES_CCM_Decrypt_process(data: Uint8Array): Uint8Array {
    let dpos = 0;
    let dlen = data.length || 0;
    const asm = this.aes.asm;
    const heap = this.aes.heap;
    let counter = this.counter;
    const tagSize = this.tagSize;
    let pos = this.aes.pos;
    let len = this.aes.len;
    let rpos = 0;
    const rlen = len + dlen > tagSize ? (len + dlen - tagSize) & -16 : 0;
    const tlen = len + dlen - rlen;
    let wlen = 0;

    if (((counter - 1) << 4) + len + dlen > _AES_CCM_data_maxLength) throw new RangeError('counter overflow');

    const result = new Uint8Array(rlen);

    while (dlen > tlen) {
      wlen = _heap_write(heap, pos + len, data, dpos, dlen - tlen);
      len += wlen;
      dpos += wlen;
      dlen -= wlen;

      wlen = asm.cipher(AES_asm.DEC.CTR, AES_asm.HEAP_DATA + pos, wlen);
      wlen = asm.mac(AES_asm.MAC.CBC, AES_asm.HEAP_DATA + pos, wlen);

      if (wlen) result.set(heap.subarray(pos, pos + wlen), rpos);
      counter += wlen >>> 4;
      rpos += wlen;

      pos = 0;
      len = 0;
    }

    if (dlen > 0) {
      len += _heap_write(heap, 0, data, dpos, dlen);
    }

    this.counter = counter;
    this.aes.pos = pos;
    this.aes.len = len;

    return result;
  }

  AES_CCM_Decrypt_finish(): Uint8Array {
    const asm = this.aes.asm;
    const heap = this.aes.heap;
    const tagSize = this.tagSize;
    const pos = this.aes.pos;
    const len = this.aes.len;
    const rlen = len - tagSize;

    if (len < tagSize) throw new IllegalStateError('authentication tag not found');

    const result = new Uint8Array(rlen);
    const atag = new Uint8Array(heap.subarray(pos + rlen, pos + len));

    asm.cipher(AES_asm.DEC.CTR, AES_asm.HEAP_DATA + pos, (rlen + 15) & -16);
    result.set(heap.subarray(pos, pos + rlen));

    let i = rlen;
    for (; i & 15; i++) heap[pos + i] = 0;
    asm.mac(AES_asm.MAC.CBC, AES_asm.HEAP_DATA + pos, i);

    asm.set_counter(0, 0, 0, 0);
    asm.get_iv(AES_asm.HEAP_DATA);
    asm.cipher(AES_asm.ENC.CTR, AES_asm.HEAP_DATA, 16);

    let acheck = 0;
    for (let j = 0; j < tagSize; ++j) acheck |= atag[j] ^ heap[j];
    if (acheck) throw new SecurityError('data integrity check failed');

    this.counter = 1;
    this.aes.pos = 0;
    this.aes.len = 0;

    return result;
  }

  private AES_CTR_set_options(nonce: Uint8Array, counter: number, size: number): void {
    if (size < 8 || size > 48) throw new IllegalArgumentError('illegal counter size');

    const mask = Math.pow(2, size) - 1;
    this.aes.asm.set_mask(0, 0, (mask / 0x100000000) | 0, mask | 0);

    const len = nonce.length;
    if (!len || len > 16) throw new IllegalArgumentError('illegal nonce size');

    this.nonce = nonce;

    const view = new DataView(new ArrayBuffer(16));
    new Uint8Array(view.buffer).set(nonce);

    this.aes.asm.set_nonce(view.getUint32(0), view.getUint32(4), view.getUint32(8), view.getUint32(12));

    if (counter < 0 || counter >= Math.pow(2, size)) throw new IllegalArgumentError('illegal counter value');

    this.counter = counter;

    this.aes.asm.set_counter(0, 0, (counter / 0x100000000) | 0, counter | 0);
  }
}
