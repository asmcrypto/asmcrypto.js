import { IllegalArgumentError, IllegalStateError, SecurityError } from '../other/errors';
import { _heap_write } from '../other/utils';
import { AES } from './aes';
import { AES_asm } from './aes.asm';

const _AES_GCM_data_maxLength = 68719476704; // 2^36 - 2^5

export class AES_GCM extends AES {
  private readonly adata: Uint8Array | undefined;
  private readonly gamma0: number = 0;

  private counter: number = 1;

  static encrypt(
    cleartext: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    adata?: Uint8Array,
    tagsize?: number,
  ): Uint8Array {
    return new AES_GCM(key, nonce, adata, tagsize).encrypt(cleartext);
  }

  static decrypt(
    ciphertext: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    adata?: Uint8Array,
    tagsize?: number,
  ): Uint8Array {
    return new AES_GCM(key, nonce, adata, tagsize).decrypt(ciphertext);
  }

  constructor(key: Uint8Array, nonce: Uint8Array, adata?: Uint8Array, private readonly tagSize: number = 16) {
    super(key, undefined, false, 'CTR');

    // Init GCM
    this.asm.gcm_init();

    // Tag size
    if (this.tagSize < 4 || this.tagSize > 16) throw new IllegalArgumentError('illegal tagSize value');

    // Nonce
    const noncelen = nonce.length || 0;
    const noncebuf = new Uint8Array(16);
    if (noncelen !== 12) {
      this._gcm_mac_process(nonce);

      this.heap[0] = 0;
      this.heap[1] = 0;
      this.heap[2] = 0;
      this.heap[3] = 0;
      this.heap[4] = 0;
      this.heap[5] = 0;
      this.heap[6] = 0;
      this.heap[7] = 0;
      this.heap[8] = 0;
      this.heap[9] = 0;
      this.heap[10] = 0;
      this.heap[11] = noncelen >>> 29;
      this.heap[12] = (noncelen >>> 21) & 255;
      this.heap[13] = (noncelen >>> 13) & 255;
      this.heap[14] = (noncelen >>> 5) & 255;
      this.heap[15] = (noncelen << 3) & 255;
      this.asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA, 16);

      this.asm.get_iv(AES_asm.HEAP_DATA);
      this.asm.set_iv(0, 0, 0, 0);

      noncebuf.set(this.heap.subarray(0, 16));
    } else {
      noncebuf.set(nonce);
      noncebuf[15] = 1;
    }

    const nonceview = new DataView(noncebuf.buffer);
    this.gamma0 = nonceview.getUint32(12);

    this.asm.set_nonce(nonceview.getUint32(0), nonceview.getUint32(4), nonceview.getUint32(8), 0);
    this.asm.set_mask(0, 0, 0, 0xffffffff);

    // Associated data
    if (adata !== undefined) {
      if (adata.length > _AES_GCM_data_maxLength) throw new IllegalArgumentError('illegal adata length');

      if (adata.length) {
        this.adata = adata;
        this._gcm_mac_process(adata);
      } else {
        this.adata = undefined;
      }
    } else {
      this.adata = undefined;
    }

    // Counter
    if (this.counter < 1 || this.counter > 0xffffffff)
      throw new RangeError('counter must be a positive 32-bit integer');
    this.asm.set_counter(0, 0, 0, (this.gamma0 + this.counter) | 0);
  }

  encrypt(data: Uint8Array) {
    return this.AES_GCM_encrypt(data);
  }

  decrypt(data: Uint8Array) {
    return this.AES_GCM_decrypt(data);
  }

  AES_GCM_Encrypt_process(data: Uint8Array): Uint8Array {
    let dpos = 0;
    let dlen = data.length || 0;
    let asm = this.asm;
    let heap = this.heap;
    let counter = this.counter;
    let pos = this.pos;
    let len = this.len;
    let rpos = 0;
    let rlen = (len + dlen) & -16;
    let wlen = 0;

    if (((counter - 1) << 4) + len + dlen > _AES_GCM_data_maxLength) throw new RangeError('counter overflow');

    const result = new Uint8Array(rlen);

    while (dlen > 0) {
      wlen = _heap_write(heap, pos + len, data, dpos, dlen);
      len += wlen;
      dpos += wlen;
      dlen -= wlen;

      wlen = asm.cipher(AES_asm.ENC.CTR, AES_asm.HEAP_DATA + pos, len);
      wlen = asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, wlen);

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
    this.pos = pos;
    this.len = len;

    return result;
  }

  AES_GCM_Encrypt_finish(): Uint8Array {
    let asm = this.asm;
    let heap = this.heap;
    let counter = this.counter;
    let tagSize = this.tagSize;
    let adata = this.adata;
    let pos = this.pos;
    let len = this.len;

    const result = new Uint8Array(len + tagSize);

    asm.cipher(AES_asm.ENC.CTR, AES_asm.HEAP_DATA + pos, (len + 15) & -16);
    if (len) result.set(heap.subarray(pos, pos + len));

    let i = len;
    for (; i & 15; i++) heap[pos + i] = 0;
    asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, i);

    const alen = adata !== undefined ? adata.length : 0;
    const clen = ((counter - 1) << 4) + len;

    heap[0] = 0;
    heap[1] = 0;
    heap[2] = 0;
    heap[3] = alen >>> 29;
    heap[4] = alen >>> 21;
    heap[5] = (alen >>> 13) & 255;
    heap[6] = (alen >>> 5) & 255;
    heap[7] = (alen << 3) & 255;
    heap[8] = heap[9] = heap[10] = 0;
    heap[11] = clen >>> 29;
    heap[12] = (clen >>> 21) & 255;
    heap[13] = (clen >>> 13) & 255;
    heap[14] = (clen >>> 5) & 255;
    heap[15] = (clen << 3) & 255;

    asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA, 16);
    asm.get_iv(AES_asm.HEAP_DATA);

    asm.set_counter(0, 0, 0, this.gamma0);
    asm.cipher(AES_asm.ENC.CTR, AES_asm.HEAP_DATA, 16);
    result.set(heap.subarray(0, tagSize), len);

    this.counter = 1;
    this.pos = 0;
    this.len = 0;

    return result;
  }

  AES_GCM_Decrypt_process(data: Uint8Array): Uint8Array {
    let dpos = 0;
    let dlen = data.length || 0;
    let asm = this.asm;
    let heap = this.heap;
    let counter = this.counter;
    let tagSize = this.tagSize;
    let pos = this.pos;
    let len = this.len;
    let rpos = 0;
    let rlen = len + dlen > tagSize ? (len + dlen - tagSize) & -16 : 0;
    let tlen = len + dlen - rlen;
    let wlen = 0;

    if (((counter - 1) << 4) + len + dlen > _AES_GCM_data_maxLength) throw new RangeError('counter overflow');

    const result = new Uint8Array(rlen);

    while (dlen > tlen) {
      wlen = _heap_write(heap, pos + len, data, dpos, dlen - tlen);
      len += wlen;
      dpos += wlen;
      dlen -= wlen;

      wlen = asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, wlen);
      wlen = asm.cipher(AES_asm.DEC.CTR, AES_asm.HEAP_DATA + pos, wlen);

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
    this.pos = pos;
    this.len = len;

    return result;
  }

  AES_GCM_Decrypt_finish() {
    let asm = this.asm;
    let heap = this.heap;
    let tagSize = this.tagSize;
    let adata = this.adata;
    let counter = this.counter;
    let pos = this.pos;
    let len = this.len;
    let rlen = len - tagSize;

    if (len < tagSize) throw new IllegalStateError('authentication tag not found');

    const result = new Uint8Array(rlen);
    const atag = new Uint8Array(heap.subarray(pos + rlen, pos + len));

    let i = rlen;
    for (; i & 15; i++) heap[pos + i] = 0;

    asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, i);
    asm.cipher(AES_asm.DEC.CTR, AES_asm.HEAP_DATA + pos, i);

    if (rlen) result.set(heap.subarray(pos, pos + rlen));

    const alen = adata !== undefined ? adata.length : 0;
    const clen = ((counter - 1) << 4) + len - tagSize;
    heap[0] = 0;
    heap[1] = 0;
    heap[2] = 0;
    heap[3] = alen >>> 29;
    heap[4] = alen >>> 21;
    heap[5] = (alen >>> 13) & 255;
    heap[6] = (alen >>> 5) & 255;
    heap[7] = (alen << 3) & 255;
    heap[8] = heap[9] = heap[10] = 0;
    heap[11] = clen >>> 29;
    heap[12] = (clen >>> 21) & 255;
    heap[13] = (clen >>> 13) & 255;
    heap[14] = (clen >>> 5) & 255;
    heap[15] = (clen << 3) & 255;
    asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA, 16);
    asm.get_iv(AES_asm.HEAP_DATA);

    asm.set_counter(0, 0, 0, this.gamma0);
    asm.cipher(AES_asm.ENC.CTR, AES_asm.HEAP_DATA, 16);

    let acheck = 0;
    for (let i = 0; i < tagSize; ++i) acheck |= atag[i] ^ heap[i];
    if (acheck) throw new SecurityError('data integrity check failed');

    this.counter = 1;
    this.pos = 0;
    this.len = 0;

    return result;
  }

  private AES_GCM_decrypt(data: Uint8Array): Uint8Array {
    const result1 = this.AES_GCM_Decrypt_process(data);
    const result2 = this.AES_GCM_Decrypt_finish();

    const result = new Uint8Array(result1.length + result2.length);
    if (result1.length) result.set(result1);
    if (result2.length) result.set(result2, result1.length);

    return result;
  }

  private AES_GCM_encrypt(data: Uint8Array): Uint8Array {
    const result1 = this.AES_GCM_Encrypt_process(data);
    const result2 = this.AES_GCM_Encrypt_finish();

    const result = new Uint8Array(result1.length + result2.length);
    if (result1.length) result.set(result1);
    if (result2.length) result.set(result2, result1.length);

    return result;
  }

  _gcm_mac_process(data: Uint8Array) {
    const heap = this.heap;
    const asm = this.asm;
    let dpos = 0;
    let dlen = data.length || 0;
    let wlen = 0;

    while (dlen > 0) {
      wlen = _heap_write(heap, 0, data, dpos, dlen);
      dpos += wlen;
      dlen -= wlen;

      while (wlen & 15) heap[wlen++] = 0;

      asm.mac(AES_asm.MAC.GCM, AES_asm.HEAP_DATA, wlen);
    }
  }
}
