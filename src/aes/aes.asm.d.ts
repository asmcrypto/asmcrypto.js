declare type AES_mode = 'ECB' | 'CBC' | 'CFB' | 'OFB' | 'CTR' | 'CCM';
export class AES_asm {
  constructor(foreign: any, heap: ArrayBuffer);

  /**
   * @param ks - key size, 4/6/8 (for 128/192/256-bit key correspondingly)
   * @param k0 - key vector components
   * @param k1 - key vector components
   * @param k2 - key vector components
   * @param k3 - key vector components
   * @param k4 - key vector components
   * @param k5 - key vector components
   * @param k6 - key vector components
   * @param k7 - key vector components
   */
  set_key(
    ks: number,
    k0: number,
    k1: number,
    k2: number,
    k3: number,
    k4: number,
    k5: number,
    k6: number,
    k7: number,
  ): void;

  /**
   * Populate the internal iv of the module
   */
  set_iv(i0: number, i1: number, i2: number, i3: number): void;

  /**
   * Set counter mask for CTR-family modes
   */
  set_mask(m0: number, m1: number, m2: number, m3: number): void;

  /**
   * Set nonce for CTR-family modes
   */
  set_nonce(n0: number, n1: number, n2: number, n3: number): void;

  /**
   * Set counter for CTR-family modes
   */
  set_counter(c0: number, c1: number, c2: number, c3: number): void;

  /**
   * Perform ciphering operation on the supplied data
   *
   * @param mode - block cipher mode (see {@link AES_asm} mode constants)
   * @param pos - offset of the data being processed
   * @param len - length of the data being processed
   * @return Actual amount of data have been processed
   */
  cipher(mode: number, pos: number, len: number): number;

  /**
   * GCM initialization
   */
  gcm_init(): void;

  /**
   * Store the internal iv vector into the heap
   *
   * @returns The number of bytes have been written into the heap, always 16
   */
  get_iv(pos: number): 16;

  /**
   * Calculates MAC of the supplied data
   *
   * @param mode - block cipher mode (see {@link AES_asm} mode constants)
   * @param pos - offset of the data being processed
   * @param len - length of the data being processed
   * @return Actual amount of data have been processed
   */
  mac(mode: number, pos: number, len: number): number;

  /**
   * Store the internal state vector into the heap.
   *
   * @param pos - offset where to put the data
   * @return The number of bytes have been written into the heap, always 16.
   */
  get_state(pos: number): 16;

  /**
   * AES enciphering mode constants
   */
  static ENC: {
    ECB: 0;
    CBC: 2;
    CFB: 4;
    OFB: 6;
    CTR: 7;
    [key: string]: number;
  };

  /**
   * AES deciphering mode constants
   */
  static DEC: {
    ECB: 1;
    CBC: 3;
    CFB: 5;
    OFB: 6;
    CTR: 7;
    [key: string]: number;
  };

  /**
   * AES MAC mode constants
   */
  static MAC: {
    CBC: 0;
    GCM: 1;
    [key: string]: number;
  };

  static HEAP_DATA: number;
}
