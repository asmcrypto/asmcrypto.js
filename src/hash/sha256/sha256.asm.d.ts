declare interface sha256result {
  // SHA1
  reset: () => void;
  init: (h0: number, h1: number, h2: number, h3: number, h4: number, total0: number, total1: number) => void;

  /**
   * @param offset - multiple of 64
   * @param length
   * @returns hashed
   */
  process: (offset: number, length: number) => number;

  /**
   * @param offset - multiple of 64
   * @param length
   * @param output - multiple of 32
   * @returns hashed
   */
  finish: (offset: number, length: number, output: number) => number;

  // HMAC-SHA;
  hmac_reset: () => void;
  hmac_init: (
    p0: number,
    p1: number,
    p2: number,
    p3: number,
    p4: number,
    p5: number,
    p6: number,
    p7: number,
    p8: number,
    p9: number,
    p10: number,
    p11: number,
    p12: number,
    p13: number,
    p14: number,
    p15: number,
  ) => void;

  /**
   * @param offset - multiple of 64
   * @param length
   * @param output - multiple of 32
   * @returns hashed
   */
  hmac_finish: (offset: number, length: number, output: number) => number;

  // ;
  /**
   * PBKDF2-HMAC-SHA
   * @param offset - multiple of 64
   * @param length
   * @param block
   * @param count
   * @param output - multiple of 32
   */
  pbkdf2_generate_block: (offset: number, length: number, block: number, count: number, output: number) => 0 | -1;
}

export function sha256_asm(stdlib: any, foreign: any, buffer: ArrayBuffer): sha256result;
