declare interface sha512result {
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
    p0h: number,
    p0l: number,
    p1h: number,
    p1l: number,
    p2h: number,
    p2l: number,
    p3h: number,
    p3l: number,
    p4h: number,
    p4l: number,
    p5h: number,
    p5l: number,
    p6h: number,
    p6l: number,
    p7h: number,
    p7l: number,
    p8h: number,
    p8l: number,
    p9h: number,
    p9l: number,
    p10h: number,
    p10l: number,
    p11h: number,
    p11l: number,
    p12h: number,
    p12l: number,
    p13h: number,
    p13l: number,
    p14h: number,
    p14l: number,
    p15h: number,
    p15l: number,
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

export function sha512_asm(stdlib: any, foreign: any, buffer: ArrayBuffer): sha512result;
