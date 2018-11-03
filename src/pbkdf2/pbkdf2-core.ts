import { HmacSha1 } from "../hmac/hmac-sha1";
import { HmacSha256 } from "../hmac/hmac-sha256";
import { HmacSha512 } from "../hmac/hmac-sha512";

export function pbkdf2core(hmac: HmacSha1 | HmacSha256 | HmacSha512, salt: Uint8Array, length: number, count: number): Uint8Array {
  const result = new Uint8Array(length);

  const blocks = Math.ceil(length / hmac.HMAC_SIZE);

  for (let i = 1; i <= blocks; ++i) {
    const j = (i - 1) * hmac.HMAC_SIZE;
    const l = (i < blocks ? 0 : length % hmac.HMAC_SIZE) || hmac.HMAC_SIZE;

    hmac.reset().process(salt);
    hmac.hash.asm.pbkdf2_generate_block(hmac.hash.pos, hmac.hash.len, i, count, 0);

    result.set(hmac.hash.heap.subarray(0, l), j);
  }

  return result;
}
