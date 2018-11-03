import { HmacSha256 } from '../hmac/hmac-sha256';
import { pbkdf2core } from './pbkdf2-core';

export function Pbkdf2HmacSha256(password: Uint8Array, salt: Uint8Array, count: number, length: number): Uint8Array {
  const hmac = new HmacSha256(password);

  return pbkdf2core(hmac, salt, length, count);
}
