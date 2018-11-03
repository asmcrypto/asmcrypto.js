import { HmacSha1 } from '../hmac/hmac-sha1';
import { pbkdf2core } from './pbkdf2-core';

export function Pbkdf2HmacSha1(password: Uint8Array, salt: Uint8Array, count: number, length: number): Uint8Array {
  const hmac = new HmacSha1(password);

  return pbkdf2core(hmac, salt, length, count);
}
