import { HmacSha512 } from '../hmac/hmac-sha512';
import { pbkdf2core } from './pbkdf2-core';

export function Pbkdf2HmacSha512(password: Uint8Array, salt: Uint8Array, count: number, length: number): Uint8Array {
  const hmac = new HmacSha512(password);

  return pbkdf2core(hmac, salt, length, count);
}
