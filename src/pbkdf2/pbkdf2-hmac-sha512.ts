import { Pbkdf2 } from './pbkdf2';
import { HmacSha512 } from '../hmac/hmac-sha512';

export function Pbkdf2HmacSha512(password: Uint8Array, salt: Uint8Array, count: number, length: number): Uint8Array {
  return Pbkdf2(new HmacSha512(password), salt, count, length)
}

