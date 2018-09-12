import { Pbkdf2 } from './pbkdf2';
import { HmacSha1 } from '../hmac/hmac-sha1';

export function Pbkdf2HmacSha1(password: Uint8Array, salt: Uint8Array, count: number, length: number): Uint8Array {
  return Pbkdf2(new HmacSha1(password), salt, count, length);
}
