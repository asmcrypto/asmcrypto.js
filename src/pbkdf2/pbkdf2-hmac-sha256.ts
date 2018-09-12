import { Pbkdf2 } from './pbkdf2';
import { HmacSha256 } from '../hmac/hmac-sha256';

export function Pbkdf2HmacSha256(password: Uint8Array, salt: Uint8Array, count: number, length: number): Uint8Array {
  return Pbkdf2(new HmacSha256(password), salt, count, length);
}
