/**
 * AES-ECB exports
 */

import { _AES_asm_instance, _AES_heap_instance } from '../exports';
import { AES_ECB, AES_ECB_Decrypt, AES_ECB_Encrypt } from './ecb';

function AES_ECB_encrypt_bytes(data, key) {
  if (data === undefined) throw new SyntaxError('data required');
  if (key === undefined) throw new SyntaxError('key required');
  return new AES_ECB(key, _AES_heap_instance, _AES_asm_instance).encrypt(data).result;
}

function AES_ECB_decrypt_bytes(data, key) {
  if (data === undefined) throw new SyntaxError('data required');
  if (key === undefined) throw new SyntaxError('key required');
  return new AES_ECB(key, _AES_heap_instance, _AES_asm_instance).decrypt(data).result;
}

AES_ECB.encrypt = AES_ECB_encrypt_bytes;
AES_ECB.decrypt = AES_ECB_decrypt_bytes;

AES_ECB.Encrypt = AES_ECB_Encrypt;
AES_ECB.Decrypt = AES_ECB_Decrypt;

export { AES_ECB };
