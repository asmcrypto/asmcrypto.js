/**
 * AES-CFB exports
 */

import { _AES_asm_instance, _AES_heap_instance } from '../exports';
import { AES_CFB, AES_CFB_Decrypt, AES_CFB_Encrypt } from './cfb';

/**
 * @param {Uint8Array} data
 * @param {Uint8Array} key
 * @param {Uint8Array} [iv]
 * @returns {Uint8Array}
 */
function AES_CFB_encrypt_bytes(data, key, iv) {
  if (data === undefined) throw new SyntaxError('data required');
  if (key === undefined) throw new SyntaxError('key required');
  return new AES_CFB(key, iv, _AES_heap_instance, _AES_asm_instance).encrypt(data).result;
}

/**
 * @param {Uint8Array} data
 * @param {Uint8Array} key
 * @param {Uint8Array} [iv]
 * @returns {Uint8Array}
 */
function AES_CFB_decrypt_bytes(data, key, iv) {
  if (data === undefined) throw new SyntaxError('data required');
  if (key === undefined) throw new SyntaxError('key required');
  return new AES_CFB(key, iv, _AES_heap_instance, _AES_asm_instance).decrypt(data).result;
}

AES_CFB.encrypt = AES_CFB_encrypt_bytes;
AES_CFB.decrypt = AES_CFB_decrypt_bytes;

export { AES_CFB, AES_CFB_Encrypt, AES_CFB_Decrypt };
