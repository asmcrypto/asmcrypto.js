/**
 * AES-GCM exports
 */

import { _AES_asm_instance, _AES_heap_instance } from '../exports';
import { AES_GCM, AES_GCM_Decrypt, AES_GCM_Encrypt } from './gcm';

/**
 * @param {Uint8Array} data
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array} [adata]
 * @param {number} [tagSize]
 * @return {Uint8Array}
 */
function AES_GCM_encrypt_bytes(data, key, nonce, adata, tagSize) {
  if (data === undefined) throw new SyntaxError('data required');
  if (key === undefined) throw new SyntaxError('key required');
  if (nonce === undefined) throw new SyntaxError('nonce required');
  return new AES_GCM(key, nonce, adata, tagSize, _AES_heap_instance, _AES_asm_instance).encrypt(data).result;
}

/**
 * @param {Uint8Array} data
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array} [adata]
 * @param {number} [tagSize]
 * @return {Uint8Array}
 */
function AES_GCM_decrypt_bytes(data, key, nonce, adata, tagSize) {
  if (data === undefined) throw new SyntaxError('data required');
  if (key === undefined) throw new SyntaxError('key required');
  if (nonce === undefined) throw new SyntaxError('nonce required');
  return new AES_GCM(key, nonce, adata, tagSize, _AES_heap_instance, _AES_asm_instance).decrypt(data).result;
}

AES_GCM.encrypt = AES_GCM_encrypt_bytes;
AES_GCM.decrypt = AES_GCM_decrypt_bytes;

export { AES_GCM, AES_GCM_Encrypt, AES_GCM_Decrypt };
