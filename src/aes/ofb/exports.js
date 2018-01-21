/**
 * AES-OFB exports
 */

import { _AES_asm_instance, _AES_heap_instance } from '../exports';
import { AES_OFB, AES_OFB_Crypt } from './ofb';

/**
 * @param {Uint8Array} data
 * @param {Uint8Array} key
 * @param {Uint8Array} iv
 */
function AES_OFB_crypt_bytes(data, key, iv) {
  if (data === undefined) throw new SyntaxError('data required');
  if (key === undefined) throw new SyntaxError('key required');
  return new AES_OFB(key, iv, _AES_heap_instance, _AES_asm_instance).encrypt(data).result;
}

AES_OFB.encrypt = AES_OFB_crypt_bytes;
AES_OFB.decrypt = AES_OFB_crypt_bytes;

export { AES_OFB, AES_OFB_Crypt };
