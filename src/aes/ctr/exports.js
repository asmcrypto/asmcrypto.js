/**
 * AES-CTR exports
 */

import {_AES_asm_instance, _AES_heap_instance} from '../exports';
import { AES_CTR } from './ctr'

/**
 * @param {Uint8Array} data
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @returns {Uint8Array}
 */
function AES_CTR_crypt_bytes ( data, key, nonce ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    return new AES_CTR(key, nonce, _AES_heap_instance, _AES_asm_instance).encrypt(data).result;
}

AES_CTR.encrypt = AES_CTR_crypt_bytes;
AES_CTR.decrypt = AES_CTR_crypt_bytes;

AES_CTR.Encrypt = AES_CTR.Decrypt = AES_CTR;

export {AES_CTR};
