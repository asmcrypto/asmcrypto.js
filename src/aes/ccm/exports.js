/**
 * AES-CCM exports
 */

import {_AES_asm_instance, _AES_heap_instance} from '../exports';
import {AES_CCM, AES_CCM_Decrypt, AES_CCM_Encrypt} from './ccm';

/**
 * @param {Uint8Array} data
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array} [adata]
 * @param {number} [tagSize]
 */
function AES_CCM_encrypt_bytes (data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    var dataLength = data.length || 0;
    return new AES_CCM(key, nonce, adata, tagSize, dataLength, _AES_heap_instance, _AES_asm_instance ).encrypt(data).result;
}

/**
 * @param {Uint8Array} data
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array} [adata]
 * @param {number} [tagSize]
 */
function AES_CCM_decrypt_bytes ( data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    var dataLength = data.length || 0;
    tagSize = tagSize || 16;
    return new AES_CCM( key, nonce, adata, tagSize, dataLength-tagSize, _AES_heap_instance, _AES_asm_instance ).decrypt(data).result;
}


AES_CCM.encrypt = AES_CCM_encrypt_bytes;
AES_CCM.decrypt = AES_CCM_decrypt_bytes;

AES_CCM.Encrypt = AES_CCM_Encrypt;
AES_CCM.Decrypt = AES_CCM_Decrypt;

export {AES_CCM};
