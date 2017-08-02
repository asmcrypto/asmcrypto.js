/**
 * AES-CCM exports
 */

import {_AES_asm_instance, _AES_heap_instance} from '../exports';
import { AES_CCM_constructor, AES_CCM_Decrypt, AES_CCM_Encrypt} from './ccm';

function AES_CCM_encrypt_bytes (data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    var dataLength = data.length || 0;
    return new AES_CCM_constructor( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, nonce: nonce, adata: adata, tagSize: tagSize, dataLength: dataLength } ).encrypt(data).result;
}

function AES_CCM_decrypt_bytes ( data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    var dataLength = data.length || 0;
    tagSize = tagSize || 16;
    return new AES_CCM_constructor( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, nonce: nonce, adata: adata, tagSize: tagSize, dataLength: dataLength-tagSize } ).decrypt(data).result;
}

export var AES_CCM = AES_CCM_constructor;
AES_CCM.encrypt = AES_CCM_encrypt_bytes;
AES_CCM.decrypt = AES_CCM_decrypt_bytes;

AES_CCM.Encrypt = AES_CCM_Encrypt;
AES_CCM.Decrypt = AES_CCM_Decrypt;
