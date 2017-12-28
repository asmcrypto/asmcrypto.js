/**
 * AES-GCM exports
 */

import {_AES_asm_instance, _AES_heap_instance} from '../exports';
import { AES_GCM_constructor, AES_GCM_Decrypt, AES_GCM_Encrypt} from './gcm';


function AES_GCM_encrypt_bytes ( data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    return new AES_GCM_constructor( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, nonce: nonce, adata: adata, tagSize: tagSize } ).encrypt(data).result;
}

function AES_GCM_decrypt_bytes ( data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    return new AES_GCM_constructor( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, nonce: nonce, adata: adata, tagSize: tagSize } ).decrypt(data).result;
}

export var AES_GCM = AES_GCM_constructor;

AES_GCM.encrypt = AES_GCM_encrypt_bytes;
AES_GCM.decrypt = AES_GCM_decrypt_bytes;

AES_GCM.Encrypt = AES_GCM_Encrypt;
AES_GCM.Decrypt = AES_GCM_Decrypt;
