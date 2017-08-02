/**
 * AES-CFB exports
 */

import {_AES_asm_instance, _AES_heap_instance} from '../exports';
import { AES_CFB_constructor, AES_CFB_Decrypt, AES_CFB_Encrypt} from './cfb';

function AES_CFB_encrypt_bytes ( data, key, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_CFB_constructor( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, iv: iv } ).encrypt(data).result;
}

function AES_CFB_decrypt_bytes ( data, key, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_CFB_constructor( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, iv: iv } ).decrypt(data).result;
}

export var AES_CFB = AES_CFB_constructor;

AES_CFB.encrypt = AES_CFB_encrypt_bytes;
AES_CFB.decrypt = AES_CFB_decrypt_bytes;

AES_CFB.Encrypt = AES_CFB_Encrypt;
AES_CFB.Decrypt = AES_CFB_Decrypt;
