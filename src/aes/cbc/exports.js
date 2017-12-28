import {AES_CBC_constructor, AES_CBC_Decrypt, AES_CBC_Encrypt} from './cbc';
import {_AES_asm_instance, _AES_heap_instance} from '../exports';

/**
 * AES-CBC exports
 */

function AES_CBC_encrypt_bytes (data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_CBC_constructor( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, padding: padding, iv: iv } ).encrypt(data).result;
}

function AES_CBC_decrypt_bytes ( data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_CBC_constructor( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, padding: padding, iv: iv } ).decrypt(data).result;
}

export var AES_CBC = AES_CBC_constructor;
AES_CBC.encrypt = AES_CBC_encrypt_bytes;
AES_CBC.decrypt = AES_CBC_decrypt_bytes;

AES_CBC.Encrypt = AES_CBC_Encrypt;
AES_CBC.Decrypt = AES_CBC_Decrypt;
