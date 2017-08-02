/**
 * AES-OFB exports
 */

import {_AES_asm_instance, _AES_heap_instance} from '../exports';
import {AES_OFB_constructor, AES_OFB_Crypt} from './ofb';


function AES_OFB_crypt_bytes ( data, key, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_OFB_constructor( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, iv: iv } ).encrypt(data).result;
}

export const AES_OFB = AES_OFB_constructor;

AES_OFB.encrypt = AES_OFB_crypt_bytes;
AES_OFB.decrypt = AES_OFB_crypt_bytes;

AES_OFB.Encrypt = AES_OFB.Decrypt = AES_OFB_Crypt;
