/**
 * AES-CTR exports
 */

import {_AES_asm_instance, _AES_heap_instance} from '../exports';
import { AES_CTR_constructor, AES_CTR_Crypt } from './ctr'

function AES_CTR_crypt_bytes ( data, key, nonce ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    return new AES_CTR_constructor( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, nonce: nonce } ).encrypt(data).result;
}

export const AES_CTR = AES_CTR_constructor;

AES_CTR.encrypt = AES_CTR_crypt_bytes;
AES_CTR.decrypt = AES_CTR_crypt_bytes;

AES_CTR.Encrypt = AES_CTR.Decrypt = AES_CTR_Crypt;
