import {_AES_asm_instance, _AES_heap_instance} from '../exports';
import {AES_CBC, AES_CBC_Decrypt, AES_CBC_Encrypt} from './cbc';

/**
 * @param {Uint8Array} data
 * @param {Uint8Array} key
 * @param {boolean} [padding]
 * @param {Uint8Array} [iv]
 * @returns {Uint8Array}
 */
function AES_CBC_encrypt_bytes (data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_CBC(key, iv, padding, _AES_heap_instance, _AES_asm_instance).encrypt(data).result;
}

/**
 * @param {Uint8Array} data
 * @param {Uint8Array} key
 * @param {boolean} [padding]
 * @param {Uint8Array} [iv]
 * @returns {Uint8Array}
 */
function AES_CBC_decrypt_bytes ( data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_CBC(key, iv, padding, _AES_heap_instance, _AES_asm_instance).decrypt(data).result;
}

AES_CBC.encrypt = AES_CBC_encrypt_bytes;
AES_CBC.decrypt = AES_CBC_decrypt_bytes;

AES_CBC.Encrypt = AES_CBC_Encrypt;
AES_CBC.Decrypt = AES_CBC_Decrypt;

export {AES_CBC};
