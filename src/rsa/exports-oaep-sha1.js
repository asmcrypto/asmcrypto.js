/**
 * RSA-OAEP-SHA1 exports
 */

import {RSA_OAEP} from './pkcs1';
import {get_sha1_instance} from '../hash/sha1/sha1';

function rsa_oaep_sha1_encrypt_bytes (data, key, label ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA_OAEP({ hash: get_sha1_instance(), key: key, label: label })).encrypt(data).result;
}

function rsa_oaep_sha1_decrypt_bytes ( data, key, label ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA_OAEP({ hash: get_sha1_instance(), key: key, label: label })).decrypt(data).result;
}

export const RSA_OAEP_SHA1 = {
    encrypt: rsa_oaep_sha1_encrypt_bytes,
    decrypt: rsa_oaep_sha1_decrypt_bytes
};
