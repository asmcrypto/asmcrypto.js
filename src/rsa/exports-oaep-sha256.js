/**
 * RSA-OAEP-SHA256 exports
 */

import {RSA_OAEP} from './pkcs1';
import {get_sha256_instance} from '../hash/sha256/sha256';

function rsa_oaep_sha256_encrypt_bytes (data, key, label ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA_OAEP({ hash: get_sha256_instance(), key: key, label: label })).encrypt(data).result;
}

function rsa_oaep_sha256_decrypt_bytes ( data, key, label ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA_OAEP({ hash: get_sha256_instance(), key: key, label: label })).decrypt(data).result;
}

export const RSA_OAEP_SHA256 = {
    encrypt: rsa_oaep_sha256_encrypt_bytes,
    decrypt: rsa_oaep_sha256_decrypt_bytes
};
