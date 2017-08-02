/**
 * RSA-RAW exports
 */

import RSA from './raw';

function rsa_raw_encrypt_bytes ( data, key ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA({ key: key })).encrypt(data).result;
}

function rsa_raw_decrypt_bytes ( data, key ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA({ key: key })).decrypt(data).result;
}

export var RSA_RAW = RSA;

RSA_RAW.encrypt = rsa_raw_encrypt_bytes;
RSA_RAW.decrypt = rsa_raw_decrypt_bytes;
RSA_RAW.sign = rsa_raw_decrypt_bytes;
RSA_RAW.verify = rsa_raw_encrypt_bytes;

