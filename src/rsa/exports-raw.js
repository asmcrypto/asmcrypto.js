/**
 * RSA-RAW exports
 */

function rsa_raw_encrypt_bytes ( data, key ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA_RAW({ key: key })).encrypt(data).result;
}

function rsa_raw_decrypt_bytes ( data, key ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA_RAW({ key: key })).decrypt(data).result;
}

exports.RSA_RAW = {
    encrypt: rsa_raw_encrypt_bytes,
    decrypt: rsa_raw_decrypt_bytes,
    sign: rsa_raw_decrypt_bytes,
    verify: rsa_raw_encrypt_bytes
};
