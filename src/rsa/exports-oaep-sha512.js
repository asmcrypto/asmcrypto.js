/**
 * RSA-OAEP-SHA512 exports
 */

function rsa_oaep_sha512_encrypt_bytes ( data, key, label ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA_OAEP({ hash: get_sha512_instance(), key: key, label: label })).encrypt(data).result;
}

function rsa_oaep_sha512_decrypt_bytes ( data, key, label ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA_OAEP({ hash: get_sha512_instance(), key: key, label: label })).decrypt(data).result;
}

exports.RSA_OAEP_SHA512 = {
    encrypt: rsa_oaep_sha512_encrypt_bytes,
    decrypt: rsa_oaep_sha512_decrypt_bytes
};
