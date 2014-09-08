/**
 * RSA-OAEP-SHA1 exports
 */

function rsa_oaep_sha1_encrypt_bytes ( data, key, label ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA_OAEP({ hash: get_sha1_instance(), key: key, label: label })).encrypt(data).result;
}

function rsa_oaep_sha1_decrypt_bytes ( data, key, label ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA_OAEP({ hash: get_sha1_instance(), key: key, label: label })).decrypt(data).result;
}

exports.RSA_OAEP_SHA1 = {
    encrypt: rsa_oaep_sha1_encrypt_bytes,
    decrypt: rsa_oaep_sha1_decrypt_bytes
};
