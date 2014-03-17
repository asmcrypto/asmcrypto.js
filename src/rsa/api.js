if ( !_is_crypto_worker )
{
    function rsa_oaep_encrypt_bytes ( data, key ) {
        if ( data === undefined ) throw new SyntaxError("data required");
        if ( key === undefined ) throw new SyntaxError("key required");
        return (new RSA_OAEP({ hash: SHA256_instance, key: key })).encrypt(data).result;
    }

    function rsa_oaep_decrypt_bytes ( data, key ) {
        if ( data === undefined ) throw new SyntaxError("data required");
        if ( key === undefined ) throw new SyntaxError("key required");
        return (new RSA_OAEP({ hash: SHA256_instance, key: key })).decrypt(data).result;
    }

    exports.RSA = RSA;
    RSA.encrypt = rsa_oaep_encrypt_bytes;
    RSA.decrypt = rsa_oaep_decrypt_bytes;
    RSA.generateKey = RSA_generateKey;
/*
    exports.RSA = {
        encrypt: rsa_encrypt_bytes,
        decrypt: rsa_decrypt_bytes,
        generateKey: RSA_generateKey
    };
*/
}
