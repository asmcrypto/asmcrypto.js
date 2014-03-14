if ( !_is_crypto_worker )
{
    function rsa_encrypt_bytes ( data, e, m ) {
        if ( data === undefined ) throw new SyntaxError("data required");
        if ( e === undefined ) throw new SyntaxError("public exponent required");
        if ( m === undefined ) throw new SyntaxError("modulus required");
        return (new RSA({ modulus: m, publicExponent: e })).encrypt(data).result;
    }

    function rsa_decrypt_bytes ( data, d, m ) {
        if ( data === undefined ) throw new SyntaxError("data required");
        if ( d === undefined ) throw new SyntaxError("private exponent required");
        if ( m === undefined ) throw new SyntaxError("modulus required");
        return (new RSA({ modulus: m, privateExponent: d })).decrypt(data).result;
    }

    exports.RSA = RSA;
    RSA.encrypt = rsa_encrypt_bytes;
    RSA.decrypt = rsa_decrypt_bytes;
    RSA.generateKey = RSA_generateKey;
/*
    exports.RSA = {
        encrypt: rsa_encrypt_bytes,
        decrypt: rsa_decrypt_bytes
    };
*/
}
