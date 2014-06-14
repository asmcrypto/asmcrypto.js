/**
 * RSA keygen exports
 */
function rsa_generate_key ( bitlen, e ) {
    if ( bitlen === undefined ) throw new SyntaxError("bitlen required");
    if ( e === undefined ) throw new SyntaxError("e required");
    var key = RSA_generateKey( bitlen, e );
    for ( var i = 0; i < key.length; i++ ) {
        if ( is_big_number(key[i]) )
            key[i] = key[i].toBytes();
    }
    return key;
}

exports.RSA = {
    generateKey: rsa_generate_key
};

/**
 * RSA-RAW exports
 */
if ( typeof RSA_RAW !== 'undefined' ) {
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
}

/**
 * RSA-OAEP-SHA1 exports
 * RSA-PSS-SHA1 exports
 */
if ( typeof get_sha1_instance !== 'undefined' )
{
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

    function rsa_pss_sha1_sign_bytes ( data, key, slen ) {
        if ( data === undefined ) throw new SyntaxError("data required");
        if ( key === undefined ) throw new SyntaxError("key required");
        return (new RSA_PSS({ hash: get_sha1_instance(), key: key, saltLength: slen })).sign(data).result;
    }

    function rsa_pss_sha1_verify_bytes ( signature, data, key, slen ) {
        if ( signature === undefined ) throw new SyntaxError("signature required");
        if ( data === undefined ) throw new SyntaxError("data required");
        if ( key === undefined ) throw new SyntaxError("key required");
        try {
            (new RSA_PSS({ hash: get_sha1_instance(), key: key, saltLength: slen })).verify(signature, data);
            return true;
        }
        catch ( e ) {
            if ( !( e instanceof SecurityError ) )
                throw e;
        }
        return false;
    }

    exports.RSA_PSS_SHA1 = {
        sign: rsa_pss_sha1_sign_bytes,
        verify: rsa_pss_sha1_verify_bytes
    };
}

/**
 * RSA-OAEP-SHA256 exports
 * RSA-PSS-SHA256 exports
 */
if ( typeof get_sha256_instance !== 'undefined' )
{
    function rsa_oaep_sha256_encrypt_bytes ( data, key, label ) {
        if ( data === undefined ) throw new SyntaxError("data required");
        if ( key === undefined ) throw new SyntaxError("key required");
        return (new RSA_OAEP({ hash: get_sha256_instance(), key: key, label: label })).encrypt(data).result;
    }

    function rsa_oaep_sha256_decrypt_bytes ( data, key, label ) {
        if ( data === undefined ) throw new SyntaxError("data required");
        if ( key === undefined ) throw new SyntaxError("key required");
        return (new RSA_OAEP({ hash: get_sha256_instance(), key: key, label: label })).decrypt(data).result;
    }

    exports.RSA_OAEP_SHA256 = {
        encrypt: rsa_oaep_sha256_encrypt_bytes,
        decrypt: rsa_oaep_sha256_decrypt_bytes
    };

    function rsa_pss_sha256_sign_bytes ( data, key, slen ) {
        if ( data === undefined ) throw new SyntaxError("data required");
        if ( key === undefined ) throw new SyntaxError("key required");
        return (new RSA_PSS({ hash: get_sha256_instance(), key: key, saltLength: slen })).sign(data).result;
    }

    function rsa_pss_sha256_verify_bytes ( signature, data, key, slen ) {
        if ( signature === undefined ) throw new SyntaxError("signature required");
        if ( data === undefined ) throw new SyntaxError("data required");
        if ( key === undefined ) throw new SyntaxError("key required");
        try {
            (new RSA_PSS({ hash: get_sha256_instance(), key: key, saltLength: slen })).verify(signature, data);
            return true;
        }
        catch ( e ) {
            if ( !( e instanceof SecurityError ) )
                throw e;
        }
        return false;
    }

    exports.RSA_PSS_SHA256 = {
        sign: rsa_pss_sha256_sign_bytes,
        verify: rsa_pss_sha256_verify_bytes
    };
}

/**
 * RSA-OAEP-SHA512 exports
 * RSA-PSS-SHA512 exports
 */
if ( typeof get_sha512_instance !== 'undefined' )
{
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

    function rsa_pss_sha512_sign_bytes ( data, key, slen ) {
        if ( data === undefined ) throw new SyntaxError("data required");
        if ( key === undefined ) throw new SyntaxError("key required");
        return (new RSA_PSS({ hash: get_sha512_instance(), key: key, saltLength: slen })).sign(data).result;
    }

    function rsa_pss_sha512_verify_bytes ( signature, data, key, slen ) {
        if ( signature === undefined ) throw new SyntaxError("signature required");
        if ( data === undefined ) throw new SyntaxError("data required");
        if ( key === undefined ) throw new SyntaxError("key required");
        try {
            (new RSA_PSS({ hash: get_sha512_instance(), key: key, saltLength: slen })).verify(signature, data);
            return true;
        }
        catch ( e ) {
            if ( !( e instanceof SecurityError ) )
                throw e;
        }
        return false;
    }

    exports.RSA_PSS_SHA512 = {
        sign: rsa_pss_sha512_sign_bytes,
        verify: rsa_pss_sha512_verify_bytes
    };
}
