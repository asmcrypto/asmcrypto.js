/**
 * PBKDF2-HMAC-SHA1 exports
 */
if ( pbkdf2_hmac_sha1_constructor !== undefined )
{
    var pbkdf2_hmac_sha1_instance = new pbkdf2_hmac_sha1_constructor( { hmac: hmac_sha1_instance } );

    function pbkdf2_hmac_sha1_bytes ( password, salt, iterations, dklen ) {
        if ( password === undefined ) throw new SyntaxError("password required");
        if ( salt === undefined ) throw new SyntaxError("salt required");
        return pbkdf2_hmac_sha1_instance.reset( { password: password } ).generate( salt, iterations, dklen ).result;
    }

    function pbkdf2_hmac_sha1_hex ( password, salt, iterations, dklen ) {
        var result = pbkdf2_hmac_sha1_bytes( password, salt, iterations, dklen );
        return bytes_to_hex(result);
    }

    function pbkdf2_hmac_sha1_base64 ( password, salt, iterations, dklen ) {
        var result = pbkdf2_hmac_sha1_bytes( password, salt, iterations, dklen );
        return bytes_to_base64(result);
    }

    exports.PBKDF2 =
    exports.PBKDF2_HMAC_SHA1 = {
        bytes: pbkdf2_hmac_sha1_bytes,
        hex: pbkdf2_hmac_sha1_hex,
        base64: pbkdf2_hmac_sha1_base64
    };
}

/**
 * PBKDF2-HMAC-SHA256 exports
 */
if ( pbkdf2_hmac_sha256_constructor !== undefined )
{
    var pbkdf2_hmac_sha256_instance = new pbkdf2_hmac_sha256_constructor( { hmac: hmac_sha256_instance } );

    function pbkdf2_hmac_sha256_bytes ( password, salt, iterations, dklen ) {
        if ( password === undefined ) throw new SyntaxError("password required");
        if ( salt === undefined ) throw new SyntaxError("salt required");
        return pbkdf2_hmac_sha256_instance.reset( { password: password } ).generate( salt, iterations, dklen ).result;
    }

    function pbkdf2_hmac_sha256_hex ( password, salt, iterations, dklen ) {
        var result = pbkdf2_hmac_sha256_bytes( password, salt, iterations, dklen );
        return bytes_to_hex(result);
    }

    function pbkdf2_hmac_sha256_base64 ( password, salt, iterations, dklen ) {
        var result = pbkdf2_hmac_sha256_bytes( password, salt, iterations, dklen );
        return bytes_to_base64(result);
    }

    exports.PBKDF2_HMAC_SHA256 = {
        bytes: pbkdf2_hmac_sha256_bytes,
        hex: pbkdf2_hmac_sha256_hex,
        base64: pbkdf2_hmac_sha256_base64
    };
}

/**
 * PBKDF2-HMAC-SHA512 exports
 */
if ( pbkdf2_hmac_sha512_constructor !== undefined )
{
    var pbkdf2_hmac_sha512_instance = new pbkdf2_hmac_sha512_constructor( { hmac: hmac_sha512_instance } );

    function pbkdf2_hmac_sha512_bytes ( password, salt, iterations, dklen ) {
        if ( password === undefined ) throw new SyntaxError("password required");
        if ( salt === undefined ) throw new SyntaxError("salt required");
        return pbkdf2_hmac_sha512_instance.reset( { password: password } ).generate( salt, iterations, dklen ).result;
    }

    function pbkdf2_hmac_sha512_hex ( password, salt, iterations, dklen ) {
        var result = pbkdf2_hmac_sha512_bytes( password, salt, iterations, dklen );
        return bytes_to_hex(result);
    }

    function pbkdf2_hmac_sha512_base64 ( password, salt, iterations, dklen ) {
        var result = pbkdf2_hmac_sha512_bytes( password, salt, iterations, dklen );
        return bytes_to_base64(result);
    }

    exports.PBKDF2_HMAC_SHA512 = {
        bytes: pbkdf2_hmac_sha512_bytes,
        hex: pbkdf2_hmac_sha512_hex,
        base64: pbkdf2_hmac_sha512_base64
    };
}
