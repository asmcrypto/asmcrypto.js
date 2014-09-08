/**
 * PBKDF2-HMAC-SHA512 exports
 */

function pbkdf2_hmac_sha512_bytes ( password, salt, iterations, dklen ) {
    if ( password === undefined ) throw new SyntaxError("password required");
    if ( salt === undefined ) throw new SyntaxError("salt required");
    return get_pbkdf2_hmac_sha512_instance().reset( { password: password } ).generate( salt, iterations, dklen ).result;
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
