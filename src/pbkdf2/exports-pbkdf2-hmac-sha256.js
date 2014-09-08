/**
 * PBKDF2-HMAC-SHA256 exports
 */

function pbkdf2_hmac_sha256_bytes ( password, salt, iterations, dklen ) {
    if ( password === undefined ) throw new SyntaxError("password required");
    if ( salt === undefined ) throw new SyntaxError("salt required");
    return get_pbkdf2_hmac_sha256_instance().reset( { password: password } ).generate( salt, iterations, dklen ).result;
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
