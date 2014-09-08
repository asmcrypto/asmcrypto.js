/**
 * HMAC-SHA1 exports
 */

function hmac_sha1_bytes ( data, password ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( password === undefined ) throw new SyntaxError("password required");
    return get_hmac_sha1_instance().reset( { password: password } ).process(data).finish().result;
}

function hmac_sha1_hex ( data, password ) {
    var result = hmac_sha1_bytes( data, password );
    return bytes_to_hex(result);
}

function hmac_sha1_base64 ( data, password ) {
    var result = hmac_sha1_bytes( data, password );
    return bytes_to_base64(result);
}

exports.HMAC =
exports.HMAC_SHA1 = {
    bytes: hmac_sha1_bytes,
    hex: hmac_sha1_hex,
    base64: hmac_sha1_base64
};
