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

exports.HMAC = hmac_constructor;

hmac_sha1_constructor.bytes = hmac_sha1_bytes;
hmac_sha1_constructor.hex = hmac_sha1_hex;
hmac_sha1_constructor.base64 = hmac_sha1_base64;

exports.HMAC_SHA1 = hmac_sha1_constructor;
