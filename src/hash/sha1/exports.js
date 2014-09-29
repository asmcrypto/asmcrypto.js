/**
 * SHA1 exports
 */

function sha1_bytes ( data ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    return get_sha1_instance().reset().process(data).finish().result;
}

function sha1_hex ( data ) {
    var result = sha1_bytes(data);
    return bytes_to_hex(result);
}

function sha1_base64 ( data ) {
    var result = sha1_bytes(data);
    return bytes_to_base64(result);
}

sha1_constructor.bytes = sha1_bytes;
sha1_constructor.hex = sha1_hex;
sha1_constructor.base64 = sha1_base64;

exports.SHA1 = sha1_constructor;
