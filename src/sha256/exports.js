/**
 * SHA256 exports
 */

function sha256_bytes ( data ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    return get_sha256_instance().reset().process(data).finish().result;
}

function sha256_hex ( data ) {
    var result = sha256_bytes(data);
    return bytes_to_hex(result);
}

function sha256_base64 ( data ) {
    var result = sha256_bytes(data);
    return bytes_to_base64(result);
}

sha256_constructor.bytes = sha256_bytes;
sha256_constructor.hex = sha256_hex;
sha256_constructor.base64 = sha256_base64;

exports.SHA256 = sha256_constructor;
