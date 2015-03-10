/**
 * SHA512 exports
 */

function sha512_bytes ( data ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    return get_sha512_instance().reset().process(data).finish().result;
}

function sha512_hex ( data ) {
    var result = sha512_bytes(data);
    return bytes_to_hex(result);
}

function sha512_base64 ( data ) {
    var result = sha512_bytes(data);
    return bytes_to_base64(result);
}

sha512_constructor.bytes = sha512_bytes;
sha512_constructor.hex = sha512_hex;
sha512_constructor.base64 = sha512_base64;

exports.SHA512 = sha512_constructor;
