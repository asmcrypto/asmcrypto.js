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

exports.SHA1 = {
    bytes: sha1_bytes,
    hex: sha1_hex,
    base64: sha1_base64
};
