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

exports.SHA256 = {
    bytes: sha256_bytes,
    hex: sha256_hex,
    base64: sha256_base64
};
