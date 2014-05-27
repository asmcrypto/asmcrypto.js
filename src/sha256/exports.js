/**
 * SHA256 exports
 */

var SHA256_instance = new sha256_constructor( { heapSize: 0x100000 } );

function sha256_bytes ( data ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    return SHA256_instance.reset().process(data).finish().result;
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
