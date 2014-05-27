/**
 * SHA1 exports
 */

var SHA1_instance = new sha1_constructor( { heapSize: 0x100000 } );

function sha1_bytes ( data ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    return SHA1_instance.reset().process(data).finish().result;
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
