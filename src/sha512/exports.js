/**
 * SHA512 exports
 */

var SHA512_instance = new sha512_constructor( { heapSize: 0x100000 } );

function sha512_bytes ( data ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    return SHA512_instance.reset().process(data).finish().result;
}

function sha512_hex ( data ) {
    var result = sha512_bytes(data);
    return bytes_to_hex(result);
}

function sha512_base64 ( data ) {
    var result = sha512_bytes(data);
    return bytes_to_base64(result);
}

exports.SHA512 = {
    bytes: sha512_bytes,
    hex: sha512_hex,
    base64: sha512_base64
};
