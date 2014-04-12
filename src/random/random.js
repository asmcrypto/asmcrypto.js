var _global_crypto = global.crypto;

function Random_getBytes ( buffer ) {
    if ( !is_buffer(buffer) && !is_bytes(buffer) )
        throw new TypeError("unexpected buffer type");

    var bytes = new Uint8Array( (buffer.buffer||buffer), buffer.byteOffset||0, buffer.byteLength||buffer.length );

    if ( _global_crypto ) {
        _global_crypto.getRandomValues(bytes);
    }
    else {
        var random = global.Math.random;
        for ( var i = 0; i < bytes.length; i++ ) {
            bytes[i] = random() * 256 | 0;
        }
    }

    return bytes;
}
