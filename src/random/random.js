function Random_getBytes ( buffer ) {
    if ( !is_buffer(buffer) && !is_bytes(buffer) )
        throw new TypeError("unexpected buffer type");

    var bytes = new Uint8Array( (buffer.buffer||buffer), buffer.byteOffset||0, buffer.byteLength||buffer.length );
    global.crypto.getRandomValues(bytes);

    return bytes;
}
