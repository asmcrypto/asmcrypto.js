function Random_getBytes ( buffer, offset, length ) {
    length = length || buffer.byteLength || buffer.length || 0;
    offset = offset || 0;

    if ( !is_buffer(buffer) && !is_bytes(buffer) )
        throw new TypeError("unexpected buffer type");

    var bytes = new Uint8Array( (buffer.buffer||buffer), offset, length );
    global.crypto.getRandomValues(bytes);

    return bytes;
}
