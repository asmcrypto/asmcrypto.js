var _global_crypto = global.crypto;

var _global_math_random = global.Math.random;

var _isaac_rand = ISAAC.rand;

function Random_getValues ( buffer ) {
    if ( !is_buffer(buffer) && !is_typed_array(buffer) )
        throw new TypeError("unexpected buffer type");

    var blen = buffer.byteLength || buffer.length,
        bytes = new Uint8Array( (buffer.buffer||buffer), buffer.byteOffset||0, blen ),
        i, r;

    if ( _global_crypto ) {
        _global_crypto.getRandomValues(bytes);
    }
    else {
        for ( i = 0; i < blen; i++ ) {
            if ( !(i & 3) ) r = _global_math_random() * 0x100000000 | 0;
            bytes[i] = r;
            r >>>= 8;
        }
    }

    for ( i = 0; i < blen; i++ ) {
        if ( !(i & 3) ) r = _isaac_rand();
        bytes[i] ^= r;
        r >>>= 8;
    }
}
