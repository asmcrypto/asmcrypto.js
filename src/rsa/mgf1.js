function RSA_MGF1_generate( seed, length ) {
    seed = seed || '';
    length = length || 0;

    var hash_size = this.hash.HASH_SIZE;
    if ( length > (hash_size << 32) )
        throw new IllegalArgumentError("mask length too large");

    var mask = new Uint8Array(length),
        counter = new Uint8Array(4),
        chunks = Math.ceil(length/hash_length);
    for ( var i = 0; i < chunks; i++ ) {
        counter[0] = i >>> 24,
        counter[1] = (i >>> 16) & 255,
        counter[2] = (i >>> 8) & 255,
        counter[3] = i & 255;
        mask.set( this.hash.reset().process(seed).process(counter).finish().result, i * hash_size );
    }

    return mask;
}
