function RSA_OAEP ( options ) {
    options = options || {};

    if ( !options.hash )
        throw new SyntaxError("option 'hash' is required");

    if ( !options.hash.HASH_SIZE )
        throw new SyntaxError("option 'hash' supplied doesn't seem to be a valid hash function");

    this.hash = options.hash;

    this.label = null;

    this.reset(options);
}

function RSA_OAEP_reset ( options ) {
    options = options || {};

    var label = options.label;
    if ( label !== undefined ) {
        if ( is_buffer(label) || is_bytes(label) ) {
            label = new Uint8Array(label);
        }
        else if ( is_string(label) ) {
            var str = label;
            label = new Uint8Array(str.length);
            for ( var i = 0; i < str.length; i++ )
                label[i] = str.charCodeAt(i);
        }
        else {
            throw new TypeError("unexpected label type");
        }

        this.label = ( label.length > 0 ) ? label : null;
    }
    else {
        this.label = null;
    }

    RSA_reset.call( this, options );
}

function RSA_OAEP_encrypt ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var key_size = Math.ceil( this.key[0].bitLength / 8 ),
        hash_size = this.hash.HASH_SIZE,
        data_length = data.byteLength || data.length || 0,
        ps_length = key_size - data_length - 2*hash_size - 2;

    if ( data_length > key_size - 2*this.hash.HASH_SIZE - 2 )
        throw new IllegalArgumentError("data too large");

    var message = new Uint8Array(key_size),
        seed = message.subarray( 1, hash_size + 1 ),
        data_block = message.subarray( hash_size + 1 );

    if ( is_bytes(data) ) {
        data_block.set( data, hash_size + ps_length + 1 );
    }
    else if ( is_buffer(data) ) {
        data_block.set( new Uint8Array(data), hash_size + ps_length + 1 );
    }
    else if ( is_string(data) ) {
        for ( var i = 0; i < data.length; i++ )
            data_block[ key_size + ps_length + 1 + i ] = data.charCodeAt(i);
    }
    else {
        throw new TypeError("unexpected data type");
    }

    data_block.set( this.hash.reset().process( this.label || '' ).finish().result, 0 );
    data_block[ hash_size + ps_length ] = 1;

    Random_getBytes.call( this, seed );

    var data_block_mask = RSA_MGF1_generate.call( this, seed, data_block.length );
    for ( var i = 0; i < data_block.length; i++ )
        data_block[i] ^= data_block_mask[i];

    var seed_mask = RSA_MGF1_generate.call( this, data_block, seed.length );
    for ( var i = 0; i < seed.length; i++ )
        seed[i] ^= seed_mask[i];

    RSA_encrypt.call( this, message );

    return this;
}

function RSA_OAEP_decrypt ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var key_size = Math.ceil( this.key[0].bitLength / 8 ),
        hash_size = this.hash.HASH_SIZE,
        data_length = data.byteLength || data.length || 0;

    if ( data_length !== key_size )
        throw new IllegalArgumentError("bad data");

    RSA_decrypt.call( this, data );

    var z = this.result[0],
        seed = this.result.subarray( 1, hash_size + 1 ),
        data_block = this.result.subarray( hash_size + 1 );

    if ( z !== 0 )
        throw new SecurityError("decryption failed");

    var seed_mask = RSA_MGF1_generate.call( this, data_block, seed.length );
    for ( var i = 0; i < seed.length; i++ )
        seed[i] ^= seed_mask[i];

    var data_block_mask = RSA_MGF1_generate.call( this, seed, data_block.length );
    for ( var i = 0; i < data_block.length; i++ )
        data_block[i] ^= data_block_mask[i];

    var lhash = this.hash.reset().process( this.label || '' ).finish().result;
    for ( var i = 0; i < hash_size; i++ ) {
        if ( lhash[i] !== data_block[i] )
            throw new SecurityError("decryption failed");
    }

    var ps_end = hash_size;
    for ( ; ps_end < data_block.length; ps_end++ ) {
        var psz = data_block[ps_end];
        if ( psz === 1 )
            break;
        if ( psz !== 0 )
            throw new SecurityError("decryption failed");
    }
    if ( ps_end === data_block.length )
        throw new SecurityError("decryption failed");

    this.result = data_block.subarray( ps_end + 1 );

    return this;
}

function RSA_MGF1_generate( seed, length ) {
    seed = seed || '';
    length = length || 0;

    var hash_size = this.hash.HASH_SIZE;
//    if ( length > (hash_size * 0x100000000) )
//        throw new IllegalArgumentError("mask length too large");

    var mask = new Uint8Array(length),
        counter = new Uint8Array(4),
        chunks = Math.ceil( length / hash_size );
    for ( var i = 0; i < chunks; i++ ) {
        counter[0] = i >>> 24,
        counter[1] = (i >>> 16) & 255,
        counter[2] = (i >>> 8) & 255,
        counter[3] = i & 255;

        var submask = mask.subarray( i * hash_size );

        var chunk = this.hash.reset().process(seed).process(counter).finish().result;
        if ( chunk.length > submask.length ) chunk = chunk.subarray( 0, submask.length );

        submask.set(chunk);
    }

    return mask;
}

var RSA_OAEP_prototype = RSA_OAEP.prototype;
RSA_OAEP_prototype.reset = RSA_OAEP_reset;
RSA_OAEP_prototype.encrypt = RSA_OAEP_encrypt;
RSA_OAEP_prototype.decrypt = RSA_OAEP_decrypt;
