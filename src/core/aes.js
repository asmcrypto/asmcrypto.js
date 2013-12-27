var _aes_block_size = 16,
    _aes_zero_iv = new Uint8Array(_aes_block_size);

function _aes_constructor ( options ) {
    options = options || {};
    options.heapSize = options.heapSize || 4096;

    if ( options.heapSize <= 0 || options.heapSize % 4096 )
        throw new IllegalArgumentError("heapSize must be a positive number and multiple of 4096");

    this.BLOCK_SIZE = _aes_block_size;
    this.KEY_SIZE   = 16; // TODO support of 192- and 256-bit keys

    this.heap = options.heap || new Uint8Array(options.heapSize);
    this.asm = options.asm || aes_asm( global, null, this.heap.buffer );
    this.pos = _aes_heap_start;
    this.len = 0;

    this.key = null;
    this.result = null;

    this.reset( options );
}

function _aes_reset ( options ) {
    options = options || {};

    this.result = null;
    this.pos = _aes_heap_start;
    this.len = 0;

    var asm = this.asm;

    var key = options.key;
    if ( key !== undefined ) {
        if ( key instanceof ArrayBuffer || key instanceof Uint8Array ) {
            key = new Uint8Array(key);
        }
        else if ( typeof key === 'string' ) {
            var str = key;
            key = new Uint8Array(str.length);
            for ( var i = 0; i < str.length; ++i )
                key[i] = str.charCodeAt(i);
        }
        else {
            throw new TypeError("unexpected key type");
        }

        if ( key.length !== this.KEY_SIZE )
            throw new IllegalArgumentError("illegal key size");

        this.key = key;

        asm.init_key_128.apply( asm, key );
    }

    return this;
}

function _aes_init_iv ( iv ) {
    var asm = this.asm;

    if ( iv !== undefined ) {
        if ( iv instanceof Uint8Array || iv instanceof ArrayBuffer ) {
            iv = new Uint8Array(iv);
        }
        else if ( typeof iv === 'string' ) {
            var str = iv;
            iv = new Uint8Array(str.length);
            for ( var i = 0; i < str.length; ++i )
                iv[i] = str.charCodeAt(i);
        }
        else {
            throw new TypeError("unexpected iv type");
        }

        if ( iv.length !== _aes_block_size )
            throw new IllegalArgumentError("illegal iv size");

        this.iv = iv;
        asm.init_state.apply( asm, iv );
    }
    else {
        this.iv = null;
        asm.init_state.apply( asm, _aes_zero_iv );
    }
}

function _aes_heap_write ( heap, hpos, data, dpos, dlen ) {
    var hlen = heap.byteLength - hpos,
        wlen = (hlen < dlen) ? hlen : dlen;

    if ( data instanceof ArrayBuffer || data instanceof Uint8Array ) {
        heap.set( new Uint8Array( (data.buffer||data), dpos, wlen ), hpos );
    }
    else if ( typeof data === 'string' ) {
        for ( var i = 0; i < wlen; ++i ) heap[ hpos + i ] = data.charCodeAt( dpos + i );
    }
    else {
        throw new TypeError("unexpected data type");
    }

    return wlen;
}
