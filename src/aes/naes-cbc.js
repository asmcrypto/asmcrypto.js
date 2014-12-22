/**
 * New Cipher-block chaining (CBC)
 */

function _naes_reset ( options ) {
    options = options || {};

    this.result = null;
    this.pos = 0;
    this.len = 0;

    var asm = this.asm;

    _naes_set_key.call( this, options.key );
    _naes_set_iv.call( this, options.iv );

    return this;
}

function _naes_set_key ( key ) {
    if ( key !== undefined ) {
        if ( is_buffer(key) || is_bytes(key) ) {
            key = new Uint8Array(key);
        }
        else if ( is_string(key) ) {
            key = string_to_bytes(key);
        }
        else {
            throw new TypeError("unexpected key type");
        }

        var keylen = key.length;
        if ( keylen !== 16 && keylen !== 24 && keylen !== 32 )
            throw new IllegalArgumentError("illegal key size");

        var keyview = new DataView( key.buffer, key.byteOffset, key.byteLength );
        this.asm.set_key(
            keylen >> 2,
            keyview.getUint32(0),
            keyview.getUint32(4),
            keyview.getUint32(8),
            keyview.getUint32(12),
            keylen > 16 ? keyview.getUint32(16) : 0,
            keylen > 16 ? keyview.getUint32(20) : 0,
            keylen > 24 ? keyview.getUint32(24) : 0,
            keylen > 24 ? keyview.getUint32(28) : 0
        );

        this.key = key;
    }
}

function _naes_set_iv ( iv ) {
    if ( iv !== undefined ) {
        if ( is_buffer(iv) || is_bytes(iv) ) {
            iv = new Uint8Array(iv);
        }
        else if ( is_string(iv) ) {
            iv = string_to_bytes(iv);
        }
        else {
            throw new TypeError("unexpected iv type");
        }

        if ( iv.length !== _aes_block_size )
            throw new IllegalArgumentError("illegal iv size");

        var ivview = new DataView( iv.buffer, iv.byteOffset, iv.byteLength );

        this.iv = iv;
        this.asm.set_state( ivview.getUint32(0), ivview.getUint32(4), ivview.getUint32(8), ivview.getUint32(12) );
    }
    else {
        this.iv = null;
        this.asm.set_state( 0, 0, 0, 0 );
    }
}

function cbc_naes_constructor ( options ) {
    this.padding = true;
    this.mode = 'cbc';
    this.iv = null;
    this.BLOCK_SIZE = _aes_block_size;

    options = options || {};

    this.heap = _heap_init( Uint8Array, options ).subarray( naes_asm.HEAP_DATA );
    this.asm = options.asm || naes_asm( global, null, this.heap.buffer );
    this.pos = 0;
    this.len = 0;

    this.key = null;
    this.result = null;

    this.reset( options );
}

function cbc_naes_encrypt_constructor ( options ) {
    cbc_naes_constructor.call( this, options );
}

function cbc_naes_decrypt_constructor ( options ) {
    cbc_naes_constructor.call( this, options );
}

function cbc_naes_reset ( options ) {
    options = options || {};

    _naes_reset.call( this, options );

    var padding = options.padding;
    if ( padding !== undefined ) {
        this.padding = !!padding;
    } else {
        this.padding = true;
    }

    return this;
}

function cbc_naes_encrypt_process ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    if ( !is_bytes(data) )
        throw new TypeError("data isn't of expected type");

    var ks = this.key.length >> 2,
        mode = naes_asm.CBC_ENC,
        hdata = naes_asm.HEAP_DATA,
        dpos = 0,
        dlen = data.length || 0,
        asm = this.asm,
        heap = this.heap,
        pos = this.pos,
        len = this.len,
        rpos = 0,
        rlen = _aes_block_size * Math.floor( ( len + dlen ) / _aes_block_size ),
        wlen = 0;

    var result = new Uint8Array(rlen);

    while ( dlen > 0 ) {
        wlen = _heap_write( heap, pos+len, data, dpos, dlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.cipher( ks, mode, hdata+pos, len );

        result.set( heap.subarray( pos, pos+wlen ), rpos );
        rpos += wlen;

        if ( wlen < len ) {
            pos += wlen;
            len -= wlen;
        } else {
            pos = 0;
            len = 0;
        }
    }

    this.result = result;
    this.pos = pos;
    this.len = len;

    return this;
}

function cbc_naes_encrypt_finish () {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var ks = this.key.length >> 2,
        mode = naes_asm.CBC_ENC,
        hdata = naes_asm.HEAP_DATA,
        asm = this.asm,
        heap = this.heap,
        padding = this.padding,
        pos = this.pos,
        len = this.len,
        rlen = _aes_block_size * Math.ceil( len / _aes_block_size );

    if ( len % _aes_block_size === 0 ) {
        if ( padding ) rlen += _aes_block_size;
    }
    else if ( !padding ) {
        throw new IllegalArgumentError("data length must be a multiple of " + _aes_block_size);
    }

    var result = new Uint8Array(rlen);

    if ( len < rlen ) {
        var plen = _aes_block_size - len % _aes_block_size;
        for ( var p = 0; p < plen; ++p ) heap[ pos + len + p ] = plen;
        len += plen;
    }

    if ( len > 0 ) {
        asm.cipher( ks, mode, hdata+pos, len );
        result.set( heap.subarray( pos, pos + len ) );
    }

    this.result = result;
    this.pos = 0;
    this.len = 0;

    return this;
}

function cbc_naes_encrypt ( data ) {
    var result1 = cbc_naes_encrypt_process.call( this, data ).result,
        result2 = cbc_naes_encrypt_finish.call(this).result,
        result;

    result = new Uint8Array( result1.length + result2.length );
    result.set(result1);
    if ( result2.length > 0 ) result.set( result2, result1.length );
    this.result = result;

    return this;
}

function cbc_naes_decrypt_process ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    if ( !is_bytes(data) )
        throw new TypeError("data isn't of expected type");

    var ks = this.key.length >> 2,
        mode = naes_asm.CBC_DEC,
        hdata = naes_asm.HEAP_DATA,
        dpos = 0,
        dlen = data.length || 0,
        asm = this.asm,
        heap = this.heap,
        padding = this.padding,
        pos = this.pos,
        len = this.len,
        rpos = 0,
        rlen = _aes_block_size * Math.floor( ( len + dlen ) / _aes_block_size ),
        wlen = 0;

    var result = new Uint8Array(rlen);

    while ( dlen > 0 ) {
        wlen = _heap_write( heap, pos+len, data, dpos, dlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.cipher( ks, mode, hdata+pos, len - ( padding && dlen === 0 && len % _aes_block_size === 0 ? _aes_block_size : 0 ) );

        result.set( heap.subarray( pos, pos+wlen ), rpos );
        rpos += wlen;

        if ( wlen < len ) {
            pos += wlen;
            len -= wlen;
        } else {
            pos = 0;
            len = 0;
        }
    }

    this.result = result.subarray( 0, rpos );
    this.pos = pos;
    this.len = len;

    return this;
}

function cbc_naes_decrypt_finish () {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var ks = this.key.length >> 2,
        mode = naes_asm.CBC_DEC,
        hdata = naes_asm.HEAP_DATA,
        asm = this.asm,
        heap = this.heap,
        padding = this.padding,
        pos = this.pos,
        len = this.len;

    if ( len === 0 ) {
        if ( !padding ) {
            this.result = new Uint8Array(0);
            this.pos = 0;
            this.len = 0;
            return this;
        }
        else {
            throw new IllegalStateError("padding not found");
        }
    }

    if ( len % _aes_block_size !== 0 )
        throw new IllegalArgumentError("data length must be a multiple of " + _aes_block_size);

    var result = new Uint8Array(len);

    if ( len > 0 ) {
        asm.cipher( ks, mode, hdata+pos, len );
        result.set( heap.subarray( pos, pos + len ) );
    }

    if ( padding ) {
        var pad = result[ len - 1 ];
        result = result.subarray( 0, len - pad );
    }

    this.result = result;
    this.pos = 0;
    this.len = 0;

    return this;
}

function cbc_naes_decrypt ( data ) {
    var result1 = cbc_naes_decrypt_process.call( this, data ).result,
        result2 = cbc_naes_decrypt_finish.call(this).result,
        result;

    result = new Uint8Array( result1.length + result2.length );
    result.set(result1);
    if ( result2.length > 0 ) result.set( result2, result1.length );
    this.result = result;

    return this;
}

var cbc_naes_encrypt_prototype = cbc_naes_encrypt_constructor.prototype;
cbc_naes_encrypt_prototype.reset = cbc_naes_reset;
cbc_naes_encrypt_prototype.process = cbc_naes_encrypt_process;
cbc_naes_encrypt_prototype.finish = cbc_naes_encrypt_finish;

var cbc_naes_decrypt_prototype = cbc_naes_decrypt_constructor.prototype;
cbc_naes_decrypt_prototype.reset = cbc_naes_reset;
cbc_naes_decrypt_prototype.process = cbc_naes_decrypt_process;
cbc_naes_decrypt_prototype.finish = cbc_naes_decrypt_finish;

var cbc_naes_prototype = cbc_naes_constructor.prototype;
cbc_naes_prototype.reset = cbc_naes_reset;
cbc_naes_prototype.encrypt = cbc_naes_encrypt;
cbc_naes_prototype.decrypt = cbc_naes_decrypt;
