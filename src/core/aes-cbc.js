/**
 * Cipher-block chaining (CBC)
 */

function cbc_aes_constructor ( options ) {
    this.padding = true;
    this.mode = 'cbc';
    this.iv = null;

    _aes_constructor.call( this, options );
}

function cbc_aes_encrypt_constructor ( options ) {
    cbc_aes_constructor.call( this, options );
}

function cbc_aes_decrypt_constructor ( options ) {
    cbc_aes_constructor.call( this, options );
}

function cbc_aes_reset ( options ) {
    options = options || {};

    _aes_reset.call( this, options );

    var padding = options.padding;
    if ( padding !== undefined ) {
        this.padding = !!padding;
    } else {
        this.padding = true;
    }

    _aes_init_iv.call( this, options.iv );

    return this;
}

function cbc_aes_encrypt_process ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var dpos = data.byteOffset || 0,
        dlen = data.byteLength || data.length || 0,
        asm = this.asm,
        heap = this.heap,
        pos = this.pos,
        len = this.len,
        rpos = 0,
        rlen = _aes_block_size * Math.floor( ( len + dlen ) / _aes_block_size ),
        wlen = 0;

    var result = new Uint8Array(rlen);

    while ( dlen > 0 ) {
        wlen = _aes_heap_write( heap, pos+len, data, dpos, dlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.cbc_encrypt( pos, len );

        result.set( heap.subarray( pos, pos+wlen ), rpos );
        rpos += wlen;

        if ( wlen < len ) {
            pos += wlen;
            len -= wlen;
        } else {
            pos = _aes_heap_start;
            len = 0;
        }
    }

    this.result = result;
    this.pos = pos;
    this.len = len;

    return this;
}

function cbc_aes_encrypt_finish () {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var asm = this.asm,
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

    asm.cbc_encrypt( pos, len );

    result.set( heap.subarray( pos, pos + len ) );

    this.result = result;
    this.pos = _aes_heap_start;
    this.len = 0;

    return this;
}

function cbc_aes_encrypt ( data ) {
    var result1 = cbc_aes_encrypt_process.call( this, data ).result,
        result2 = cbc_aes_encrypt_finish.call(this).result,
        result;

    result = new Uint8Array( result1.length + result2.length );
    result.set(result1);
    result.set( result2, result1.length );
    this.result = result;

    return this;
}

function cbc_aes_decrypt_process ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var dpos = data.byteOffset || 0,
        dlen = data.byteLength || data.length || 0,
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
        wlen = _aes_heap_write( heap, pos+len, data, dpos, dlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.cbc_decrypt( pos, len - ( padding && dlen === 0 && len % _aes_block_size === 0 ? _aes_block_size : 0 ) );

        result.set( heap.subarray( pos, pos+wlen ), rpos );
        rpos += wlen;

        if ( wlen < len ) {
            pos += wlen;
            len -= wlen;
        } else {
            pos = _aes_heap_start;
            len = 0;
        }
    }

    this.result = result.subarray( 0, rpos );
    this.pos = pos;
    this.len = len;

    return this;
}

function cbc_aes_decrypt_finish () {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var asm = this.asm,
        heap = this.heap,
        padding = this.padding,
        pos = this.pos,
        len = this.len;

    if ( len === 0 ) {
        if ( !padding ) {
            this.result = new Uint8Array(0);
            this.pos = _aes_heap_start;
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

    asm.cbc_decrypt( pos, len );
    result.set( heap.subarray( pos, pos + len ) );

    if ( padding ) {
        var pad = result[ len - 1 ];
        result = result.subarray( 0, len - pad );
    }

    this.result = result;
    this.pos = _aes_heap_start;
    this.len = 0;

    return this;
}

function cbc_aes_decrypt ( data ) {
    var result1 = cbc_aes_decrypt_process.call( this, data ).result,
        result2 = cbc_aes_decrypt_finish.call(this).result,
        result;

    result = new Uint8Array( result1.length + result2.length );
    result.set(result1);
    result.set( result2, result1.length );
    this.result = result;

    return this;
}

var cbc_aes_encrypt_prototype = cbc_aes_encrypt_constructor.prototype;
cbc_aes_encrypt_prototype.reset = cbc_aes_reset;
cbc_aes_encrypt_prototype.process = cbc_aes_encrypt_process;
cbc_aes_encrypt_prototype.finish = cbc_aes_encrypt_finish;

var cbc_aes_decrypt_prototype = cbc_aes_decrypt_constructor.prototype;
cbc_aes_decrypt_prototype.reset = cbc_aes_reset;
cbc_aes_decrypt_prototype.process = cbc_aes_decrypt_process;
cbc_aes_decrypt_prototype.finish = cbc_aes_decrypt_finish;

var cbc_aes_prototype = cbc_aes_constructor.prototype;
cbc_aes_prototype.reset = cbc_aes_reset;
cbc_aes_prototype.encrypt = cbc_aes_encrypt;
cbc_aes_prototype.decrypt = cbc_aes_decrypt;
