/**
 * Cipher feedback (CFB)
 */

function cfb_aes_constructor ( options ) {
    this.padding = false;
    this.mode = 'cfb';
    this.iv = null;

    _aes_constructor.call( this, options );
}

function cfb_aes_encrypt_constructor ( options ) {
    cfb_aes_constructor.call( this, options );
}

function cfb_aes_decrypt_constructor ( options ) {
    cfb_aes_constructor.call( this, options );
}

function cfb_aes_reset ( options ) {
    options = options || {};

    _aes_reset.call( this, options );

    _aes_init_iv.call( this, options.iv );

    return this;
}

function cfb_aes_encrypt_process ( data ) {
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

        wlen = asm.cfb_encrypt( pos, _aes_block_size * Math.floor( len / _aes_block_size ) );

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

function cfb_aes_encrypt_finish () {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var asm = this.asm,
        heap = this.heap,
        pos = this.pos,
        len = this.len;

    var result = new Uint8Array(len);

    if ( len > 0 ) {
        asm.cfb_encrypt( pos, len );
        result.set( heap.subarray( pos, pos + len ) );
    }

    this.result = result;
    this.pos = _aes_heap_start;
    this.len = 0;

    return this;
}

function cfb_aes_encrypt ( data ) {
    var result1 = cfb_aes_encrypt_process.call( this, data ).result,
        result2 = cfb_aes_encrypt_finish.call(this).result,
        result;

    result = new Uint8Array( result1.length + result2.length );
    result.set(result1);
    if ( result2.length > 0 ) result.set( result2, result1.length );
    this.result = result;

    return this;
}

function cfb_aes_decrypt_process ( data ) {
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

        wlen = asm.cfb_decrypt( pos, _aes_block_size * Math.floor( len / _aes_block_size ) );

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

function cfb_aes_decrypt_finish () {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var asm = this.asm,
        heap = this.heap,
        pos = this.pos,
        len = this.len;

    var result = new Uint8Array(len);

    if ( len > 0 ) {
        asm.cfb_decrypt( pos, len );
        result.set( heap.subarray( pos, pos + len ) );
    }

    this.result = result;
    this.pos = _aes_heap_start;
    this.len = 0;

    return this;
}

function cfb_aes_decrypt ( data ) {
    var result1 = cfb_aes_decrypt_process.call( this, data ).result,
        result2 = cfb_aes_decrypt_finish.call(this).result,
        result;

    result = new Uint8Array( result1.length + result2.length );
    result.set(result1);
    if ( result2.length > 0 ) result.set( result2, result1.length );
    this.result = result;

    return this;
}

var cfb_aes_encrypt_prototype = cfb_aes_encrypt_constructor.prototype;
cfb_aes_encrypt_prototype.reset = cfb_aes_reset;
cfb_aes_encrypt_prototype.process = cfb_aes_encrypt_process;
cfb_aes_encrypt_prototype.finish = cfb_aes_encrypt_finish;

var cfb_aes_decrypt_prototype = cfb_aes_decrypt_constructor.prototype;
cfb_aes_decrypt_prototype.reset = cfb_aes_reset;
cfb_aes_decrypt_prototype.process = cfb_aes_decrypt_process;
cfb_aes_decrypt_prototype.finish = cfb_aes_decrypt_finish;

var cfb_aes_prototype = cfb_aes_constructor.prototype;
cfb_aes_prototype.reset = cfb_aes_reset;
cfb_aes_prototype.encrypt = cfb_aes_encrypt;
cfb_aes_prototype.decrypt = cfb_aes_decrypt;
