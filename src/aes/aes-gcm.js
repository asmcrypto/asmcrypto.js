/**
 * Galois/Counter mode
 */

var _gcm_data_maxLength = 68719476704;  // 2^36 - 2^5

function gcm_aes_constructor ( options ) {
    this.padding    = false;
    this.mode       = 'gcm';

    this.tagSize    = _aes_block_size;

    this.adata      = null;
    this.iv         = null;
    this.counter    = 1;

    _aes_constructor.call( this, options );
}

function gcm_aes_encrypt_constructor ( options ) {
    gcm_aes_constructor.call( this, options );
}

function gcm_aes_decrypt_constructor ( options ) {
    gcm_aes_constructor.call( this, options );
}

function _gcm_ghash ( data ) {
    var asm = this.asm,
        heap = this.heap,
        dpos = data.byteOffset || 0,
        dlen = data.byteLength || data.length || 0,
        hpos = _aes_heap_start,
        hlen = 0,
        wlen = 0;

    while ( dlen > 0 ) {
        wlen = _aes_heap_write( heap, hpos+hlen, data, dpos, dlen ),
        hlen += wlen,
        dpos += wlen,
        dlen -= wlen;

        wlen = asm.gcm_ghash( hpos, hlen ),
        hpos += wlen,
        hlen -= wlen;

        if ( !hlen ) hpos = _aes_heap_start;
    }

    if ( hlen > 0 ) {
        while ( hlen < 16 ) heap[hpos|(hlen++)] = 0;
        asm.gcm_ghash( hpos, hlen );
    }
}

function gcm_aes_reset ( options ) {
    options = options || {};

    var asm = this.asm,
        heap = this.heap;

    _aes_reset.call( this, options );
    asm.gcm_init();

    var iv = options.iv;

    if ( iv !== undefined && iv !== null ) {
        if ( is_buffer(iv) || is_bytes(iv) ) {
            iv = new Uint8Array(iv);
        }
        else if ( is_string(iv) ) {
            iv = string_to_bytes(iv);
        }
        else {
            throw new TypeError("unexpected iv type");
        }

        var ivlen = iv.byteLength || iv.length || 0;
        if ( ivlen !== 12 ) {
            asm.init_state( 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 );

            _gcm_ghash.call( this, iv );

            heap[_aes_heap_start|0] = heap[_aes_heap_start|1] = heap[_aes_heap_start|2] = heap[_aes_heap_start|3] =
            heap[_aes_heap_start|4] = heap[_aes_heap_start|5] = heap[_aes_heap_start|6] = heap[_aes_heap_start|7] =
            heap[_aes_heap_start|8] = heap[_aes_heap_start|9] = heap[_aes_heap_start|10] = 0,
            heap[_aes_heap_start|11] = (ivlen >>> 29),
            heap[_aes_heap_start|12] = (ivlen >>> 21) & 255,
            heap[_aes_heap_start|13] = (ivlen >>> 13) & 255,
            heap[_aes_heap_start|14] = (ivlen >>> 5) & 255,
            heap[_aes_heap_start|15] = (ivlen << 3) & 255;
            asm.gcm_ghash( _aes_heap_start, _aes_block_size );

            asm.save_state( _aes_heap_start );

            this.iv = new Uint8Array( heap.subarray( _aes_heap_start, _aes_heap_start+_aes_block_size ) );
        }
        else {
            this.iv = new Uint8Array(16);
            this.iv.set(iv);
            this.iv[15] = 1;
        }
    }
    else {
        this.iv = new Uint8Array(16);
        this.iv[15] = 1;
    }

    var counter = options.counter;
    if ( counter !== undefined ) {
        if ( !is_number(counter) )
            throw new TypeError("counter must be a number");

        if ( counter < 1 || counter > 0xffffffff )
            throw new RangeError("counter must be a positive 32-bit integer");

        this.counter = counter;
    }
    else {
        this.counter = 1;
    }

    var tagSize = options.tagSize;
    if ( tagSize !== undefined ) {
        if ( !is_number(tagSize) )
            throw new TypeError("tagSize must be a number");

        if ( tagSize < 4 || tagSize > 16 )
            throw new IllegalArgumentError("illegal tagSize value");

        this.tagSize = tagSize;
    }
    else {
        this.tagSize = _aes_block_size;
    }

    asm.init_state( 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 );

    var adata = options.adata;
    if ( adata !== undefined && adata !== null ) {
        if ( is_buffer(adata) || is_bytes(adata) ) {
            adata = new Uint8Array(adata);
        }
        else if ( is_string(adata) ) {
            adata = string_to_bytes(adata);
        }
        else {
            throw new TypeError("unexpected adata type");
        }

        if ( adata.byteLength === 0 || adata.byteLength > _gcm_data_maxLength )
            throw new IllegalArgumentError("illegal adata length");

        _gcm_ghash.call( this, adata );

        this.adata = adata;
    }
    else {
        this.adata = null;
    }

    return this;
}

function gcm_aes_encrypt_process ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var asm = this.asm,
        heap = this.heap,
        iv  = this.iv,
        counter = this.counter,
        dpos = data.byteOffset || 0,
        dlen = data.byteLength || data.length || 0,
        hpos = this.pos,
        hlen = this.len,
        rpos = 0,
        rlen = _aes_block_size * Math.floor( ( hlen + dlen ) / _aes_block_size ),
        wlen = 0;

    var result = new Uint8Array(rlen);

    if ( ((counter-1)<<4) + hlen + dlen > _gcm_data_maxLength )
        throw new IllegalStateError("counter overflow");

    while ( dlen > 0 ) {
        wlen = _aes_heap_write( heap, hpos+hlen, data, dpos, dlen );
        hlen  += wlen;
        dpos += wlen;
        dlen -= wlen;

        var ivc = (iv[12] << 24) | (iv[13] << 16) | (iv[14] << 8) | iv[15];
        wlen = asm.gcm_encrypt( hpos, hlen & -15, iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], (ivc+counter)|0 );
        result.set( heap.subarray( hpos, hpos+wlen ), rpos );
        counter += (wlen>>>4);
        rpos += wlen,
        hpos += wlen,
        hlen -= wlen;

        if ( !hlen ) hpos = _aes_heap_start;
    }

    this.result = result;
    this.counter = counter;
    this.pos = hpos;
    this.len = hlen;

    return this;
}

function gcm_aes_encrypt_finish () {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var asm = this.asm,
        heap = this.heap,
        iv  = this.iv,
        adata = this.adata,
        counter = this.counter,
        tagSize = this.tagSize,
        pos = this.pos,
        hlen = this.len,
        wlen = 0;

    var result = new Uint8Array( hlen + tagSize );

    var ivc = (iv[12] << 24) | (iv[13] << 16) | (iv[14] << 8) | iv[15];

    if ( hlen > 0 ) {
        wlen = asm.gcm_encrypt( pos, hlen, iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], (ivc+counter)|0 );
        result.set( heap.subarray( pos, pos+wlen ) );
    }

    var alen = ( adata !== null ) ? adata.byteLength || adata.length || 0 : 0,
        clen = ( (counter-1) << 4) + wlen;
    heap[_aes_heap_start|0] = heap[_aes_heap_start|1] = heap[_aes_heap_start|2] = 0,
    heap[_aes_heap_start|3] = (alen >>> 29),
    heap[_aes_heap_start|4] = (alen >>> 21),
    heap[_aes_heap_start|5] = (alen >>> 13) & 255,
    heap[_aes_heap_start|6] = (alen >>> 5) & 255,
    heap[_aes_heap_start|7] = (alen << 3) & 255,
    heap[_aes_heap_start|8] = heap[_aes_heap_start|9] = heap[_aes_heap_start|10] = 0,
    heap[_aes_heap_start|11] = (clen >>> 29),
    heap[_aes_heap_start|12] = (clen >>> 21) & 255,
    heap[_aes_heap_start|13] = (clen >>> 13) & 255,
    heap[_aes_heap_start|14] = (clen >>> 5) & 255,
    heap[_aes_heap_start|15] = (clen << 3) & 255;
    asm.gcm_ghash( _aes_heap_start, _aes_block_size );
    asm.save_state( _aes_heap_start );

    asm.gcm_encrypt( _aes_heap_start, _aes_block_size, iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], ivc );
    result.set( heap.subarray( _aes_heap_start, _aes_heap_start+tagSize ), wlen );

    this.result = result;
    this.counter = 1;
    this.pos = _aes_heap_start;
    this.len = 0;

    return this;
}

function gcm_aes_encrypt ( data ) {
    var result1 = gcm_aes_encrypt_process.call( this, data ).result,
        result2 = gcm_aes_encrypt_finish.call(this).result;

    var result = new Uint8Array( result1.length + result2.length );
    if ( result1.length ) result.set( result1 );
    if ( result2.length ) result.set( result2, result1.length );
    this.result = result;

    return this;
}

function gcm_aes_decrypt_process ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var asm = this.asm,
        heap = this.heap,
        iv  = this.iv,
        counter = this.counter,
        tagSize = this.tagSize,
        dpos = data.byteOffset || 0,
        dlen = data.byteLength || data.length || 0,
        hpos = this.pos,
        hlen = this.len,
        rpos = 0,
        rlen = _aes_block_size * Math.floor( ( hlen + dlen - tagSize ) / _aes_block_size ),
        wlen = 0;

    var result = new Uint8Array(rlen);

    if ( ((counter-1)<<4) + hlen + dlen - tagSize > _gcm_data_maxLength )
        throw new IllegalStateError("counter overflow");

    while ( dlen > 0 ) {
        wlen = _aes_heap_write( heap, hpos+hlen, data, dpos, dlen ),
        hlen += wlen,
        dpos += wlen,
        dlen -= wlen;

        var ivc = (iv[12] << 24) | (iv[13] << 16) | (iv[14] << 8) | iv[15];
        wlen = asm.gcm_decrypt( hpos, Math.min( hlen, hlen + dlen - tagSize ) & -15, iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], (ivc+counter)|0 );
        result.set( heap.subarray( hpos, hpos+wlen ), rpos );
        counter += (wlen>>>4);
        rpos += wlen,
        hpos += wlen,
        hlen -= wlen;

        if ( !hlen ) hpos = _aes_heap_start;
    }

    this.result = result;
    this.counter = counter;
    this.pos = hpos;
    this.len = hlen;

    return this;
}

function gcm_aes_decrypt_finish () {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var asm = this.asm,
        heap = this.heap,
        iv  = this.iv,
        adata = this.adata,
        counter = this.counter,
        tagSize = this.tagSize,
        hpos = this.pos,
        hlen = this.len,
        rlen = hlen - tagSize,
        wlen = 0;

    var result = new Uint8Array(rlen),
        atag = new Uint8Array( heap.subarray( hpos+rlen, hpos+hlen ) );

    var ivc = (iv[12] << 24) | (iv[13] << 16) | (iv[14] << 8) | iv[15];

    if ( hlen > 0 ) {
        wlen = asm.gcm_decrypt( hpos, rlen, iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], (ivc+counter)|0 );
        result.set( heap.subarray( hpos, hpos+wlen ) );
    }

    var alen = ( adata !== null ) ? adata.byteLength || adata.length || 0 : 0,
        clen = ( (counter-1) << 4) + wlen;
    heap[_aes_heap_start|0] = heap[_aes_heap_start|1] = heap[_aes_heap_start|2] = 0,
    heap[_aes_heap_start|3] = (alen >>> 29),
    heap[_aes_heap_start|4] = (alen >>> 21),
    heap[_aes_heap_start|5] = (alen >>> 13) & 255,
    heap[_aes_heap_start|6] = (alen >>> 5) & 255,
    heap[_aes_heap_start|7] = (alen << 3) & 255,
    heap[_aes_heap_start|8] = heap[_aes_heap_start|9] = heap[_aes_heap_start|10] = 0,
    heap[_aes_heap_start|11] = (clen >>> 29),
    heap[_aes_heap_start|12] = (clen >>> 21) & 255,
    heap[_aes_heap_start|13] = (clen >>> 13) & 255,
    heap[_aes_heap_start|14] = (clen >>> 5) & 255,
    heap[_aes_heap_start|15] = (clen << 3) & 255;
    asm.gcm_ghash( _aes_heap_start, _aes_block_size );
    asm.save_state( _aes_heap_start );

    asm.gcm_encrypt( _aes_heap_start, _aes_block_size, iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], ivc );

    var acheck = 0;
    for ( var i = 0; i < tagSize; ++i ) acheck |= atag[i] ^ heap[_aes_heap_start|i];
    if ( acheck )
        throw new SecurityError("data integrity check failed");

    this.result = result;
    this.counter = 1;
    this.pos = _aes_heap_start;
    this.len = 0;

    return this;
}

function gcm_aes_decrypt ( data ) {
    var result1 = gcm_aes_decrypt_process.call( this, data ).result,
        result2 = gcm_aes_decrypt_finish.call( this ).result;

    var result = new Uint8Array( result1.length + result2.length );
    if ( result1.length ) result.set( result1 );
    if ( result2.length ) result.set( result2, result1.length );
    this.result = result;

    return this;
}

var gcm_aes_prototype = gcm_aes_constructor.prototype;
gcm_aes_prototype.reset = gcm_aes_reset;
gcm_aes_prototype.encrypt = gcm_aes_encrypt;
gcm_aes_prototype.decrypt = gcm_aes_decrypt;

var gcm_aes_encrypt_prototype = gcm_aes_encrypt_constructor.prototype;
gcm_aes_encrypt_prototype.reset = gcm_aes_reset;
gcm_aes_encrypt_prototype.process = gcm_aes_encrypt_process;
gcm_aes_encrypt_prototype.finish = gcm_aes_encrypt_finish;

var gcm_aes_decrypt_prototype = gcm_aes_decrypt_constructor.prototype;
gcm_aes_decrypt_prototype.reset = gcm_aes_reset;
gcm_aes_decrypt_prototype.process = gcm_aes_decrypt_process;
gcm_aes_decrypt_prototype.finish = gcm_aes_decrypt_finish;
