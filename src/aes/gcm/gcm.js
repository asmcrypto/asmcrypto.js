/**
 * Galois/Counter mode
 */

var _AES_GCM_data_maxLength = 68719476704;  // 2^36 - 2^5

function _gcm_mac_process ( data ) {
    var heap = this.heap,
        asm  = this.asm,
        dpos = 0,
        dlen = data.length || 0,
        wlen = 0;

    while ( dlen > 0 ) {
        wlen = _heap_write( heap, 0, data, dpos, dlen );
        dpos += wlen;
        dlen -= wlen;

        while ( wlen & 15 ) heap[ wlen++ ] = 0;

        asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA, wlen );
    }
}

function AES_GCM ( options ) {
    this.nonce      = null;
    this.adata      = null;
    this.iv         = null;
    this.counter    = 1;
    this.tagSize    = 16;

    AES.call( this, options );

    this.mode       = 'GCM';
}

function AES_GCM_Encrypt ( options ) {
    AES_GCM.call( this, options );
}

function AES_GCM_Decrypt ( options ) {
    AES_GCM.call( this, options );
}

function AES_GCM_reset ( options ) {
    options = options || {};

    AES_reset.call( this, options );

    var asm = this.asm,
        heap = this.heap;

    asm.gcm_init();

    var tagSize = options.tagSize;
    if ( tagSize !== undefined ) {
        if ( !is_number(tagSize) )
            throw new TypeError("tagSize must be a number");

        if ( tagSize < 4 || tagSize > 16 )
            throw new IllegalArgumentError("illegal tagSize value");

        this.tagSize = tagSize;
    }
    else {
        this.tagSize = 16;
    }

    var nonce = options.nonce;
    if ( nonce !== undefined ) {
        if ( is_bytes(nonce) || is_buffer(nonce) ) {
            nonce = new Uint8Array(nonce);
        }
        else if ( is_string(nonce) ) {
            nonce = string_to_bytes(nonce);
        }
        else {
            throw new TypeError("unexpected nonce type");
        }

        this.nonce = nonce;

        var noncelen = nonce.length || 0,
            noncebuf = new Uint8Array(16);
        if ( noncelen !== 12 ) {
            asm.set_iv();
            _gcm_mac_process.call( this, nonce );

            heap[0] = heap[1] = heap[2] = heap[3] = heap[4] = heap[5] = heap[6] = heap[7] = heap[8] = heap[9] = heap[10] = 0,
            heap[11] = noncelen>>>29,
            heap[12] = noncelen>>>21&255,
            heap[13] = noncelen>>>13&255,
            heap[14] = noncelen>>>5&255,
            heap[15] = noncelen<<3&255;
            asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA, 16 );

            asm.get_iv( AES_asm.HEAP_DATA );

            noncebuf.set( heap.subarray( 0, 16 ) );
        }
        else {
            noncebuf.set(nonce);
            noncebuf[15] = 1;
        }

        var nonceview = new DataView( noncebuf.buffer );
        this.gamma0 = nonceview.getUint32(12);

        asm.set_nonce( nonceview.getUint32(0), nonceview.getUint32(4), nonceview.getUint32(8), 0 );
        asm.set_mask( 0, 0, 0, 0xffffffff );
    }
    else {
        throw new Error("nonce is required");
    }

    var adata = options.adata;
    if ( adata !== undefined && adata !== null ) {
        if ( is_bytes(adata) || is_buffer(adata) ) {
            adata = new Uint8Array(adata);
        }
        else if ( is_string(adata) ) {
            adata = string_to_bytes(adata);
        }
        else {
            throw new TypeError("unexpected adata type");
        }

        if ( adata.length > _AES_GCM_data_maxLength )
            throw new IllegalArgumentError("illegal adata length");

        if ( adata.length ) {
            this.adata = adata;
            asm.set_iv();
            _gcm_mac_process.call( this, adata );
        }
        else {
            this.adata = null;
        }
    }
    else {
        this.adata = null;
    }

    var counter = options.counter;
    if ( counter !== undefined ) {
        if ( !is_number(counter) )
            throw new TypeError("counter must be a number");

        if ( counter < 1 || counter > 0xffffffff )
            throw new RangeError("counter must be a positive 32-bit integer");

        this.counter = counter;
        asm.set_counter( 0, 0, 0, this.gamma0+counter|0 );
    }
    else {
        this.counter = 1;
        asm.set_counter( 0, 0, 0, this.gamma0+1|0 );
    }

    var iv = options.iv;
    if ( iv !== undefined ) {
        if ( !is_number(counter) )
            throw new TypeError("counter must be a number");

        this.iv = iv;

        AES_set_iv.call( this, iv );
    }

    return this;
}

function AES_GCM_Encrypt_process ( data ) {
    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    if ( !is_bytes(data) )
        throw new TypeError("data isn't of expected type");

    var dpos = 0,
        dlen = data.length || 0,
        asm = this.asm,
        heap = this.heap,
        counter = this.counter,
        pos = this.pos,
        len = this.len,
        rpos = 0,
        rlen = ( len + dlen ) & -16,
        wlen = 0;

    if ( ((counter-1)<<4) + len + dlen > _AES_GCM_data_maxLength )
        throw new RangeError("counter overflow");

    var result = new Uint8Array(rlen);

    while ( dlen > 0 ) {
        wlen = _heap_write( heap, pos+len, data, dpos, dlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.cipher( AES_asm.ENC.CTR, AES_asm.HEAP_DATA + pos, len );
        wlen = asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, wlen );

        if ( wlen ) result.set( heap.subarray( pos, pos + wlen ), rpos );
        counter += (wlen>>>4);
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
    this.counter = counter;
    this.pos = pos;
    this.len = len;

    return this;
}

function AES_GCM_Encrypt_finish () {
    var asm = this.asm,
        heap = this.heap,
        counter = this.counter,
        tagSize = this.tagSize,
        adata = this.adata,
        pos = this.pos,
        len = this.len;

    var result = new Uint8Array( len + tagSize );

    asm.cipher( AES_asm.ENC.CTR, AES_asm.HEAP_DATA + pos, (len + 15) & -16 );
    if ( len ) result.set( heap.subarray( pos, pos + len ) );

    for ( var i = len; i & 15; i++ ) heap[ pos + i ] = 0;
    asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, i );

    var alen = ( adata !== null ) ? adata.length : 0,
        clen = ( (counter-1) << 4) + len;
    heap[0] = heap[1] = heap[2] = 0,
    heap[3] = alen>>>29,
    heap[4] = alen>>>21,
    heap[5] = alen>>>13&255,
    heap[6] = alen>>>5&255,
    heap[7] = alen<<3&255,
    heap[8] = heap[9] = heap[10] = 0,
    heap[11] = clen>>>29,
    heap[12] = clen>>>21&255,
    heap[13] = clen>>>13&255,
    heap[14] = clen>>>5&255,
    heap[15] = clen<<3&255;
    asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA, 16 );
    asm.get_iv( AES_asm.HEAP_DATA );

    asm.set_counter( 0, 0, 0, this.gamma0 );
    asm.cipher( AES_asm.ENC.CTR, AES_asm.HEAP_DATA, 16 );
    result.set( heap.subarray( 0, tagSize ), len );

    this.result = result;
    this.counter = 1;
    this.pos = 0;
    this.len = 0;

    return this;
}

function AES_GCM_encrypt ( data ) {
    var result1 = AES_GCM_Encrypt_process.call( this, data ).result,
        result2 = AES_GCM_Encrypt_finish.call(this).result;

    var result = new Uint8Array( result1.length + result2.length );
    if ( result1.length ) result.set( result1 );
    if ( result2.length ) result.set( result2, result1.length );
    this.result = result;

    return this;
}

function AES_GCM_Decrypt_process ( data ) {
    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    if ( !is_bytes(data) )
        throw new TypeError("data isn't of expected type");

    var dpos = 0,
        dlen = data.length || 0,
        asm = this.asm,
        heap = this.heap,
        counter = this.counter,
        tagSize = this.tagSize,
        pos = this.pos,
        len = this.len,
        rpos = 0,
        rlen = len + dlen > tagSize ? ( len + dlen - tagSize ) & -16 : 0,
        tlen = len + dlen - rlen,
        wlen = 0;

    if ( ((counter-1)<<4) + len + dlen > _AES_GCM_data_maxLength )
        throw new RangeError("counter overflow");

    var result = new Uint8Array(rlen);

    while ( dlen > tlen ) {
        wlen = _heap_write( heap, pos+len, data, dpos, dlen-tlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, wlen );
        wlen = asm.cipher( AES_asm.DEC.CTR, AES_asm.HEAP_DATA + pos, wlen );

        if ( wlen ) result.set( heap.subarray( pos, pos+wlen ), rpos );
        counter += (wlen>>>4);
        rpos += wlen;

        pos = 0;
        len = 0;
    }

    if ( dlen > 0 ) {
        len += _heap_write( heap, 0, data, dpos, dlen );
    }

    this.result = result;
    this.counter = counter;
    this.pos = pos;
    this.len = len;

    return this;
}

function AES_GCM_Decrypt_finish () {
    var asm = this.asm,
        heap = this.heap,
        tagSize = this.tagSize,
        adata = this.adata,
        counter = this.counter,
        pos = this.pos,
        len = this.len,
        rlen = len - tagSize,
        wlen = 0;

    if ( len < tagSize )
        throw new IllegalStateError("authentication tag not found");

    var result = new Uint8Array(rlen),
        atag = new Uint8Array( heap.subarray( pos+rlen, pos+len ) );

    for ( var i = rlen; i & 15; i++ ) heap[ pos + i ] = 0;

    wlen = asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA + pos, i );
    wlen = asm.cipher( AES_asm.DEC.CTR, AES_asm.HEAP_DATA + pos, i );
    if ( rlen ) result.set( heap.subarray( pos, pos+rlen ) );

    var alen = ( adata !== null ) ? adata.length : 0,
        clen = ( (counter-1) << 4) + len - tagSize;
    heap[0] = heap[1] = heap[2] = 0,
    heap[3] = alen>>>29,
    heap[4] = alen>>>21,
    heap[5] = alen>>>13&255,
    heap[6] = alen>>>5&255,
    heap[7] = alen<<3&255,
    heap[8] = heap[9] = heap[10] = 0,
    heap[11] = clen>>>29,
    heap[12] = clen>>>21&255,
    heap[13] = clen>>>13&255,
    heap[14] = clen>>>5&255,
    heap[15] = clen<<3&255;
    asm.mac( AES_asm.MAC.GCM, AES_asm.HEAP_DATA, 16 );
    asm.get_iv( AES_asm.HEAP_DATA );

    asm.set_counter( 0, 0, 0, this.gamma0 );
    asm.cipher( AES_asm.ENC.CTR, AES_asm.HEAP_DATA, 16 );

    var acheck = 0;
    for ( var i = 0; i < tagSize; ++i ) acheck |= atag[i] ^ heap[i];
    if ( acheck )
        throw new SecurityError("data integrity check failed");

    this.result = result;
    this.counter = 1;
    this.pos = 0;
    this.len = 0;

    return this;
}

function AES_GCM_decrypt ( data ) {
    var result1 = AES_GCM_Decrypt_process.call( this, data ).result,
        result2 = AES_GCM_Decrypt_finish.call( this ).result;

    var result = new Uint8Array( result1.length + result2.length );
    if ( result1.length ) result.set( result1 );
    if ( result2.length ) result.set( result2, result1.length );
    this.result = result;

    return this;
}

var AES_GCM_prototype = AES_GCM.prototype;
AES_GCM_prototype.BLOCK_SIZE = 16;
AES_GCM_prototype.reset = AES_GCM_reset;
AES_GCM_prototype.encrypt = AES_GCM_encrypt;
AES_GCM_prototype.decrypt = AES_GCM_decrypt;

var AES_GCM_Encrypt_prototype = AES_GCM_Encrypt.prototype;
AES_GCM_Encrypt_prototype.BLOCK_SIZE = 16;
AES_GCM_Encrypt_prototype.reset = AES_GCM_reset;
AES_GCM_Encrypt_prototype.process = AES_GCM_Encrypt_process;
AES_GCM_Encrypt_prototype.finish = AES_GCM_Encrypt_finish;

var AES_GCM_Decrypt_prototype = AES_GCM_Decrypt.prototype;
AES_GCM_Decrypt_prototype.BLOCK_SIZE = 16;
AES_GCM_Decrypt_prototype.reset = AES_GCM_reset;
AES_GCM_Decrypt_prototype.process = AES_GCM_Decrypt_process;
AES_GCM_Decrypt_prototype.finish = AES_GCM_Decrypt_finish;
