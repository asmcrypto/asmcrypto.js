/**
 * Counter with CBC-MAC (CCM)
 *
 * Due to JS limitations (counter is 32-bit unsigned) maximum encrypted message length
 * is limited to ~64 GiB ( 2^36 - 16 ) per `nonce`-`key` pair. That also limits `lengthSize` parameter
 * maximum value to 5 (not 8 as described in RFC3610).
 *
 * Additional authenticated data `adata` maximum length is limited to 65279 bytes ( 2^16 - 2^8 ),
 * wich is considered enough for the wast majority of use-cases.
 *
 * And one more important thing: in case of progressive ciphering of a data stream (in other
 * words when data can't be held in-memory at a whole and are ciphered chunk-by-chunk)
 * you have to know the `dataLength` in advance and pass that value to the cipher options.
 */

function _cbc_mac_process ( data ) {
    var dpos = data.byteOffset || 0,
        dlen = data.byteLength || data.length || 0,
        wlen = 0;

    while ( dlen > 0 ) {
        wlen = _aes_heap_write( this.heap, _aes_heap_start, data, dpos, dlen );
        this.asm.cbc_mac( _aes_heap_start, wlen, -1 );
        dpos += wlen;
        dlen -= wlen;
    }
}

var _ccm_adata_maxLength = 65279,       // 2^16 - 2^8
    _ccm_data_maxLength = 68719476720;  // 2^36 - 2^4

function ccm_aes_constructor ( options ) {
    this.padding    = false;
    this.mode       = 'ccm';

    this.tagSize    = _aes_block_size;
    this.lengthSize = 4;

    this.nonce      = null;

    this.adata      = null;

    this.iv         = null;
    this.dataLength = -1;
    this.dataLeft   = -1;

    this.counter    = 1;

    _aes_constructor.call( this, options );
}

function ccm_aes_encrypt_constructor ( options ) {
    ccm_aes_constructor.call( this, options );
}

function ccm_aes_decrypt_constructor ( options ) {
    ccm_aes_constructor.call( this, options );
}

function _ccm_calculate_iv () {
    var nonce = this.nonce,
        adata = this.adata,
        tagSize = this.tagSize,
        lengthSize = this.lengthSize,
        dataLength = this.dataLength;

    var data = new Uint8Array( _aes_block_size + ( adata ? 2 + adata.byteLength : 0 ) );

    // B0: flags(adata?, M', L'), nonce, len(data)
    data[0] = ( adata ? 64 : 0 ) | ( (tagSize-2)<<2 ) | ( lengthSize-1 );
    data.set( nonce, 1 );
    if (lengthSize > 4) data[11] = ( ( dataLength - (dataLength>>>0) ) / 4294967296 )&15;
    if (lengthSize > 3) data[12] = dataLength>>>24;
    if (lengthSize > 2) data[13] = dataLength>>>16&255;
    data[14] = dataLength>>>8&255;
    data[15] = dataLength&255;

    // B*: len(adata), adata
    if ( adata ) {
        data[16] = adata.byteLength>>>8&255;
        data[17] = adata.byteLength&255;
        data.set( adata, 18 );
    }

    _cbc_mac_process.call( this, data );
    this.asm.save_state( _aes_heap_start );

    this.iv = new Uint8Array( this.heap.subarray( _aes_heap_start, _aes_heap_start + _aes_block_size ) );
}

function ccm_aes_reset ( options ) {
    options = options || {};

    _aes_reset.call( this, options );

    _aes_init_iv.call( this, options.iv );

    var tagSize = options.tagSize;
    if ( tagSize !== undefined ) {
        if ( typeof tagSize !== 'number' )
            throw new TypeError("tagSize must be a number");

        if ( tagSize < 4 || tagSize > 16 || tagSize & 1 )
            throw new IllegalArgumentError("illegal tagSize value");

        this.tagSize = tagSize;
    }
    else {
        this.tagSize = _aes_block_size;
    }

    var lengthSize = options.lengthSize,
        nonce = options.nonce;
    if ( nonce !== undefined ) {
        if ( nonce instanceof Uint8Array || nonce instanceof ArrayBuffer ) {
            nonce = new Uint8Array(nonce);
        }
        else if ( typeof nonce === 'string' ) {
            var str = nonce;
            nonce = new Uint8Array(str.length);
            for ( var i = 0; i < str.length; ++i )
                nonce[i] = str.charCodeAt(i);
        }
        else {
            throw new TypeError("unexpected nonce type");
        }

        if ( nonce.length < 10 || nonce.length > 13 )
            throw new IllegalArgumentError("illegal nonce length");

        lengthSize = lengthSize || ( 15 - nonce.length );

        this.nonce = nonce;
    }
    else {
        this.nonce = null;
    }

    if ( lengthSize !== undefined ) {
        if ( typeof lengthSize !== 'number' )
            throw new TypeError("lengthSize must be a number");

        if ( lengthSize < 2 || lengthSize > 5 || nonce.length + lengthSize !== 15 )
            throw new IllegalArgumentError("illegal lengthSize value");

        this.lengthSize = lengthSize;
    }
    else {
        this.lengthSize = lengthSize = 4;
    }

    var iv = this.iv;

    var counter = options.counter;
    if ( counter !== undefined ) {
        if ( iv === null )
            throw new IllegalStateError("iv is also required");

        if ( typeof counter !== 'number' )
            throw new TypeError("counter must be a number");

        this.counter = counter;
    }
    else {
        this.counter = 1;
    }

    var dataLength = options.dataLength;
    if ( dataLength !== undefined ) {
        if ( typeof dataLength !== 'number' )
            throw new TypeError("dataLength must be a number");

        if ( dataLength < 0 || dataLength > _ccm_data_maxLength || dataLength > ( Math.pow( 2, 8*lengthSize ) - 1 ) )
            throw new IllegalArgumentError("illegal dataLength value");

        this.dataLength = dataLength;

        var dataLeft = options.dataLeft || dataLength;

        if ( typeof dataLeft !== 'number' )
            throw new TypeError("dataLeft must be a number");

        if ( dataLeft < 0 || dataLeft > dataLength )
            throw new IllegalArgumentError("illegal dataLeft value");

        this.dataLeft = dataLeft;
    }
    else {
        this.dataLength = dataLength = -1;
        this.dataLeft   = dataLength;
    }

    var adata = options.adata;
    if ( adata !== undefined ) {
        if ( iv !== null )
            throw new IllegalStateError("you must specify either adata or iv, not both");

        if ( adata instanceof ArrayBuffer || adata instanceof Uint8Array ) {
            adata = new Uint8Array(adata);
        }
        else if ( typeof adata === 'string' ) {
            var str = adata;
            adata = new Uint8Array(str.length);
            for ( var i = 0; i < str.length; ++i )
                adata[i] = str.charCodeAt(i);
        }
        else {
            throw new TypeError("unexpected adata type");
        }

        if ( adata.byteLength === 0 || adata.byteLength > _ccm_adata_maxLength )
            throw new IllegalArgumentError("illegal adata length");

        this.adata = adata;
        this.counter = 1;
    }
    else {
        this.adata = adata = null;
    }

    if ( dataLength !== -1 )
        _ccm_calculate_iv.call(this);

    return this;
}

function ccm_aes_encrypt_process ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var dpos = data.byteOffset || 0,
        dlen = data.byteLength || data.length || 0,
        asm = this.asm,
        heap = this.heap,
        nonce = this.nonce,
        counter = this.counter,
        pos = this.pos,
        len = this.len,
        rpos = 0,
        rlen = _aes_block_size * Math.floor( ( len + dlen ) / _aes_block_size ),
        wlen = 0;

    if ( ((counter-1)<<4) + len + dlen > _ccm_data_maxLength )
        throw new RangeError("counter overflow");

    var result = new Uint8Array(rlen);

    var asm_args = [ 0, 0, (this.lengthSize-1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];
    for ( var i = 0; i < nonce.length; i++ ) asm_args[3+i] = nonce[i];

    while ( dlen > 0 ) {
        wlen = _aes_heap_write( heap, pos+len, data, dpos, dlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        asm_args[0] = pos;
        asm_args[1] = len & ~15; // same as (len - (len % 16))
        asm_args[16] = (counter/0x100000000)>>>0;
        asm_args[17] = counter>>>0;

        wlen = asm.ccm_encrypt.apply( asm, asm_args );
        result.set( heap.subarray( pos, pos + wlen ), rpos );
        counter += (wlen>>>4);
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
    this.counter = counter;
    this.pos = pos;
    this.len = len;

    return this;
}

function ccm_aes_encrypt_finish () {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var asm = this.asm,
        heap = this.heap,
        nonce = this.nonce,
        counter = this.counter,
        tagSize = this.tagSize,
        pos = this.pos,
        len = this.len,
        wlen = 0;

    var result = new Uint8Array( len + tagSize );

    var asm_args = [ 0, 0, (this.lengthSize-1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];
    for ( var i = 0; i < nonce.length; i++ ) asm_args[3+i] = nonce[i];

    asm_args[0] = pos;
    asm_args[1] = len;
    asm_args[16] = (counter/0x100000000)>>>0;
    asm_args[17] = counter>>>0;

    wlen = asm.ccm_encrypt.apply( asm, asm_args );
    result.set( heap.subarray( pos, pos + wlen ) );
    counter = 1;
    pos = _aes_heap_start;
    len = 0;

    asm.save_state( _aes_heap_start );

    asm_args[0] = _aes_heap_start,
    asm_args[1] = _aes_block_size,
    asm_args[16] = 0;
    asm_args[17] = 0;
    asm.ccm_encrypt.apply( asm, asm_args );

    result.set( heap.subarray( _aes_heap_start, _aes_heap_start + tagSize ), wlen );

    this.result = result;
    this.counter = counter;
    this.pos = pos;
    this.len = len;

    return this;
}

function ccm_aes_encrypt ( data ) {
    this.dataLength = this.dataLeft = data.byteLength || data.length || 0;

    var result1 = ccm_aes_encrypt_process.call( this, data ).result,
        result2 = ccm_aes_encrypt_finish.call(this).result,
        result;

    result = new Uint8Array( result1.length + result2.length );
    result.set(result1);
    result.set( result2, result1.length );
    this.result = result;

    return this;
}

function ccm_aes_decrypt_process ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var dpos = data.byteOffset || 0,
        dlen = data.byteLength || data.length || 0,
        asm = this.asm,
        heap = this.heap,
        nonce = this.nonce,
        counter = this.counter,
        pos = this.pos,
        len = this.len,
        rpos = 0,
        rlen = _aes_block_size * Math.floor( ( len + dlen ) / _aes_block_size ),
        wlen = 0;

    if ( ((counter-1)<<4) + len + dlen > _ccm_data_maxLength )
        throw new RangeError("counter overflow");

    var result = new Uint8Array(rlen);

    var asm_args = [ 0, 0, (this.lengthSize-1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];
    for ( var i = 0; i < nonce.length; i++ ) asm_args[3+i] = nonce[i];

    while ( dlen > 0 ) {
        wlen = _aes_heap_write( heap, pos+len, data, dpos, dlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        asm_args[0] = pos;
        asm_args[1] = len  - ( len % _aes_block_size || ( dlen ? 0 : _aes_block_size ) );
        asm_args[16] = (counter/0x100000000)>>>0;
        asm_args[17] = counter>>>0;

        wlen = asm.ccm_decrypt.apply( asm, asm_args );
        result.set( heap.subarray( pos, pos + wlen ), rpos );
        counter += (wlen>>>4);
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
    this.counter = counter;
    this.pos = pos;
    this.len = len;

    return this;
}

function ccm_aes_decrypt_finish () {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    var asm = this.asm,
        heap = this.heap,
        nonce = this.nonce,
        counter = this.counter,
        tagSize = this.tagSize,
        pos = this.pos,
        len = this.len,
        rlen = len - tagSize,
        wlen = 0;

    if ( len < tagSize )
        throw new IllegalStateError("authentication tag not found");

    var result = new Uint8Array(rlen),
        atag = new Uint8Array( heap.subarray( pos+rlen, pos+len ) );

    var asm_args = [ 0, 0, (this.lengthSize-1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];
    for ( var i = 0; i < nonce.length; i++ ) asm_args[3+i] = nonce[i];

    asm_args[0] = pos;
    asm_args[1] = rlen;
    asm_args[16] = (counter/0x100000000)>>>0;
    asm_args[17] = counter>>>0;

    wlen = asm.ccm_decrypt.apply( asm, asm_args );
    result.set( heap.subarray( pos, pos + wlen ) );
    counter = 1;
    pos = _aes_heap_start;
    len = 0;

    asm.save_state( _aes_heap_start );

    asm_args[0] = _aes_heap_start,
    asm_args[1] = _aes_block_size,
    asm_args[16] = 0;
    asm_args[17] = 0;
    asm.ccm_encrypt.apply( asm, asm_args );

    var acheck = 0;
    for ( var i = 0; i < tagSize; ++i ) acheck |= atag[i] ^ heap[ _aes_heap_start + i ];
    if ( acheck )
        throw new SecurityError("data integrity check failed");

    this.result = result;
    this.counter = counter;
    this.pos = pos;
    this.len = len;

    return this;
}

function ccm_aes_decrypt ( data ) {
    this.dataLength = this.dataLeft = data.byteLength || data.length || 0;

    var result1 = ccm_aes_decrypt_process.call( this, data ).result,
        result2 = ccm_aes_decrypt_finish.call(this).result,
        result;

    result = new Uint8Array( result1.length + result2.length );
    result.set(result1);
    result.set( result2, result1.length );
    this.result = result;

    return this;
}

var ccm_aes_prototype = ccm_aes_constructor.prototype;
ccm_aes_prototype.reset = ccm_aes_reset;
ccm_aes_prototype.encrypt = ccm_aes_encrypt;
ccm_aes_prototype.decrypt = ccm_aes_decrypt;

var ccm_aes_encrypt_prototype = ccm_aes_encrypt_constructor.prototype;
ccm_aes_encrypt_prototype.reset = ccm_aes_reset;
ccm_aes_encrypt_prototype.process = ccm_aes_encrypt_process;
ccm_aes_encrypt_prototype.finish = ccm_aes_encrypt_finish;

var ccm_aes_decrypt_prototype = ccm_aes_decrypt_constructor.prototype;
ccm_aes_decrypt_prototype.reset = ccm_aes_reset;
ccm_aes_decrypt_prototype.process = ccm_aes_decrypt_process;
ccm_aes_decrypt_prototype.finish = ccm_aes_decrypt_finish;
