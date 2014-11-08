var _ctr_data_maxLength = 68719476720;  // 2^36 - 2^4

function ctr_aes_constructor ( options ) {
    this.padding    = false;
    this.mode       = 'ctr';

    this.nonce      = null;
    this.counter    = 0;

    _aes_constructor.call( this, options );
}

function ctr_aes_encrypt_constructor ( options ) {
    ctr_aes_constructor.call( this, options );
}

function ctr_aes_reset ( options ) {
    options = options || {};

    _aes_reset.call( this, options );

    var nonce = options.nonce;
    if ( nonce !== undefined ) {
        if ( is_buffer(nonce) ) {
            nonce = new Uint8Array(nonce);
        }
        else if ( is_string(nonce) ) {
            nonce = string_to_bytes(nonce);
        }
        else if ( is_bytes(nonce) ) {
            // do nothing
        }
        else {
            throw new TypeError("unexpected nonce type");
        }

        if ( nonce.length > 16 )
            throw new IllegalArgumentError("illegal nonce length");

        this.nonce = new Uint8Array(16);
        this.nonce.set(nonce);
    }
    else {
        this.nonce = null;
    }

    var counter = options.counter;
    if ( counter !== undefined ) {
        if ( !is_number(counter) )
            throw new TypeError("counter must be a number");

        this.counter = counter;
    }
    else {
        this.counter = 0;
    }

    return this;
}

function ctr_aes_encrypt_process ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    if ( !this.nonce )
        throw new IllegalStateError("no nonce is associated with the instance");

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
        nonce = this.nonce,
        counter = this.counter,
        pos = this.pos,
        len = this.len,
        rpos = 0,
        rlen = _aes_block_size * Math.floor( ( len + dlen ) / _aes_block_size ),
        wlen = 0;

    if ( (counter << 4) + len + dlen > _ctr_data_maxLength )
        throw new RangeError("counter overflow");

    var result = new Uint8Array(rlen);

    var nc = (nonce[12] << 24) | (nonce[13] << 16) | (nonce[14] << 8) | nonce[15];

    while ( dlen > 0 ) {
        wlen = _aes_heap_write( heap, pos+len, data, dpos, dlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.ctr_encrypt( pos, len, nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7], nonce[8], nonce[9], nonce[10], nonce[11], (nc+counter)|0 );
        if ( wlen ) result.set( heap.subarray( pos, pos + wlen ), rpos );
        counter += (wlen >>> 4);
        rpos += wlen;

        pos += wlen;
        len -= wlen;

        if ( !len ) pos = _aes_heap_start;
    }

    this.result = result;
    this.counter = counter;
    this.pos = pos;
    this.len = len;

    return this;
}

function ctr_aes_encrypt_finish () {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    if ( !this.nonce )
        throw new IllegalStateError("no nonce is associated with the instance");

    var asm = this.asm,
        heap = this.heap,
        nonce = this.nonce,
        counter = this.counter,
        pos = this.pos,
        len = this.len,
        wlen = 0;

    var result = new Uint8Array(len);

    var nc = (nonce[12] << 24) | (nonce[13] << 16) | (nonce[14] << 8) | nonce[15];

    if ( len > 0 ) {
        wlen = asm.ctr_encrypt( pos, (len + 15) & -16, nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7], nonce[8], nonce[9], nonce[10], nonce[11], (nc+counter)|0 );
        result.set( heap.subarray( pos, pos+len ) );
    }

    this.result = result;
    this.counter = 0;
    this.pos = _aes_heap_start;
    this.len = 0;

    return this;
}

function ctr_aes_encrypt ( data ) {
    var result1 = ctr_aes_encrypt_process.call( this, data ).result,
        result2 = ctr_aes_encrypt_finish.call(this).result,
        result;

    result = new Uint8Array( result1.length + result2.length );
    if ( result1.length ) result.set(result1);
    if ( result2.length ) result.set( result2, result1.length );
    this.result = result;

    return this;
}

var ctr_aes_prototype = ctr_aes_constructor.prototype;
ctr_aes_prototype.reset = ctr_aes_reset;
ctr_aes_prototype.encrypt = ctr_aes_encrypt;
ctr_aes_prototype.decrypt = ctr_aes_encrypt;

var ctr_aes_encrypt_prototype = ctr_aes_encrypt_constructor.prototype;
ctr_aes_encrypt_prototype.reset = ctr_aes_reset;
ctr_aes_encrypt_prototype.process = ctr_aes_encrypt_process;
ctr_aes_encrypt_prototype.finish = ctr_aes_encrypt_finish;

var ctr_aes_decrypt_prototype = ctr_aes_encrypt_constructor.prototype;
ctr_aes_decrypt_prototype.reset = ctr_aes_reset;
ctr_aes_decrypt_prototype.process = ctr_aes_encrypt_process;
ctr_aes_decrypt_prototype.finish = ctr_aes_encrypt_finish;
