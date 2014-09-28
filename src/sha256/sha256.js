var _sha256_block_size = 64,
    _sha256_hash_size = 32;

function sha256_constructor ( options ) {
    options = options || {};
    options.heapSize = options.heapSize || 4096;

    if ( options.heapSize <= 0 || options.heapSize % 4096 )
        throw new IllegalArgumentError("heapSize must be a positive number and multiple of 4096");

    this.heap = options.heap || new Uint8Array(options.heapSize);
    this.asm = options.asm || sha256_asm( global, null, this.heap.buffer );

    this.BLOCK_SIZE = _sha256_block_size;
    this.HASH_SIZE = _sha256_hash_size;

    this.reset();
}

function sha256_reset () {
    this.result = null;
    this.pos = 0;
    this.len = 0;

    this.asm.reset();

    return this;
}

function sha256_process ( data ) {
    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    var dpos = 0, dlen = 0, clen = 0;

    if ( is_buffer(data) || is_bytes(data) ) {
        dpos = data.byteOffset||0;
        dlen = data.byteLength;
    }
    else if ( is_string(data) ) {
        data = string_to_bytes(data);
        dlen = data.length;
    }
    else {
        throw new TypeError("data isn't of expected type");
    }

    while ( dlen > 0 ) {
        clen = this.heap.byteLength - this.pos - this.len;
        clen = ( clen < dlen ) ? clen : dlen;

        if ( is_buffer(data) || is_bytes(data) ) {
            this.heap.set( new Uint8Array( (data.buffer||data), dpos, clen ), this.pos + this.len );
        } else {
            for ( var i = 0; i < clen; i++ ) this.heap[ this.pos + this.len + i ] = data.charCodeAt( dpos + i );
        }
        this.len += clen;
        dpos += clen;
        dlen -= clen;

        clen = this.asm.process( this.pos, this.len );
        if ( clen < this.len ) {
            this.pos += clen;
            this.len -= clen;
        } else {
            this.pos = 0;
            this.len = 0;
        }
    }

    return this;
}

function sha256_finish () {
    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    this.asm.finish( this.pos, this.len, 0 );

    this.result = new Uint8Array(_sha256_hash_size);
    this.result.set( this.heap.subarray( 0, _sha256_hash_size ) );

    this.pos = 0;
    this.len = 0;

    return this;
}

sha256_constructor.BLOCK_SIZE = _sha256_block_size;
sha256_constructor.HASH_SIZE = _sha256_hash_size;
var sha256_prototype = sha256_constructor.prototype;
sha256_prototype.reset =   sha256_reset;
sha256_prototype.process = sha256_process;
sha256_prototype.finish =  sha256_finish;

var sha256_instance = null;

function get_sha256_instance () {
    if ( sha256_instance === null ) sha256_instance = new sha256_constructor( { heapSize: 0x100000 } );
    return sha256_instance;
}
