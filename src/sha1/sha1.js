var _sha1_block_size = 64,
    _sha1_hash_size = 20;

function sha1_constructor ( options ) {
    options = options || {};
    options.heapSize = options.heapSize || 4096;

    if ( options.heapSize <= 0 || options.heapSize % 4096 )
        throw new IllegalArgumentError("heapSize must be a positive number and multiple of 4096");

    this.heap = options.heap || new Uint8Array(options.heapSize);
    this.asm = options.asm || sha1_asm( global, null, this.heap.buffer );

    this.BLOCK_SIZE = _sha1_block_size;
    this.HASH_SIZE = _sha1_hash_size;

    this.reset();
}

function sha1_reset () {
    this.result = null;
    this.pos = 0;
    this.len = 0;

    this.asm.reset();

    return this;
}

function sha1_process ( data ) {
    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    if ( !is_bytes(data) )
        throw new TypeError("data isn't of expected type");

    var asm = this.asm,
        heap = this.heap,
        hpos = this.pos,
        hlen = this.len,
        dpos = 0,
        dlen = data.byteLength,
        wlen = 0;

    while ( dlen > 0 ) {
        wlen = heap.byteLength - hpos - hlen;
        wlen = ( wlen < dlen ) ? wlen : dlen;

        heap.set( new Uint8Array( (data.buffer||data), dpos, wlen ), this.pos + this.len );
        heap.set( data.subarray( dpos, dpos+wlen ), hpos+hlen );

        hlen += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.process( hpos, hlen );

        hpos += wlen;
        hlen -= wlen;

        if ( !hlen ) hpos = 0;
    }

    this.pos = hpos;
    this.len = hlen;

    return this;
}

function sha1_finish () {
    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    this.asm.finish( this.pos, this.len, 0 );

    this.result = new Uint8Array(_sha1_hash_size);
    this.result.set( this.heap.subarray( 0, _sha1_hash_size ) );

    this.pos = 0;
    this.len = 0;

    return this;
}

sha1_constructor.BLOCK_SIZE = _sha1_block_size;
sha1_constructor.HASH_SIZE = _sha1_hash_size;
var sha1_prototype = sha1_constructor.prototype;
sha1_prototype.reset =   sha1_reset;
sha1_prototype.process = sha1_process;
sha1_prototype.finish =  sha1_finish;

var sha1_instance = null;

function get_sha1_instance () {
    if ( sha1_instance === null ) sha1_instance = new sha1_constructor( { heapSize: 0x100000 } );
    return sha1_instance;
}
