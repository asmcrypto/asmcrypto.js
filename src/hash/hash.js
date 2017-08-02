import {_heap_write, is_buffer, is_bytes, is_string, string_to_bytes} from '../utils';

export function hash_reset () {
    this.result = null;
    this.pos = 0;
    this.len = 0;

    this.asm.reset();

    return this;
}

export function hash_process ( data ) {
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
        dlen = data.length,
        wlen = 0;

    while ( dlen > 0 ) {
        wlen = _heap_write( heap, hpos+hlen, data, dpos, dlen );
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

export function hash_finish () {
    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    this.asm.finish( this.pos, this.len, 0 );

    this.result = new Uint8Array(this.HASH_SIZE);
    this.result.set( this.heap.subarray( 0, this.HASH_SIZE ) );

    this.pos = 0;
    this.len = 0;

    return this;
}
