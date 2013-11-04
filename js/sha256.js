function sha256_constructor ( options ) {
    options = options || {};
    options.heapSize = options.heapSize || 4096

    if ( options.heapSize % 4096 > 0 )
        throw new Error("heapSize must be a multiple of 4096");

    this.heap = new Uint8Array( options.heapSize || 4096 );
    this.pos = 0;
    this.len = 0;

    this.asm = sha256_asm( window, null, this.heap.buffer );
    this.asm.reset();

    this.BLOCK_SIZE = 64;
    this.HASH_SIZE = 32;

    this.result = null;
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
        throw new Error("Illegal state");

    var dpos, dlen, clen;

    if ( data instanceof ArrayBuffer || data instanceof Uint8Array ) {
        dpos = data.byteOffset||0;
        dlen = data.byteLength;
    }
    else if ( typeof data === 'string' ) {
        dpos = 0;
        dlen = data.length;
    }
    else {
        throw new ReferenceError("Illegal argument");
    }

    while ( dlen > 0 ) {
        clen = this.heap.byteLength - this.pos - this.len;
        clen = ( clen < dlen ) ? clen : dlen;

        if ( data instanceof ArrayBuffer || data instanceof Uint8Array ) {
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
        throw new Error("Illegal state");

    this.asm.finish( this.pos, this.len, 0 );

    this.result = new Uint8Array(this.HASH_SIZE);
    this.result.set( this.heap.subarray( 0, this.HASH_SIZE ) );

    this.pos = 0;
    this.len = 0;

    return this;
}

// methods
var sha256_prototype = sha256_constructor.prototype;
sha256_prototype.reset =   sha256_reset;
sha256_prototype.process = sha256_process;
sha256_prototype.finish =  sha256_finish;
sha256_prototype.asHex =   resultAsHex;
sha256_prototype.asBase64 = resultAsBase64;
sha256_prototype.asBinaryString = resultAsBinaryString;
sha256_prototype.asArrayBuffer = resultAsArrayBuffer;

// static constants
sha256_constructor.BLOCK_SIZE = 64;
sha256_constructor.HASH_SIZE = 32;

// static methods
var sha256_instance = new sha256_constructor;
sha256_constructor.hex = function ( data ) { return sha256_instance.reset().process(data).finish().asHex() };
sha256_constructor.base64 = function ( data ) { return sha256_instance.reset().process(data).finish().asBase64() };

// export
exports.SHA256 = sha256_constructor;
