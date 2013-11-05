function pbkdf2_constructor ( password, options ) {
    options = options || {};
    options.hmacFunction = options.hmacFunction || hmac_sha256_constructor;
    options.count = options.count || 4096;
    options.length = options.length || options.hmacFunction.HMAC_SIZE;

    if ( !options.hmacFunction.HMAC_SIZE )
        throw new ReferenceError("'hmacFunction' supplied doesn't seem to be a valid HMAC function");

    this.hmac = new options.hmacFunction( password, options );
    this.count = options.count;
    this.length = options.length;

    this.result = null;

    return this;
}

function pbkdf2_hmac_sha256_constructor ( password, options ) {
    options = options || {};
    options.hmacFunction = options.hmacFunction || hmac_sha256_constructor;

    pbkdf2_constructor.call( this, password, options );

    return this;
}

function pbkdf2_reset ( password ) {
    this.result = null;
    this.hmac.reset(password);
    return this;
}

function pbkdf2_generate ( salt, count, length ) {
    if ( this.result !== null )
        throw new Error("Illegal state");

    if ( !salt && typeof salt !== 'string' )
        throw new ReferenceError("Illegal 'salt' value");

    count = count || this.count;
    length = length || this.length;

    this.result = new Uint8Array(length);

    var blocks = Math.ceil( length / this.hmac.HMAC_SIZE );
    for ( var i = 1; i <= blocks; ++i ) {
        var j = ( i - 1 ) * this.hmac.HMAC_SIZE;
        var l = ( i < blocks ? 0 : length % this.hmac.HMAC_SIZE ) || this.hmac.HMAC_SIZE;
        var tmp = new Uint8Array( this.hmac.reset().process(salt).process( new Uint8Array([ i>>>24&0xff, i>>>16&0xff, i>>>8&0xff, i&0xff ]) ).finish().asArrayBuffer() );
        this.result.set( tmp.subarray( 0, l ), j );
        for ( var k = 1; k < count; ++k ) {
            tmp = new Uint8Array( this.hmac.reset().process(tmp).finish().asArrayBuffer() );
            for ( var r = 0; r < l; ++r ) this.result[j+r] ^= tmp[r];
        }
    }

    return this;
}

function pbkdf2_hmac_sha256_generate ( salt, count, length ) {
    if ( this.result !== null )
        throw new Error("Illegal state");

    if ( !salt && typeof salt !== 'string' )
        throw new ReferenceError("Illegal 'salt' value");

    count = count || this.count;
    length = length || this.length;

    this.result = new Uint8Array(length);

    var blocks = Math.ceil( length / this.hmac.HMAC_SIZE );

    for ( var i = 1; i <= blocks; ++i ) {
        var j = ( i - 1 ) * this.hmac.HMAC_SIZE;
        var l = ( i < blocks ? 0 : length % this.hmac.HMAC_SIZE ) || this.hmac.HMAC_SIZE;

        this.hmac.reset().process(salt);
        this.hmac.hash.asm.pbkdf2_generate_block( this.hmac.hash.pos, this.hmac.hash.len, i, count, 0 );

        this.result.set( this.hmac.hash.heap.subarray( 0, l ), j );
    }

    return this;
}

// methods
var pbkdf2_prototype = pbkdf2_constructor.prototype;
pbkdf2_prototype.reset =   pbkdf2_reset;
pbkdf2_prototype.generate = pbkdf2_generate;
pbkdf2_prototype.asHex =   resultAsHex;
pbkdf2_prototype.asBase64 = resultAsBase64;
pbkdf2_prototype.asBinaryString = resultAsBinaryString;
pbkdf2_prototype.asArrayBuffer = resultAsArrayBuffer;

var pbkdf2_hmac_sha256_prototype = pbkdf2_hmac_sha256_constructor.prototype;
pbkdf2_hmac_sha256_prototype.reset =   pbkdf2_reset;
pbkdf2_hmac_sha256_prototype.generate = pbkdf2_hmac_sha256_generate;
pbkdf2_hmac_sha256_prototype.asHex =   resultAsHex;
pbkdf2_hmac_sha256_prototype.asBase64 = resultAsBase64;
pbkdf2_hmac_sha256_prototype.asBinaryString = resultAsBinaryString;
pbkdf2_hmac_sha256_prototype.asArrayBuffer = resultAsArrayBuffer;

// static methods
var pbkdf2_hmac_sha256_instance = new pbkdf2_hmac_sha256_constructor;
pbkdf2_hmac_sha256_constructor.hex = function ( password, salt, count, length ) { return pbkdf2_hmac_sha256_instance.reset(password).generate(salt, count, length).asHex() };
pbkdf2_hmac_sha256_constructor.base64 = function ( password, salt, count, length ) { return pbkdf2_hmac_sha256_instance.reset(password).generate(salt, count, length).asBase64() };

// export
exports.PBKDF2 = pbkdf2_constructor;
exports.PBKDF2_HMAC_SHA256 = pbkdf2_hmac_sha256_constructor;
