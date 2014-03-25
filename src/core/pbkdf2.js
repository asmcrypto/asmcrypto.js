function pbkdf2_constructor ( options ) {
    options = options || {};

    if ( !options.hmac )
        throw new SyntaxError("option 'hmac' is required");

    if ( !options.hmac.HMAC_SIZE )
        throw new SyntaxError("option 'hmac' supplied doesn't seem to be a valid HMAC function");

    this.hmac = options.hmac;
    this.count = options.count || 4096;
    this.length = options.length || this.hmac.HMAC_SIZE;

    this.result = null;

    var password = options.password;
    if ( password || is_string(password) )
        this.reset(options);

    return this;
}

function pbkdf2_hmac_sha256_constructor ( options ) {
    options = options || {};

    if ( !( options.hmac instanceof hmac_sha256_constructor ) )
        options.hmac = new hmac_sha256_constructor(options);

    pbkdf2_constructor.call( this, options );

    return this;
}

function pbkdf2_reset ( options ) {
    this.result = null;

    this.hmac.reset(options);

    return this;
}

function pbkdf2_generate ( salt, count, length ) {
    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    if ( !salt && !is_string(salt) )
        throw new IllegalArgumentError("bad 'salt' value");

    count = count || this.count;
    length = length || this.length;

    this.result = new Uint8Array(length);

    var blocks = Math.ceil( length / this.hmac.HMAC_SIZE );

    for ( var i = 1; i <= blocks; ++i ) {
        var j = ( i - 1 ) * this.hmac.HMAC_SIZE;
        var l = ( i < blocks ? 0 : length % this.hmac.HMAC_SIZE ) || this.hmac.HMAC_SIZE;
        var tmp = new Uint8Array( this.hmac.reset().process(salt).process( new Uint8Array([ i>>>24&0xff, i>>>16&0xff, i>>>8&0xff, i&0xff ]) ).finish().result );
        this.result.set( tmp.subarray( 0, l ), j );
        for ( var k = 1; k < count; ++k ) {
            tmp = new Uint8Array( this.hmac.reset().process(tmp).finish().result );
            for ( var r = 0; r < l; ++r ) this.result[j+r] ^= tmp[r];
        }
    }

    return this;
}

function pbkdf2_hmac_sha256_generate ( salt, count, length ) {
    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    if ( !salt && !is_string(salt) )
        throw new IllegalArgumentError("bad 'salt' value");

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

var pbkdf2_hmac_sha256_prototype = pbkdf2_hmac_sha256_constructor.prototype;
pbkdf2_hmac_sha256_prototype.reset =   pbkdf2_reset;
pbkdf2_hmac_sha256_prototype.generate = pbkdf2_hmac_sha256_generate;
