function hmac_constructor ( key, options ) {
    options = options || {};
    options.hashFunction = options.hashFunction || sha256_constructor;

    if ( options.hashFunction.BLOCK_SIZE )
        throw new ReferenceError("'hashFunction' supplied doesn't seem to be a valid hash function");

    this.hash = new options.hashFunction(options);
    this.BLOCK_SIZE = this.hash.BLOCK_SIZE;
    this.HMAC_SIZE = this.hash.HASH_SIZE;

    this.key = null;
    this.result = null;

    if ( key ) this.reset(key);

    return this;
}

function hmac_sha256_constructor ( key, options ) {
    options = options || {};
    options.hashFunction = sha256_constructor;
    return new hmac_constructor( key, options );
}

function hmac_reset ( key ) {
    if ( this.key === null && typeof key !== 'string' && !key )
        throw new Error("Illegal state");

    if ( key || typeof key === 'string' ) {
        if ( key instanceof ArrayBuffer || key instanceof Uint8Array ) {
            this.key = new Uint8Array(this.hash.BLOCK_SIZE);

            if ( key.byteLength > this.hash.BLOCK_SIZE ) {
                this.key.set( new Uint8Array( this.hash.reset().process(key).finish().asArrayBuffer() ) );
            }
            else if ( key instanceof ArrayBuffer ) {
                this.key.set( new Uint8Array(key) );
            }
            else {
                this.key.set(key);
            }
        }
        else if ( typeof key === 'string' ) {
            this.key = new Uint8Array(this.hash.BLOCK_SIZE);

            if ( key.length > this.hash.BLOCK_SIZE ) {
                this.key.set( new Uint8Array( this.hash.reset().process(key).finish().asArrayBuffer() ) );
            }
            else {
                for ( var i = 0; i < key.length; ++i )
                    this.key[i] = key.charCodeAt(i);
            }
        }
        else {
            throw new ReferenceError("Illegal argument");
        }
    }

    var ipad = new Uint8Array(this.key);
    for ( var i = 0; i < ipad.length; ++i )
        ipad[i] ^= 0x36;

    this.hash.reset();
    this.hash.process(ipad);

    this.result = null;

    return this;
}

function hmac_process ( data ) {
    if ( this.key === null || this.result !== null )
        throw new Error("Illegal state");

    this.hash.process(data);

    return this;
}

function hmac_finish () {
    if ( this.key === null || this.result !== null )
        throw new Error("Illegal state");

    var inner_result = this.hash.finish().asArrayBuffer();

    var opad = new Uint8Array(this.key);
    for ( var i = 0; i < opad.length; ++i )
        opad[i] ^= 0x5c;

    this.result = new Uint8Array( this.hash.reset().process(opad).process(inner_result).finish().asArrayBuffer() );

    return this;
}

// methods
hmac_constructor.prototype.reset =   hmac_reset;
hmac_constructor.prototype.process = hmac_process;
hmac_constructor.prototype.finish =  hmac_finish;
hmac_constructor.prototype.asHex =   resultAsHex;
hmac_constructor.prototype.asBase64 = resultAsBase64;
hmac_constructor.prototype.asBinaryString = resultAsBinaryString;
hmac_constructor.prototype.asArrayBuffer = resultAsArrayBuffer;

// static constants
hmac_sha256_constructor.BLOCK_SIZE = sha256_constructor.BLOCK_SIZE;
hmac_sha256_constructor.HMAC_SIZE = sha256_constructor.HASH_SIZE;

// static methods
var hmac_sha256_instance = new hmac_sha256_constructor;
hmac_sha256_constructor.hex = function ( key, data ) { return hmac_sha256_instance.reset(key).process(data).finish().asHex() };
hmac_sha256_constructor.base64 = function ( key, data ) { return hmac_sha256_instance.reset(key).process(data).finish().asBase64() };

// export
exports.HMAC = hmac_constructor;
exports.HMAC_SHA256 = hmac_sha256_constructor;
