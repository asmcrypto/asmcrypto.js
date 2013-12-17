function hmac_constructor ( password, options ) {
    options = options || {};
    options.hashFunction = options.hashFunction || new sha256_constructor(options);

    if ( !options.hashFunction.HASH_SIZE )
        throw new TypeError("'hashFunction' supplied doesn't seem to be a valid hash function");

    this.hash = options.hashFunction;
    this.BLOCK_SIZE = this.hash.BLOCK_SIZE;
    this.HMAC_SIZE = this.hash.HASH_SIZE;

    this.key = null;
    this.result = null;

    if ( password || typeof password === 'string' )
        this.reset(password);

    return this;
}

function hmac_sha256_constructor ( password, options ) {
    hmac_constructor.call( this, password, options );

    return this;
}

function _hmac_key ( hash, password ) {
    var key;

    if ( password instanceof ArrayBuffer || password instanceof Uint8Array ) {
        key = new Uint8Array(hash.BLOCK_SIZE);

        if ( password.byteLength > this.hash.BLOCK_SIZE ) {
            key.set( new Uint8Array( hash.reset().process(password).finish().asArrayBuffer() ) );
        }
        else if ( password instanceof ArrayBuffer ) {
            key.set( new Uint8Array(password) );
        }
        else {
            key.set(password);
        }
    }
    else if ( typeof password === 'string' ) {
        key = new Uint8Array(hash.BLOCK_SIZE);

        if ( password.length > hash.BLOCK_SIZE ) {
            key.set( new Uint8Array( hash.reset().process(password).finish().asArrayBuffer() ) );
        }
        else {
            for ( var i = 0; i < password.length; ++i )
                key[i] = password.charCodeAt(i);
        }
    }
    else {
        throw new TypeError("password isn't of expected type");
    }

    return key;
}

function hmac_reset ( password ) {
    if ( this.key === null && typeof password !== 'string' && !password )
        throw new IllegalStateError("no key is associated with the instance");

    this.result = null;
    this.hash.reset();

    if ( password || typeof password === 'string' )
        this.key = _hmac_key( this.hash, password );

    var ipad = new Uint8Array(this.key);
    for ( var i = 0; i < ipad.length; ++i )
        ipad[i] ^= 0x36;

    this.hash.process(ipad);

    return this;
}

function hmac_sha256_reset ( password ) {
    if ( this.key === null && typeof password !== 'string' && !password )
        throw new IllegalStateError("no key is associated with the instance");

    this.result = null;
    this.hash.reset();

    if ( password || typeof password === 'string' ) {
        this.key = _hmac_key( this.hash, password );
        this.hash.asm.hmac_init(
            (this.key[0]<<24)|(this.key[1]<<16)|(this.key[2]<<8)|(this.key[3]),
            (this.key[4]<<24)|(this.key[5]<<16)|(this.key[6]<<8)|(this.key[7]),
            (this.key[8]<<24)|(this.key[9]<<16)|(this.key[10]<<8)|(this.key[11]),
            (this.key[12]<<24)|(this.key[13]<<16)|(this.key[14]<<8)|(this.key[15]),
            (this.key[16]<<24)|(this.key[17]<<16)|(this.key[18]<<8)|(this.key[19]),
            (this.key[20]<<24)|(this.key[21]<<16)|(this.key[22]<<8)|(this.key[23]),
            (this.key[24]<<24)|(this.key[25]<<16)|(this.key[26]<<8)|(this.key[27]),
            (this.key[28]<<24)|(this.key[29]<<16)|(this.key[30]<<8)|(this.key[31]),
            (this.key[32]<<24)|(this.key[33]<<16)|(this.key[34]<<8)|(this.key[35]),
            (this.key[36]<<24)|(this.key[37]<<16)|(this.key[38]<<8)|(this.key[39]),
            (this.key[40]<<24)|(this.key[41]<<16)|(this.key[42]<<8)|(this.key[43]),
            (this.key[44]<<24)|(this.key[45]<<16)|(this.key[46]<<8)|(this.key[47]),
            (this.key[48]<<24)|(this.key[49]<<16)|(this.key[50]<<8)|(this.key[51]),
            (this.key[52]<<24)|(this.key[53]<<16)|(this.key[54]<<8)|(this.key[55]),
            (this.key[56]<<24)|(this.key[57]<<16)|(this.key[58]<<8)|(this.key[59]),
            (this.key[60]<<24)|(this.key[61]<<16)|(this.key[62]<<8)|(this.key[63])
        );
    }
    else {
        this.hash.asm.hmac_reset();
    }

    return this;
}

function hmac_process ( data ) {
    if ( this.key === null )
        throw new IllegalStateError("no key is associated with the instance");

    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    this.hash.process(data);

    return this;
}

function hmac_finish () {
    if ( this.key === null )
        throw new IllegalStateError("no key is associated with the instance");

    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    var inner_result = this.hash.finish().result;

    var opad = new Uint8Array(this.key);
    for ( var i = 0; i < opad.length; ++i )
        opad[i] ^= 0x5c;

    this.result = this.hash.reset().process(opad).process(inner_result).finish().result;

    return this;
}

function hmac_sha256_finish () {
    if ( this.key === null )
        throw new IllegalStateError("no key is associated with the instance");

    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    this.hash.asm.hmac_finish( this.hash.pos, this.hash.len, 0 );

    this.result = new Uint8Array(this.HMAC_SIZE);
    this.result.set( this.hash.heap.subarray( 0, this.HMAC_SIZE ) );

    return this;
}

// methods
var hmac_prototype = hmac_constructor.prototype;
hmac_prototype.reset =   hmac_reset;
hmac_prototype.process = hmac_process;
hmac_prototype.finish =  hmac_finish;
hmac_prototype.asHex =   resultAsHex;
hmac_prototype.asBase64 = resultAsBase64;
hmac_prototype.asBinaryString = resultAsBinaryString;
hmac_prototype.asArrayBuffer = resultAsArrayBuffer;

var hmac_sha256_prototype = hmac_sha256_constructor.prototype;
hmac_sha256_prototype.reset = hmac_sha256_reset;
hmac_sha256_prototype.process = hmac_process;
hmac_sha256_prototype.finish = hmac_sha256_finish;
hmac_sha256_prototype.asHex =   resultAsHex;
hmac_sha256_prototype.asBase64 = resultAsBase64;
hmac_sha256_prototype.asBinaryString = resultAsBinaryString;
hmac_sha256_prototype.asArrayBuffer = resultAsArrayBuffer;

// static constants
hmac_sha256_constructor.BLOCK_SIZE = sha256_constructor.BLOCK_SIZE;
hmac_sha256_constructor.HMAC_SIZE = sha256_constructor.HASH_SIZE;

// static methods
var hmac_sha256_instance = new hmac_sha256_constructor( undefined, { hashFunction: sha256_instance } );
hmac_sha256_constructor.hex = function ( password, data ) { return hmac_sha256_instance.reset(password).process(data).finish().asHex() };
hmac_sha256_constructor.base64 = function ( password, data ) { return hmac_sha256_instance.reset(password).process(data).finish().asBase64() };

// export
exports.HMAC = hmac_constructor;
exports.HMAC_SHA256 = hmac_sha256_constructor;
