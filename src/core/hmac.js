function hmac_constructor ( options ) {
    options = options || {};

    if ( !options.hash )
        throw new SyntaxError("option 'hash' is required");

    if ( !options.hash.HASH_SIZE )
        throw new SyntaxError("option 'hash' supplied doesn't seem to be a valid hash function");

    this.hash = options.hash;
    this.BLOCK_SIZE = this.hash.BLOCK_SIZE;
    this.HMAC_SIZE = this.hash.HASH_SIZE;

    this.key = null;
    this.verify = null;
    this.result = null;

    if ( options.password !== undefined || options.verify !== undefined )
        this.reset(options);

    return this;
}

function hmac_sha256_constructor ( options ) {
    options = options || {};

    if ( !( options.hash instanceof sha256_constructor ) )
        options.hash = new sha256_constructor(options);

    hmac_constructor.call( this, options );

    return this;
}

function _hmac_key ( hash, password ) {
    var key;

    if ( password instanceof ArrayBuffer || password instanceof Uint8Array ) {
        key = new Uint8Array(hash.BLOCK_SIZE);

        if ( password.byteLength > this.hash.BLOCK_SIZE ) {
            key.set( new Uint8Array( hash.reset().process(password).finish().result ) );
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
            key.set( new Uint8Array( hash.reset().process(password).finish().result ) );
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

function _hmac_init_verify ( verify ) {
    if ( verify instanceof ArrayBuffer || verify instanceof Uint8Array ) {
        verify = new Uint8Array(verify);
    }
    else if ( typeof verify === 'string' ) {
        verify = string_to_bytes(verify);
    }
    else {
        throw new TypeError("verify tag isn't of expected type");
    }

    if ( verify.length !== this.HMAC_SIZE )
        throw new IllegalArgumentError("illegal verification tag size");

    this.verify = verify;
}

function hmac_reset ( options ) {
    options = options || {};
    var password = options.password;

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

    var verify = options.verify;
    if ( verify !== undefined ) {
        _hmac_init_verify.call( this, verify );
    }
    else {
        this.verify = null;
    }

    return this;
}

function hmac_sha256_reset ( options ) {
    options = options || {};
    var password = options.password;

    if ( this.key === null && typeof password !== 'string' && !password )
        throw new IllegalStateError("no key is associated with the instance");

    this.result = null;
    this.hash.reset();

    if ( password || typeof password === 'string' ) {
        this.key = _hmac_key( this.hash, password );
        this.hash.reset().asm.hmac_init(
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

    var verify = options.verify;
    if ( verify !== undefined ) {
        _hmac_init_verify.call( this, verify );
    }
    else {
        this.verify = null;
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

    var verify = this.verify;
    var result = this.hash.reset().process(opad).process(inner_result).finish().result;

    if ( verify ) {
        if ( verify.length === result.length ) {
            var diff = 0;
            for ( var i = 0; i < verify.length; i++ ) {
                diff |= ( verify[i] ^ result[i] );
            }
            this.result = !diff;
        } else {
            this.result = false;
        }
    }
    else {
        this.result = result;
    }

    return this;
}

function hmac_sha256_finish () {
    if ( this.key === null )
        throw new IllegalStateError("no key is associated with the instance");

    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    var hash = this.hash,
        asm = this.hash.asm,
        heap = this.hash.heap;

    asm.hmac_finish( hash.pos, hash.len, 0 );

    var verify = this.verify;
    var result = new Uint8Array(_sha256_hash_size);
    result.set( heap.subarray( 0, _sha256_hash_size ) );

    if ( verify ) {
        if ( verify.length === result.length ) {
            var diff = 0;
            for ( var i = 0; i < verify.length; i++ ) {
                diff |= ( verify[i] ^ result[i] );
            }
            this.result = !diff;
        } else {
            this.result = false;
        }
    }
    else {
        this.result = result;
    }

    return this;
}

var hmac_prototype = hmac_constructor.prototype;
hmac_prototype.reset =   hmac_reset;
hmac_prototype.process = hmac_process;
hmac_prototype.finish =  hmac_finish;

hmac_sha256_constructor.BLOCK_SIZE = sha256_constructor.BLOCK_SIZE;
hmac_sha256_constructor.HMAC_SIZE = sha256_constructor.HASH_SIZE;
var hmac_sha256_prototype = hmac_sha256_constructor.prototype;
hmac_sha256_prototype.reset = hmac_sha256_reset;
hmac_sha256_prototype.process = hmac_process;
hmac_sha256_prototype.finish = hmac_sha256_finish;
