function RSA ( options ) {
    options = options || {};

    this.key = null;
    this.result = null;

    this.reset(options);
}

function RSA_reset ( options ) {
    options = options || {};

    this.result = null;

    var key = options.key
    if ( key !== undefined ) {
        if ( key instanceof Array ) {
            var l = key.length;
            if ( l !== 2 && l !== 3 && l !== 8 )
                throw new SyntaxError("unexpected key type");

            var k = [];
            k[0] = new Modulus( key[0] );
            k[1] = new BigNumber( key[1] );
            if ( l > 2 ) {
                k[2] = new BigNumber( key[2] );
            }
            if ( l > 3 ) {
                k[3] = new Modulus( key[3] );
                k[4] = new Modulus( key[4] );
                k[5] = new BigNumber( key[5] );
                k[6] = new BigNumber( key[6] );
                k[7] = new BigNumber( key[7] );
            }

            this.key = k;
        }
        else {
            throw new TypeError("unexpected key type");
        }
    }

    return this;
}

function RSA_encrypt ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    var msg;
    if ( is_bytes(data) ) {
        msg = new BigNumber(data);
    }
    else if ( is_big_number(data) ) {
        msg = data;
    }
    else {
        throw new TypeError("unexpected data type");
    }

    if ( this.key[0].compare(msg) <= 0 )
        throw new RangeError("data too large");

    this.result = this.key[0].power( msg, this.key[1] ).toBytes();

    return this;
}

function RSA_decrypt ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    if ( this.key.length < 3 )
        throw new IllegalStateError("key isn't suitable for decription");

    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    var msg;
    if ( is_bytes(data) ) {
        msg = new BigNumber(data);
    }
    else if ( is_big_number(data) ) {
        msg = data;
    }
    else {
        throw new TypeError("unexpected data type");
    }

    if ( this.key[0].compare(msg) <= 0 )
        throw new RangeError("data too large");

    if ( this.key.length > 3 ) {
        var m = this.key[0],
            d = this.key[2],
            p = this.key[3],
            q = this.key[4],
            dp = this.key[5],
            dq = this.key[6],
            u = this.key[7];

        var x = p.power( msg, dp ),
            y = q.power( msg, dq );

        var t = x.subtract(y);
        if ( t.sign < 0 ) t = t.add(p);

        var h = p.reduce( u.multiply(t) );

        this.result = h.multiply(q).add(y).clamp(m.bitLength).toBytes();
    }
    else {
        var m = this.key[0],
            d = this.key[2];

        this.result = m.power( msg, d ).toBytes();
    }

    return this;
}

var RSA_prototype = RSA.prototype;
RSA_prototype.reset = RSA_reset;
RSA_prototype.encrypt = RSA_encrypt;
RSA_prototype.decrypt = RSA_decrypt;
