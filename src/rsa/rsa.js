function RSA ( options ) {
    options = options || {};

    this.key = null;
    this.result = null;

    this.reset(options);
}

function RSA_reset ( options ) {
    options = options || {};

    this.result = null;

    if ( options.key ) {
        this.key = _RSA_ASN1_parse_key(options.key);
    }

    return this;
}

function RSA_encrypt ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    if ( typeof data === 'string' )
        data = string_to_bytes(data);

    if ( data instanceof ArrayBuffer )
        data = new Uint8Array(data);

    var msg;
    if ( data instanceof Uint8Array ) {
        if ( ( (data.length << 3) > this.key[0].bitLength ) || ( this.key[0].compare(msg = new BigNumber(data)) <= 0 ) )
            throw new RangeError("data too large");
    }
    else if ( data instanceof BigNumber ) {
        if ( ( data.bitLength > this.key[0].bitLength ) || ( this.key[0].compare(msg = data) <= 0 ) )
            throw new RangeError("data too large");
    }
    else {
        throw new TypeError("unexpected data type");
    }

    this.result = this.key[0].power( msg, this.key[1] );

    return this;
}

function RSA_decrypt ( data ) {
    if ( !this.key )
        throw new IllegalStateError("no key is associated with the instance");

    if ( this.key.length < 3 )
        throw new IllegalStateError("key isn't suitable for decription");

    if ( typeof data === 'string' )
        data = string_to_bytes(data);

    if ( data instanceof ArrayBuffer )
        data = new Uint8Array(data);

    var msg;
    if ( data instanceof Uint8Array ) {
        if ( ( (data.length << 3) > this.key[0].bitLength ) || ( this.key[0].compare(msg = new BigNumber(data)) <= 0 ) )
            throw new RangeError("data too large");
    }
    else if ( data instanceof BigNumber ) {
        if ( ( data.bitLength > this.key[0].bitLength ) || ( this.key[0].compare(msg = data) <= 0 ) )
            throw new RangeError("data too large");
    }
    else {
        throw new TypeError("unexpected data type");
    }

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

        this.result = h.multiply(q).add(y).clamp(m.bitLength);
    }
    else {
        var m = this.key[0],
            d = this.key[2];

        this.result = m.power( msg, d );
    }

    return this;
}

function _RSA_ASN1_parse_key ( key ) {
    var buff = null;

    if ( typeof key === 'string' ) {
        var re_begin = /^-+BEGIN (?:RSA )?(PUBLIC|PRIVATE) KEY-+$/m,
            re_end  = /^-+END (?:RSA )?(PUBLIC|PRIVATE) KEY-+$/m;
        if ( key.match(re_begin) && key.match(re_end) ) {
            key = key.replace( re_begin, '' ).replace( re_end, '' ).replace( /\s/g, '' );
            buff = base64_to_bytes(key);
        }
        else {
            buff = string_to_bytes(key);
        }
    }

    var asn1 = ASN1.decode(buff);
    if ( asn1.tag.tagNumber === 16 ) {
        var re_bitlen = /\([^)]+\)\s?/;

        if ( asn1.sub && asn1.sub[0] && asn1.sub[0].sub && asn1.sub[0].sub[0].tag.tagNumber === 6 && asn1.sub[0].sub[0].content() === '1.2.840.113549.1.1.1' ) {
            var m, e;

            if ( asn1.sub[1] && asn1.sub[1].sub && asn1.sub[1].sub[0].sub ) {
                m = new Modulus( asn1.sub[1].sub[0].sub[0].content().replace( re_bitlen, '' ) );
            } else {
                throw new IllegalArgumentError("malformed RSA public key");
            }

            if ( asn1.sub[1] && asn1.sub[1].sub && asn1.sub[1].sub[0].sub && asn1.sub[1].sub[0].sub[1] ) {
                e = new BigNumber( asn1.sub[1].sub[0].sub[1].content().replace( re_bitlen, '' ) );
            } else {
                throw new IllegalArgumentError("malformed RSA public key");
            }

            return [ m, e ];
        }
        else if ( asn1.sub.length === 9 ) {
            var m, e, d, p, q, dp, dq, u;

            if ( asn1.sub[1].tag.tagNumber === 2 ) {
                m = new Modulus( asn1.sub[1].content().replace( re_bitlen, '' ) );
            } else {
                throw new IllegalArgumentError("malformed RSA private key");
            }

            if ( asn1.sub[2].tag.tagNumber === 2 ) {
                e = new BigNumber( asn1.sub[2].content().replace( re_bitlen, '' ) );
            } else {
                throw new IllegalArgumentError("malformed RSA private key");
            }

            if ( asn1.sub[3].tag.tagNumber === 2 ) {
                d = new BigNumber( asn1.sub[3].content().replace( re_bitlen, '' ) );
            } else {
                throw new IllegalArgumentError("malformed RSA private key");
            }

            if ( asn1.sub[4].tag.tagNumber === 2 ) {
                p = new Modulus( asn1.sub[4].content().replace( re_bitlen, '' ) );
            } else {
                throw new IllegalArgumentError("malformed RSA private key");
            }

            if ( asn1.sub[5].tag.tagNumber === 2 ) {
                q = new Modulus( asn1.sub[5].content().replace( re_bitlen, '' ) );
            } else {
                throw new IllegalArgumentError("malformed RSA private key");
            }

            if ( asn1.sub[6].tag.tagNumber === 2 ) {
                dp = new BigNumber( asn1.sub[6].content().replace( re_bitlen, '' ) );
            } else {
                throw new IllegalArgumentError("malformed RSA private key");
            }

            if ( asn1.sub[7].tag.tagNumber === 2 ) {
                dq = new BigNumber( asn1.sub[7].content().replace( re_bitlen, '' ) );
            } else {
                throw new IllegalArgumentError("malformed RSA private key");
            }

            if ( asn1.sub[8].tag.tagNumber === 2 ) {
                u = new BigNumber( asn1.sub[8].content().replace( re_bitlen, '' ) );
            } else {
                throw new IllegalArgumentError("malformed RSA private key");
            }

            return [ m, e, d, p, q, dp, dq, u ];
        }
    }

    throw new IllegalArgumentError("doesn't seem like a RSA key");
}

var RSAPrototype = RSA.prototype;
RSAPrototype.reset = RSA_reset;
RSAPrototype.encrypt = RSA_encrypt;
RSAPrototype.decrypt = RSA_decrypt;
