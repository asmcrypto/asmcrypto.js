var _bigint_heap = new Uint32Array(0x100000),
    _bigint_asm = bigint_asm( global, null, _bigint_heap.buffer );

///////////////////////////////////////////////////////////////////////////////

var _BigNumber_ZERO_limbs = new Uint32Array(0);

function BigNumber ( num, radix ) {
    var limbs = _BigNumber_ZERO_limbs,
        bitLength = 0,
        sign = 0;

    if ( typeof num === 'undefined' ) {
        // do nothing
    }
    else if ( typeof num === 'number' ) {
        return _BigNumber_fromNumber.call( this, num );
    }
    else if ( typeof num === 'string' ) {
        switch ( radix || 16 ) {
            case 16:
                return _BigNumber_fromHexString.call( this, num );

            default:
                throw new IllegalArgumentError("bad radix");
        }
    }
    else if ( typeof num === 'object' && num !== null ) {
        limbs = new Uint32Array( num.limbs );
        bitLength = num.bitLength;
        sign = num.sign;
    }
/*
    else if ( num instanceof ArrayBuffer || num instanceof Uint8Array ) {
        limbs = _BigNumber_fromBuffer(num);
        bitLength = 32*(limbs.length-1);
    }
*/
    else {
        throw new TypeError("number is of unexpected type");
    }

    this.limbs = limbs;
    this.bitLength = bitLength;
    this.sign = sign;
}

function _BigNumber_fromNumber ( num ) {
    var absnum = Math.abs(num),
        limbs, biglen;

    if ( absnum > 0xffffffff ) {
        limbs = new Uint32Array(2);
        limbs[0] = absnum|0;
        limbs[1] = (absnum/0x100000000)|0;
        bitlen = 52;
    }
    else if ( absnum > 0 ) {
        limbs = new Uint32Array(1);
        limbs[0] = absnum;
        bitlen = 32;
    }
    else {
        limbs = _BigNumber_ZERO_limbs;
        bitlen = 0;
    }

    this.limbs = limbs;
    this.bitLength = bitlen;
    this.sign = ( num <= 0 ? num < 0 ? -1 : 0 : 1 );

    return this;
}

function _BigNumber_fromHexString ( str ) {
    var bitlen = 0, sign = 0, limbs;

    str = str.toUpperCase().replace( /[^0-9A-F]/g, '' ).replace( /^0+/, '' );

    bitlen = str.length * 4;

    if ( bitlen > 0 ) {
        if ( str.length % 8 ) {
            str = ( '00000000'.substr( str.length % 8 ) ) + str;
        }

        limbs = new Uint32Array( (bitlen + 31) >> 5 );
        for ( var i = 0; i < str.length; i += 8 ) {
            limb = parseInt( str.substr(i, 8), 16 );
            limbs[(str.length-i-8)>>3] = limb;
        }

        sign = 1;
    }
    else {
        return BigNumber_ZERO;
    }

    this.limbs = limbs;
    this.bitLength = bitlen;
    this.sign = sign;

    return this;
}

/*
function _BigNumber_fromBuffer ( buff ) {
}
*/

function BigNumber_toString ( radix ) {
    radix = radix || 16;

    var limbs = this.limbs,
        bitlen = this.bitLength,
        str = '';

    if ( radix === 16 ) {
        for ( var i = (bitlen+31>>5)-1; i >= 0; i-- ) {
            var h = limbs[i].toString(16);
            str += '00000000'.substr(h.length);
            str += h;
        }

        str = str.replace( /^0+/, '' );

        if ( !str.length )
            str = '0';
    }
    else {
        throw new IllegalArgumentError("bad radix");
    }

    if ( this.sign < 0 )
        str = '-' + str;

    return str;
}

// Downgrade to Number
function BigNumber_valueOf () {
    var limbs = this.limbs,
        bits = this.bitLength,
        sign = this.sign;

    if ( !sign )
        return 0;

    if ( bits <= 32 )
        return sign * (limbs[0]>>>0);

    if ( bits <= 52 )
        return sign * ( 0x100000000 * (limbs[1]>>>0) + (limbs[0]>>>0) );

    // normalization
    var i, l, e = 0;
    for ( i = limbs.length-1; i >= 0; i-- ) {
        if ( (l = limbs[i]) === 0 ) continue;
        while ( ( (l << e) & 0x80000000 ) === 0 ) e++;
        break;
    }

    if ( i === 0 )
        return sign * (limbs[0]>>>0);

    return sign * ( 0x100000 * (( (limbs[i] << e) | ( e ? limbs[i-1] >>> (32-e) : 0 ) )>>>0)
                             + (( (limbs[i-1] << e) | ( e && i > 1 ? limbs[i-2] >>> (32-e) : 0 ) )>>>12)
                  ) * Math.pow( 2, 32*i-e-52 );
}

function BigNumber_clamp ( b ) {
    var limbs = this.limbs,
        bitlen = this.bitLength;

    // FIXME check b is number and in a valid range

    if ( b >= bitlen )
        return this;

    var clamped = new BigNumber,
        n = (b + 31) >> 5,
        k = b % 32;

    clamped.limbs = new Uint32Array( limbs.subarray(0,n) );
    clamped.bitLength = b;
    clamped.sign = this.sign;

    if ( k ) clamped.limbs[n-1] &= (-1 >>> (32-k));

    return clamped;
}

function BigNumber_splice ( f, b ) {
    var limbs = this.limbs,
        bitlen = this.bitLength;

    // FIXME check f is number and in a valid range
    // FIXME check b is number and in a valid range

    if ( b === undefined )
        b = bitlen - f;

    if ( f === 0 )
        return this.clamp(b);

    var spliced = new BigNumber, slimbs,
        n = f >> 5, m = (f + b + 31) >> 5,
        t = f % 32, k = b % 32;

    slimbs = new Uint32Array( limbs.subarray(n,m) ),

    spliced.limbs = slimbs
    spliced.bitLength = b;
    spliced.sign = this.sign;

    if ( k ) slimbs[m-n-1] &= (-1 >>> (32-k));

    return spliced;
}

///////////////////////////////////////////////////////////////////////////////

function BigNumber_negate () {
    var negative = new BigNumber;

    negative.limbs = this.limbs;
    negative.bitLength = this.bitLength;
    negative.sign = -1 * this.sign;

    return negative;
}

function BigNumber_compare ( that ) {
    if ( !( that instanceof BigNumber ) )
        that = new BigNumber(that);

    var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length,
        bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length,
        z = 0;

    if ( this.sign < that.sign )
        return -1;

    if ( this.sign > that.sign )
        return 1;

    _bigint_heap.set( alimbs, 0 );
    _bigint_heap.set( blimbs, alimbcnt );
    z = _bigint_asm.cmp( 0, alimbcnt<<2, alimbcnt<<2, blimbcnt<<2 );

    return z * this.sign;
}

function BigNumber_add ( that ) {
    if ( !( that instanceof BigNumber ) )
        that = new BigNumber(that);

    if ( !this.sign )
        return that;

    if ( !that.sign )
        return this;

    var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length, asign = this.sign,
        bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length, bsign = that.sign,
        rbitlen, rlimbcnt, rsign, rof, result = new BigNumber;

    rbitlen = ( abitlen > bbitlen ? abitlen : bbitlen ) + 1;
    rlimbcnt = ( rbitlen + 31 ) >> 5;

    _bigint_asm.sreset();

    var pA = _bigint_asm.salloc( alimbcnt<<2 ),
        pB = _bigint_asm.salloc( blimbcnt<<2 ),
        pR = _bigint_asm.salloc( rlimbcnt<<2 );

    _bigint_asm.z( pR-pA, 0, pA );

    _bigint_heap.set( alimbs, pA>>2 );
    _bigint_heap.set( blimbs, pB>>2 );

    if ( asign * bsign > 0 ) {
        _bigint_asm.add( pA, alimbcnt<<2, pB, blimbcnt<<2, pR, rlimbcnt<<2 );
        rsign = asign;
    }
    else if ( asign > bsign ) {
        rof = _bigint_asm.sub( pA, alimbcnt<<2, pB, blimbcnt<<2, pR, rlimbcnt<<2 );
        rsign = rof ? bsign : asign;
    }
    else {
        rof = _bigint_asm.sub( pB, blimbcnt<<2, pA, alimbcnt<<2, pR, rlimbcnt<<2 );
        rsign = rof ? asign : bsign;
    }

    if ( rof )
        _bigint_asm.neg( pR, rlimbcnt<<2, pR, rlimbcnt<<2 );

    if ( _bigint_asm.tst( pR, rlimbcnt<<2 ) === 0 )
        return BigNumber_ZERO;

    result.limbs = new Uint32Array( _bigint_heap.subarray( pR>>2, (pR>>2)+rlimbcnt ) );
    result.bitLength = rbitlen;
    result.sign = rsign;

    return result;
}

function BigNumber_subtract ( that ) {
    if ( !( that instanceof BigNumber ) )
        that = new BigNumber(that);

    return this.add( that.negate() );
}

function BigNumber_multiply ( that ) {
    if ( !( that instanceof BigNumber ) )
        that = new BigNumber(that);

    if ( !this.sign || !that.sign )
        return BigNumber_ZERO;

    var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length,
        bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length,
        rbitlen, rlimbcnt, rsign = 0, result = new BigNumber;

    rbitlen = abitlen + bbitlen;
    rlimbcnt = ( rbitlen + 31 ) >> 5;

    _bigint_asm.sreset();

    var pA = _bigint_asm.salloc( alimbcnt<<2 ),
        pB = _bigint_asm.salloc( blimbcnt<<2 ),
        pR = _bigint_asm.salloc( rlimbcnt<<2 );

    _bigint_asm.z( pR-pA, 0, pA );

    _bigint_heap.set( alimbs, pA>>2 );
    _bigint_heap.set( blimbs, pB>>2 );

    _bigint_asm.mul( pA, alimbcnt<<2, pB, blimbcnt<<2, pR, rlimbcnt<<2 );

    result.limbs = new Uint32Array( _bigint_heap.subarray( pR>>2, (pR>>2)+rlimbcnt ) );
    result.sign = this.sign * that.sign;
    result.bitLength = rbitlen;

    return result;
}

function BigNumber_square () {
    if ( !this.sign )
        return BigNumber_ZERO;

    var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length,
        rbitlen, rlimbcnt, result = new BigNumber;

    rbitlen = abitlen << 1;
    rlimbcnt = ( rbitlen + 31 ) >> 5;

    _bigint_asm.sreset();

    var pA = _bigint_asm.salloc( alimbcnt<<2 ),
        pR = _bigint_asm.salloc( rlimbcnt<<2 );

    _bigint_asm.z( pR-pA, 0, pA );

    _bigint_heap.set( alimbs, pA>>2 );

    _bigint_asm.sqr( pA, alimbcnt<<2, pR );

    result.limbs = new Uint32Array( _bigint_heap.subarray( pR>>2, (pR>>2)+rlimbcnt ) );
    result.bitLength = rbitlen;
    result.sign = 1;

    return result;
}

function BigNumber_divide ( that ) {
    if ( !( that instanceof BigNumber ) )
        that = new BigNumber(that);

    var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length,
        bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length,
        qlimbcnt, rlimbcnt, quotient = BigNumber_ZERO, remainder = BigNumber_ZERO;

    _bigint_asm.sreset();

    var pA = _bigint_asm.salloc( alimbcnt<<2 ),
        pB = _bigint_asm.salloc( blimbcnt<<2 ),
        pR = _bigint_asm.salloc( blimbcnt<<2 ),
        pQ = _bigint_asm.salloc( alimbcnt<<2 );

    _bigint_asm.z( pQ-pA, 0, pA );

    _bigint_heap.set( alimbs, pA>>2 );
    _bigint_heap.set( blimbs, pB>>2 );

    qlimbcnt = _bigint_asm.div( pA, alimbcnt<<2, pB, blimbcnt<<2, pR, pQ )>>2;

    qlimbcnt = _bigint_asm.tst( pQ, qlimbcnt<<2 )>>2;
    if ( qlimbcnt ) {
        quotient = new BigNumber;
        quotient.limbs = new Uint32Array( _bigint_heap.subarray( pQ>>2, (pQ>>2)+qlimbcnt ) );
        quotient.bitLength = abitlen < (qlimbcnt<<5) ? abitlen : (qlimbcnt<<5);
        quotient.sign = this.sign * that.sign;
    }

    rlimbcnt = _bigint_asm.tst( pR, blimbcnt<<2 )>>2;
    if ( rlimbcnt ) {
        remainder = new BigNumber;
        remainder.limbs = new Uint32Array( _bigint_heap.subarray( pR>>2, (pR>>2)+rlimbcnt ) );;
        remainder.bitLength = bbitlen < (rlimbcnt<<5) ? bbitlen : (rlimbcnt<<5);
        remainder.sign = this.sign;
    }

    return {
        quotient: quotient,
        remainder: remainder
    };
}

///////////////////////////////////////////////////////////////////////////////

var BigNumberPrototype = BigNumber.prototype = new Number;
BigNumberPrototype.toString = BigNumber_toString;
BigNumberPrototype.valueOf = BigNumber_valueOf;
BigNumberPrototype.clamp = BigNumber_clamp;
BigNumberPrototype.splice = BigNumber_splice;

///////////////////////////////////////////////////////////////////////////////

BigNumberPrototype.negate = BigNumber_negate;
BigNumberPrototype.compare = BigNumber_compare;
BigNumberPrototype.add = BigNumber_add;
BigNumberPrototype.subtract = BigNumber_subtract;
BigNumberPrototype.multiply = BigNumber_multiply;
BigNumberPrototype.square = BigNumber_square;
BigNumberPrototype.divide = BigNumber_divide;

///////////////////////////////////////////////////////////////////////////////

var BigNumber_ZERO = new BigNumber(0),
    BigNumber_ONE  = new BigNumber(1);

Object.freeze(BigNumber_ZERO);
Object.freeze(BigNumber_ONE);
