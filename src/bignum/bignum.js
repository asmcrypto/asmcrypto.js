function is_big_number ( a ) {
    return ( a instanceof BigNumber );
}

///////////////////////////////////////////////////////////////////////////////

var _bigint_heap = new Uint32Array(0x100000),
    _bigint_asm = bigint_asm( global, null, _bigint_heap.buffer );

///////////////////////////////////////////////////////////////////////////////

var _BigNumber_ZERO_limbs = new Uint32Array(0);

function BigNumber ( num ) {
    var limbs = _BigNumber_ZERO_limbs,
        bitlen = 0,
        sign = 0;

    if ( is_string(num) )
        num = string_to_bytes(num);

    if ( is_buffer(num) )
        num = new Uint8Array(num);

    if ( num === undefined ) {
        // do nothing
    }
    else if ( is_number(num) ) {
        var absnum = Math.abs(num);
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
        sign = num < 0 ? -1 : 1;
    }
    else if ( is_bytes(num) ) {
        bitlen = num.length * 8;
        if ( !bitlen )
            return BigNumber_ZERO;

        limbs = new Uint32Array( (bitlen + 31) >> 5 );
        for ( var i = num.length-4; i >= 0 ; i -= 4 ) {
            limbs[(num.length-4-i)>>2] = (num[i] << 24) | (num[i+1] << 16) | (num[i+2] << 8) | num[i+3];
        }
        if ( i === -3 ) {
            limbs[limbs.length-1] = num[0];
        }
        else if ( i === -2 ) {
            limbs[limbs.length-1] = (num[0] << 8) | num[1];
        }
        else if ( i === -1 ) {
            limbs[limbs.length-1] = (num[0] << 16) | (num[1] << 8) | num[2];
        }

        sign = 1;
    }
    else if ( typeof num === 'object' && num !== null ) {
        limbs = new Uint32Array( num.limbs );
        bitlen = num.bitLength;
        sign = num.sign;
    }
    else {
        throw new TypeError("number is of unexpected type");
    }

    this.limbs = limbs;
    this.bitLength = bitlen;
    this.sign = sign;
}

function BigNumber_toString ( radix ) {
    radix = radix || 16;

    var limbs = this.limbs,
        bitlen = this.bitLength,
        str = '';

    if ( radix === 16 ) {
        // FIXME clamp last limb to (bitlen % 32)
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

function BigNumber_toBytes () {
    var bitlen = this.bitLength,
        limbs = this.limbs;

    if ( bitlen === 0 )
        return new Uint8Array(0);

    var bytelen = ( bitlen + 7 ) >> 3,
        bytes = new Uint8Array(bytelen);
    for ( var i = 0; i < bytelen; i++ ) {
        var j = bytelen - i - 1;
        bytes[i] = limbs[j>>2] >> ( (j & 3) << 3 );
    }

    return bytes;
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

function BigNumber_slice ( f, b ) {
    if ( !is_number(f) )
        throw new TypeError("TODO");

    if ( b !== undefined && !is_number(b) )
        throw new TypeError("TODO");

    var limbs = this.limbs,
        bitlen = this.bitLength;

    if ( f < 0 )
        throw new RangeError("TODO");

    if ( f >= bitlen )
        return BigNumber_ZERO;

    if ( b === undefined || b > bitlen - f )
        b = bitlen - f;

    var sliced = new BigNumber, slimbs,
        n = f >> 5, m = (f + b + 31) >> 5, l = (b + 31) >> 5,
        t = f % 32, k = b % 32;

    slimbs = new Uint32Array(l);
    if ( t ) {
        for ( var i = 0; i < m-n-1; i++ ) {
            slimbs[i] = (limbs[n+i]>>>t) | ( limbs[n+i+1]<<(32-t) );
        }
        slimbs[i] = limbs[n+i]>>>t;
    }
    else {
        slimbs.set( limbs.subarray(n, m) );
    }

    if ( k ) {
        slimbs[l-1] &= (-1 >>> (32-k));
    }

    sliced.limbs = slimbs
    sliced.bitLength = b;
    sliced.sign = this.sign;

    return sliced;
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
    if ( !is_big_number(that) )
        that = new BigNumber(that);

    var alimbs = this.limbs, alimbcnt = alimbs.length,
        blimbs = that.limbs, blimbcnt = blimbs.length,
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
    if ( !is_big_number(that) )
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

    _bigint_asm.z( pR-pA+(rlimbcnt<<2), 0, pA );

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
    if ( !is_big_number(that) )
        that = new BigNumber(that);

    return this.add( that.negate() );
}

function BigNumber_multiply ( that ) {
    if ( !is_big_number(that) )
        that = new BigNumber(that);

    if ( !this.sign || !that.sign )
        return BigNumber_ZERO;

    var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length,
        bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length,
        rbitlen, rlimbcnt, result = new BigNumber;

    rbitlen = abitlen + bbitlen;
    rlimbcnt = ( rbitlen + 31 ) >> 5;

    _bigint_asm.sreset();

    var pA = _bigint_asm.salloc( alimbcnt<<2 ),
        pB = _bigint_asm.salloc( blimbcnt<<2 ),
        pR = _bigint_asm.salloc( rlimbcnt<<2 );

    _bigint_asm.z( pR-pA+(rlimbcnt<<2), 0, pA );

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

    _bigint_asm.z( pR-pA+(rlimbcnt<<2), 0, pA );

    _bigint_heap.set( alimbs, pA>>2 );

    _bigint_asm.sqr( pA, alimbcnt<<2, pR );

    result.limbs = new Uint32Array( _bigint_heap.subarray( pR>>2, (pR>>2)+rlimbcnt ) );
    result.bitLength = rbitlen;
    result.sign = 1;

    return result;
}

function BigNumber_divide ( that ) {
    if ( !is_big_number(that) )
        that = new BigNumber(that);

    var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length,
        bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length,
        qlimbcnt, rlimbcnt, quotient = BigNumber_ZERO, remainder = BigNumber_ZERO;

    _bigint_asm.sreset();

    var pA = _bigint_asm.salloc( alimbcnt<<2 ),
        pB = _bigint_asm.salloc( blimbcnt<<2 ),
        pR = _bigint_asm.salloc( blimbcnt<<2 ),
        pQ = _bigint_asm.salloc( alimbcnt<<2 );

    _bigint_asm.z( pQ-pA+(alimbcnt<<2), 0, pA );

    _bigint_heap.set( alimbs, pA>>2 );
    _bigint_heap.set( blimbs, pB>>2 );

    _bigint_asm.div( pA, alimbcnt<<2, pB, blimbcnt<<2, pR, pQ );

    qlimbcnt = _bigint_asm.tst( pQ, alimbcnt<<2 )>>2;
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
BigNumberPrototype.toBytes = BigNumber_toBytes;
BigNumberPrototype.valueOf = BigNumber_valueOf;
BigNumberPrototype.clamp = BigNumber_clamp;
BigNumberPrototype.slice = BigNumber_slice;

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
