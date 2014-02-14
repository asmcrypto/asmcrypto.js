var _bigint_heap = new Uint32Array(0x100000),
    _bigint_asm = bigint_asm( global, null, _bigint_heap.buffer );

///////////////////////////////////////////////////////////////////////////////

var _bignum_zero_limbs = new Uint32Array(8);

function bignum_constructor ( num, radix ) {
    var limbs = _bignum_zero_limbs,
        bitLength = 0,
        sign = 0;

    if ( typeof num === 'undefined' ) {
        // do nothing
    }
    else if ( typeof num === 'number' ) {
        var anum = Math.abs(num);
        if ( anum > 0xffffffff ) {
            limbs = new Uint32Array(8);
            limbs[0] = num|0;
            limbs[1] = (num/0x100000000)|0;
            bitLength = 52;
            sign = ( num < 0 ? -1 : 1 );
        }
        else if ( num < 0 ) {
            limbs = new Uint32Array(8);
            limbs[0] = num|0;
            bitLength = 31;
            sign = -1;
        }
        else if ( anum > 0 ) {
            limbs = new Uint32Array(8);
            limbs[0] = num|0;
            bitLength = 32;
            sign = 1;
        }
    }
    else if ( num instanceof bignum_constructor ) {
        limbs = new Uint32Array( num.limbs );
        bitLength = num.bitLength;
    }
    else if ( typeof num === 'string' ) {
        switch ( radix || 16 ) {
            case 16:
                _bignum_fromHexString.call( this, num );
                return;

            default:
                throw new IllegalArgumentError("bad radix");
        }
    }
/*
    else if ( num instanceof ArrayBuffer || num instanceof Uint8Array ) {
        limbs = _bignum_parseBuffer(num);
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

function _bignum_fromHexString ( str ) {
    var bitlen = 0, sign = 0, limbs;

    str = str.toUpperCase().replace( /[^0-9A-F]/g, '' ).replace( /^0+/, '' );

    bitlen = str.length * 4;

    if ( bitlen > 0 ) {
        if ( str.length % 8 ) {
            str = ( '00000000'.substr( str.length % 8 ) ) + str;
        }

        limbs = new Uint32Array( pow2_ceil( (bitlen + 255) >> 8 << 3 ) );
        for ( var i = 0; i < str.length; i += 8 ) {
            limb = parseInt( str.substr(i, 8), 16 );
            limbs[(str.length-i-8)>>3] = limb;
        }

        sign = 1;
    }

    this.limbs = limbs;
    this.bitLength = bitlen;
    this.sign = sign;
}

/*
function _bignum_parseBuffer ( buff ) {
}
*/

function bignum_toString ( radix ) {
    radix = radix || 16;

    if ( this.sign < 0 )
        return '-' + this.negate().toString(radix);

    var limbs = this.limbs,
        bitlen = this.bitLength,
        str = '';

    if ( radix === 16 ) {
        for ( var i = (bitlen+31>>5)-1; i >= 0; i-- ) {
            var h = limbs[i].toString(16);
            str += '00000000'.substr(h.length);
            str += h;
        }
        if ( !str.length )
            str = '0';
    }
    else {
        throw new IllegalArgumentError("bad radix");
    }

    return str;
}

// Downgrade to Number
function bignum_valueOf () {
    var limbs = this.limbs,
        bits = this.bitLength,
        sign = this.sign;

    if ( !sign )
        return 0;

    if ( sign < 0 )
        return '-' + this.negate().valueOf();

    if ( bits <= 32 )
        return limbs[0]>>>0;

    if ( bits <= 52 )
        return 0x100000000 * (limbs[1]>>>0) + (limbs[0]>>>0);

    // normalization
    var i, l, e = 0;
    for ( i = limbs.length-1; i >= 0; i-- ) {
        if ( (l = limbs[i]) === 0 ) continue;
        while ( ( (l << e) & 0x80000000 ) === 0 ) e++;
        break;
    }

    if ( i === 0 )
        return limbs[0]>>>0;

    return ( 0x100000 * (( (limbs[i] << e) | ( e ? limbs[i-1] >>> (32-e) : 0 ) )>>>0)
                      + ((limbs[i-1] << e)>>>0) ) * Math.pow( 2, 32*i-e );
}

function bignum_clamp ( b ) {
    var bitlen = this.bitLength,
        sign = this.sign,
        n = (b + 31) >> 5,
        k = b % 32;

    if ( b >= bitlen )
        return this;

    var limbs = new Uint32Array( pow2_ceil( (n+7) & -8 ) );
    limbs.set( this.limbs.subarray(0,n), 0 );
    if ( sign < 0 ) {
        if ( k ) limbs[n-1] |= -1 << k;
        for ( var i = n; i < limbs.length; i++ ) limbs[i] = -1;
    }
    else {
        if ( k ) limbs[n-1] &= ~(-1 << k);
    }

    var clamped = new bignum_constructor();
    clamped.limbs = limbs;
    clamped.bitLength = b;
    clamped.sign = sign;

    return clamped;
}

///////////////////////////////////////////////////////////////////////////////

function bignum_negate () {
    var limbcnt = this.limbs.length,
        limbs = new Uint32Array(limbcnt),
        negative = new bignum_constructor();

    _bigint_heap.set( this.limbs, 0 );

    _bigint_asm.neg( 0, limbcnt<<2, 0, limbcnt<<2 );

    limbs.set( _bigint_heap.subarray(0, limbcnt) );

    negative.limbs = limbs;
    negative.bitLength = this.bitLength;
    negative.sign = -1 * this.sign;

    return negative;
}

function bignum_compare ( that ) {
    if ( !( that instanceof bignum_constructor ) )
        that = new bignum_constructor(that);

    var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length,
        bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length,
        c;

    if ( this.sign < that.sign )
        return -1;

    if ( this.sign > that.sign )
        return 1;

    _bigint_heap.set( alimbs, 0 );
    _bigint_heap.set( blimbs, alimbcnt );
    c = _bigint_asm.cmp( 0, alimbcnt<<2, alimbcnt<<2, blimbcnt<<2 );

    return c * this.sign;
}

function bignum_add ( that ) {
    if ( !( that instanceof bignum_constructor ) )
        that = new bignum_constructor(that);

    if ( !this.sign )
        return that;

    if ( !that.sign )
        return this;

    var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length,
        bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length,
        result = new bignum_constructor(),
        rbitlen, rlimbs, rlimbcnt;

    _bigint_heap.set( alimbs, 0 );
    _bigint_heap.set( blimbs, alimbcnt );

    _bigint_asm.add( 0, alimbcnt<<2, alimbcnt<<2, blimbcnt<<2, (alimbcnt+blimbcnt)<<2, -1 );

    rbitlen = ( abitlen > bbitlen ? abitlen : bbitlen ) + 1;
    rlimbcnt = ( rbitlen + 255 ) >> 8 << 3;
    rlimbs = new Uint32Array( pow2_ceil(rlimbcnt) );
    rlimbs.set( _bigint_heap.subarray(alimbcnt+blimbcnt, alimbcnt+blimbcnt+rlimbcnt) );
    if ( rlimbcnt < rlimbs.length ) {
        rlimbs[rlimbcnt] = (rlimbs[rlimbcnt-1]|0) < 0 ? -1 : 0;
        for ( var i = rlimbcnt+1; i < rlimbs.length; i++ ) rlimbs[i] = rlimbs[rlimbcnt];
    }

    result.bitLength = rbitlen;
    result.limbs = rlimbs;

    return result;
}

function bignum_subtract ( that ) {
    if ( !( that instanceof bignum_constructor ) )
        that = new bignum_constructor(that);

    if ( !this.sign )
        return that.negate();

    if ( !that.sign )
        return this;

    var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length,
        bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length,
        result = new bignum_constructor(),
        rbitlen, rlimbs, rlimbcnt, rc;

    _bigint_heap.set( alimbs, 0 );
    _bigint_heap.set( blimbs, alimbcnt );
    rc = _bigint_asm.sub( 0, alimbcnt<<2, alimbcnt<<2, blimbcnt<<2, (alimbcnt+blimbcnt)<<2, -1 );

    rbitlen = ( abitlen > bbitlen ? abitlen : bbitlen );
    if ( this.sign * that.sign < 0 ) rbitlen++;
    rlimbcnt = ( rbitlen + 255 ) >> 8 << 3;
    rlimbs = new Uint32Array( pow2_ceil(rlimbcnt) );
    rlimbs.set( _bigint_heap.subarray(alimbcnt+blimbcnt, alimbcnt+blimbcnt+rlimbcnt) );
    if ( rlimbcnt < rlimbs.length ) {
        rlimbs[rlimbcnt] = (rlimbs[rlimbcnt-1]|0) < 0 ? -1 : 0;
        for ( var i = rlimbcnt+1; i < rlimbs.length; i++ ) rlimbs[i] = rlimbs[rlimbcnt];
    }

    result.bitLength = rbitlen;
    result.limbs = rlimbs;
    result.sign = ( rc ? -1 : 1 ) * this.sign;

    return result;
}

function bignum_multiply ( that ) {
    if ( !( that instanceof bignum_constructor ) )
        that = new bignum_constructor(that);

    var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length,
        bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length,
        result = new bignum_constructor(),
        rlimbs, rbitlen, rlimbcnt, rsign = 0;

    _bigint_heap.set( alimbs, 0 );
    if ( this.sign < 0 ) _bigint_asm.neg( 0, alimbcnt<<2, 0, alimbcnt<<2 );

    _bigint_heap.set( blimbs, alimbcnt );
    if ( that.sign < 0 ) _bigint_asm.neg( alimbcnt<<2, blimbcnt<<2, alimbcnt<<2, blimbcnt<<2 );

    rbitlen = abitlen + bbitlen;
    rlimbcnt = ( rbitlen + 255 ) >> 8 << 3;
    _bigint_asm.mul( 0, alimbcnt<<2, alimbcnt<<2, blimbcnt<<2, (alimbcnt+blimbcnt)<<2, rlimbcnt<<2 );

    rlimbs = new Uint32Array( pow2_ceil(rlimbcnt) );

    rsign = this.sign * that.sign;
    if ( rsign < 0 ) {
        _bigint_asm.neg( (alimbcnt+blimbcnt)<<2, rlimbcnt<<2, (alimbcnt+blimbcnt)<<2, rlimbcnt<<2 );
        for ( var i = 0; i < rlimbs.length; i++ ) rlimbs[i] = -1;
    }

    rlimbs.set( _bigint_heap.subarray(alimbcnt+blimbcnt, alimbcnt+blimbcnt+rlimbcnt) );

    result.bitLength = rbitlen;
    result.limbs = rlimbs;
    result.sign = rsign;

    return result;
}

function bignum_square () {
    var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length,
        result = new bignum_constructor(),
        rlimbs, rbitlen, rlimbcnt;

    _bigint_heap.set( alimbs, 0 );
    if ( this.sign < 0 ) _bigint_asm.neg( 0, alimbcnt<<2, 0, alimbcnt<<2 );

    _bigint_asm.sqr( 0, alimbcnt<<2, alimbcnt<<2 );

    rbitlen = abitlen << 1;
    rlimbcnt = alimbcnt << 1;
    rlimbs = new Uint32Array(rlimbcnt);
    rlimbs.set( _bigint_heap.subarray(alimbcnt, 3*alimbcnt) );

    result.bitLength = rbitlen;
    result.limbs = rlimbs;
    result.sign = 1;

    return result;
}

function bignum_divide ( that ) {
    if ( !( that instanceof bignum_constructor ) )
        that = new bignum_constructor(that);

    var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length,
        bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length,
        quotient = bignum_zero,
        remainder = bignum_zero,
        qlimbcnt, qlimbs, qsign,
        rlimbcnt, rlimbs;

    _bigint_heap.set( alimbs, 0 );
    if ( this.sign < 0 ) _bigint_asm.neg( 0, alimbcnt<<2, 0, alimbcnt<<2 );

    _bigint_heap.set( blimbs, alimbcnt );
    if ( that.sign < 0 ) _bigint_asm.neg( alimbcnt<<2, blimbcnt<<2, alimbcnt<<2, blimbcnt<<2 );

    qlimbcnt = _bigint_asm.div( 0, alimbcnt<<2, alimbcnt<<2, blimbcnt<<2, (alimbcnt+blimbcnt)<<2, (alimbcnt+2*blimbcnt)<<2 )>>2;
    rlimbcnt = (bbitlen + 31) >>> 5;

    if ( _bigint_asm.tst( (alimbcnt+2*blimbcnt)<<2, alimbcnt<<2 ) ) {
        qsign = this.sign * that.sign;
        if ( qsign < 0 ) _bigint_asm.neg( (alimbcnt+2*blimbcnt)<<2, alimbcnt<<2, (alimbcnt+2*blimbcnt)<<2, alimbcnt<<2 );

        qlimbs = new Uint32Array( pow2_ceil((qlimbcnt + 7) & -8) );
        qlimbs.set( _bigint_heap.subarray(alimbcnt+2*blimbcnt, alimbcnt+2*blimbcnt+qlimbcnt) );

        quotient = new bignum_constructor();
        quotient.bitLength = abitlen;
        quotient.limbs = qlimbs;
        quotient.sign = qsign;
    }

    if ( _bigint_asm.tst( (alimbcnt+blimbcnt)<<2, blimbcnt<<2 ) ) {
        rsign = this.sign;
        if ( rsign < 0 ) _bigint_asm.neg( (alimbcnt+blimbcnt)<<2, blimbcnt<<2, (alimbcnt+blimbcnt)<<2, blimbcnt<<2 );

        rlimbs = new Uint32Array(blimbcnt);
        rlimbs.set( _bigint_heap.subarray(alimbcnt+blimbcnt, alimbcnt+blimbcnt+rlimbcnt) );

        remainder = new bignum_constructor();
        remainder.bitLength = bbitlen;
        remainder.limbs = rlimbs;
        remainder.sign = rsign;
    }

    return {
        quotient: quotient,
        remainder: remainder
    };
}

///////////////////////////////////////////////////////////////////////////////

var bignum_prototype = bignum_constructor.prototype = new Number;
bignum_prototype.toString = bignum_toString;
bignum_prototype.valueOf = bignum_valueOf;
bignum_prototype.clamp = bignum_clamp;

bignum_prototype.negate = bignum_negate;
bignum_prototype.compare = bignum_compare;
bignum_prototype.add = bignum_add;
bignum_prototype.subtract = bignum_subtract;
bignum_prototype.multiply = bignum_multiply;
bignum_prototype.square = bignum_square;
bignum_prototype.divide = bignum_divide;

///////////////////////////////////////////////////////////////////////////////

var bignum_zero = new bignum_constructor(0),
    bignum_one  = new bignum_constructor(1);

Object.freeze(bignum_zero);
Object.freeze(bignum_one);
