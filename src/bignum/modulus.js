import {BigNumber_constructor, is_big_number} from './bignum';
import {BigNumber_extGCD, Number_extGCD} from './extgcd';
import {_bigint_asm, _bigint_heap} from './bignum'

/**
 * Modulus
 */
export function Modulus () {
    BigNumber_constructor.apply( this, arguments );

    if ( this.valueOf() < 1 )
        throw new RangeError();

    if ( this.bitLength <= 32 )
        return;

    var comodulus;

    if ( this.limbs[0] & 1 ) {
        var bitlen = ( (this.bitLength+31) & -32 ) + 1, limbs = new Uint32Array( (bitlen+31) >> 5 );
        limbs[limbs.length-1] = 1;
        comodulus = new BigNumber_constructor();
        comodulus.sign = 1;
        comodulus.bitLength = bitlen;
        comodulus.limbs = limbs;

        var k = Number_extGCD( 0x100000000, this.limbs[0] ).y;
        this.coefficient = k < 0 ? -k : 0x100000000-k;
    }
    else {
        /**
         * TODO even modulus reduction
         * Modulus represented as `N = 2^U * V`, where `V` is odd and thus `GCD(2^U, V) = 1`.
         * Calculation `A = TR' mod V` is made as for odd modulo using Montgomery method.
         * Calculation `B = TR' mod 2^U` is easy as modulus is a power of 2.
         * Using Chinese Remainder Theorem and Garner's Algorithm restore `TR' mod N` from `A` and `B`.
         */
        return;
    }

    this.comodulus = comodulus;
    this.comodulusRemainder = comodulus.divide(this).remainder;
    this.comodulusRemainderSquare = comodulus.square().divide(this).remainder;
}

/**
 * Modular reduction
 */
function Modulus_reduce ( a ) {
    if ( !is_big_number(a) )
        a = new BigNumber_constructor(a);

    if ( a.bitLength <= 32 && this.bitLength <= 32 )
        return new BigNumber_constructor( a.valueOf() % this.valueOf() );

    if ( a.compare(this) < 0 )
        return a;

    return a.divide(this).remainder;
}

/**
 * Modular inverse
 */
function Modulus_inverse ( a ) {
    a = this.reduce(a);

    var r = BigNumber_extGCD( this, a );
    if ( r.gcd.valueOf() !== 1 ) return null;

    r = r.y;
    if ( r.sign < 0 ) r = r.add(this).clamp(this.bitLength);

    return r;
}

/**
 * Modular exponentiation
 */
function Modulus_power ( g, e ) {
    if ( !is_big_number(g) )
        g = new BigNumber_constructor(g);

    if ( !is_big_number(e) )
        e = new BigNumber_constructor(e);

    // count exponent set bits
    var c = 0;
    for ( var i = 0; i < e.limbs.length; i++ ) {
        var t = e.limbs[i];
        while ( t ) {
            if ( t & 1 ) c++;
            t >>>= 1;
        }
    }

    // window size parameter
    var k = 8;
    if ( e.bitLength <= 4536 ) k = 7;
    if ( e.bitLength <= 1736 ) k = 6;
    if ( e.bitLength <= 630 ) k = 5;
    if ( e.bitLength <= 210 ) k = 4;
    if ( e.bitLength <= 60 ) k = 3;
    if ( e.bitLength <= 12 ) k = 2;
    if ( c <= (1 << (k-1)) ) k = 1;

    // montgomerize base
    g = _Montgomery_reduce( this.reduce(g).multiply(this.comodulusRemainderSquare), this );

    // precompute odd powers
    var g2 = _Montgomery_reduce( g.square(), this ),
        gn = new Array( 1 << (k-1) );
    gn[0] = g;
    gn[1] = _Montgomery_reduce( g.multiply(g2), this );
    for ( var i = 2; i < (1 << (k-1)); i++ ) {
        gn[i] = _Montgomery_reduce( gn[i-1].multiply(g2), this );
    }

    // perform exponentiation
    var u = this.comodulusRemainder,
        r = u;
    for ( var i = e.limbs.length-1; i >= 0; i-- ) {
        var t = e.limbs[i];
        for ( var j = 32; j > 0; ) {
            if ( t & 0x80000000 ) {
                var n = t >>> (32-k), l = k;
                while ( (n & 1) === 0 ) { n >>>= 1; l--; }
                var m = gn[n>>>1];
                while ( n ) { n >>>= 1; if ( r !== u ) r = _Montgomery_reduce( r.square(), this ); }
                r = ( r !== u ) ? _Montgomery_reduce( r.multiply(m), this ) : m;
                t <<= l, j -= l;
            }
            else {
                if ( r !== u ) r = _Montgomery_reduce( r.square(), this );
                t <<= 1, j--;
            }
        }
    }

    // de-montgomerize result
    r = _Montgomery_reduce( r, this );

    return r;
}

function _Montgomery_reduce ( a, n ) {
    var alimbs = a.limbs, alimbcnt = alimbs.length,
        nlimbs = n.limbs, nlimbcnt = nlimbs.length,
        y = n.coefficient;

    _bigint_asm.sreset();

    var pA = _bigint_asm.salloc( alimbcnt<<2 ),
        pN = _bigint_asm.salloc( nlimbcnt<<2 ),
        pR = _bigint_asm.salloc( nlimbcnt<<2 );

    _bigint_asm.z( pR-pA+(nlimbcnt<<2), 0, pA );

    _bigint_heap.set( alimbs, pA>>2 );
    _bigint_heap.set( nlimbs, pN>>2 );

    _bigint_asm.mredc( pA, alimbcnt<<2, pN, nlimbcnt<<2, y, pR );

    var result = new BigNumber_constructor();
    result.limbs = new Uint32Array( _bigint_heap.subarray( pR>>2, (pR>>2)+nlimbcnt ) );
    result.bitLength = n.bitLength;
    result.sign = 1;

    return result;
}

var ModulusPrototype = Modulus.prototype = new BigNumber_constructor;
ModulusPrototype.reduce = Modulus_reduce;
ModulusPrototype.inverse = Modulus_inverse;
ModulusPrototype.power = Modulus_power;
