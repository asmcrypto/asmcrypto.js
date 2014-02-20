// http://oeis.org/A000043
var _mersenne_exponents = [ 2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433, 1257787, 1398269, 2976221, 3021377, 6972593, 13466917, 20996011, 24036583, 25964951 ];

/**
 * Practical special-form pseudo-Mersenne primes:
 *
 *  P = 2^(32*m) - k
 *
 * such that m = 1,2,… and 0 < k < 2^16 (fits into half-word).
 *
 * Generated with `tools/pmprimes.pl` script
 */
var _pseudo_mersenne_k = [ 0,
    0x0005, 0x003b, 0x0011, 0x009f, 0x002f, 0x00ed, 0x003f, 0x00bd, 0x00a7, 0x00c5, 0x0291, 0x013d, 0x01b3, 0x00cb, 0x002f, 0x0239,
    0x02f7, 0x0315, 0x020f, 0x0131, 0x018f, 0x00f5, 0x01fd, 0x0339, 0x0069, 0x008f, 0x00f3, 0x00d5, 0x0285, 0x00a7, 0x06f3, 0x0069,
    0x02d5, 0x0059, 0x09fb, 0x039f, 0x006b, 0x0233, 0x027b, 0x0497, 0x01fd, 0x0497, 0x03a1, 0x019d, 0x0359, 0x14bd, 0x03fb, 0x0d7d,
    0x0471, 0x08e1, 0x025d, 0x04d1, 0x0459, 0x045b, 0x084b, 0x03c3, 0x1a43, 0x06e7, 0x0081, 0x05df, 0x0d97, 0x032f, 0x140d, 0x0615,
    0x0d0b, 0x0377, 0x00d7, 0x0729, 0x1d87, 0x0063, 0x034d, 0x0741, 0x0063, 0x0005, 0x0005, 0x0e8b, 0x0081, 0x0101, 0,      0x004b,
    0x08bb, 0x0095, 0x01b5, 0x09e1, 0x074d, 0x0a85, 0x120b, 0x08c7, 0x06f3, 0x09c3, 0x0f6b, 0x0059, 0x057f, 0x0bf1, 0x188f, 0x002f,
    0x024b, 0x09cb, 0x04cb, 0x0693, 0x02f3, 0x06a7, 0x0aa9, 0x0a4f, 0x0ff5, 0x0437, 0,      0,      0,      0,      0,      0x01ad,
    0x0f57, 0x0537, 0x0087, 0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,      0,
];

/**
 * Pseudo-Mersenne Prime
 */
function PseudoMersennePrime ( n, k ) {
    k = k || _pseudo_mersenne_k[n];

    if ( typeof n !== 'number' || typeof k !== number )
        throw new TypeError("Bad arguemt");

    if ( n < 1 || k < 1 )
        throw new RangeError();

    this.mersenneExponent = n;
    this.mersenneSubtrahend = k;
    this.sign = 1;
    this.bitLength = n-1;
    this.limbs = new Uint32Array( (this.bitLength + 31) >> 5 );

    var i = 0;

    for ( ; i < this.bitLength; i += 32 )
        this.limbs[i>>5] = -1;

    if ( i > this.bitLength )
        this.limbs[i-1>>5] <<= (32 - this.bitLength % 32);

    this.limbs[0] -= (k-1);
}

PseudoMersennePrime.prototype = new BigNumber;

/**
 * Modulus
 *
 * Reduction modulo `M` made using Montgomery method:
 *  - with respect to co-modulus `R=2^n > M` for odd `M` or,
 *  - with respect to (pseudo-)Mersenne prime co-modulus `R=2^n-k > M` for even `M`.
 *
 * Since `GCD(M, R) = 1` for arbitrary `M < R` this method always work
 * and reduction modulo `R` is made easy (see HAC 14.47).
 *
 * Bézout coefficient is precalculated here using Extended Euclidean Algorithm.
 */
function Modulus ( modulus ) {
    BigNumber.apply( this, arguments );

    if ( this.valueOf() < 1 )
        throw new RangeError();

    var comodulus;

    if ( this.bitLength <= 32 )
        return;

    if ( this.limbs[0] & 1 ) {
        var bitlen = this.bitLength+1, limbs = new Uint32Array( (bitlen+31) >> 5 );
        limbs[limbs.length-1] = 1 << (this.bitLength % 32);
        comodulus = new BigNumber();
        comodulus.sign = 1;
        comodulus.bitLength = bitlen;
        comodulus.limbs = limbs;
    }
    else {
        var n = (this.bitLength+31) >> 5;
        if ( n < _pseudo_mersenne_k.length ) {
            comodulus = new PseudoMersennePrime(n);
        }
        else {
            // TODO use Barrett reduction for even moduli greater than the largest configured pseudo-Mersenne prime
            return;
        }
    }

    this.comodulus = comodulus;
    this.comodulusRemainder = comodulus.divide(this).remainder;
    this.comodulusRemainderSquare = comodulus.square().divide(this).remainder;

    var k = BigNumber_extGCD( comodulus, this ).y.negate();
    this.bezoutCoefficient = k.sign > 0 ? k : k.add(comodulus);
}

function Modulus_reduce ( a ) {
    if ( !( a instanceof BigNumber ) )
        a = new BigNumber(a);

    if ( a.bitLength <= 32 && this.bitLength <= 32 )
        return new BigNumber( a.valueOf() % this.valueOf() );

    if ( this.comodulus ) {
        var R = this.comodulus,
            k = this.bezoutCoefficient,
            N = this,
            t;

        t = a.clamp(R.bitLength-1).multiply(k).clamp(R.bitLength-1)
             .multiply(N).add(a).splice(R.bitLength);

        if ( t.compare(N) >= 0 )
            t = t.subtract(N);

        return t;
    }

    return a.divide(this).remainder;
}

function Modulus_add ( a, b ) {
    if ( !( a instanceof BigNumber ) )
        a = new BigNumber(a);

    if ( !( b instanceof BigNumber ) )
        b = new BigNumber(b);

    // TODO
}

function Modulus_subtract ( a, b ) {
    // TODO
}

function Modulus_multiply ( a, b ) {
    if ( !( a instanceof BigNumber ) )
        a = new BigNumber(a);

    if ( !( b instanceof BigNumber ) )
        b = new BigNumber(b);

    a.multiply(b).divide(this).remainder;
}

function Modulus_square ( a ) {
    // TODO
}

function Modulus_inverse ( a ) {
    // TODO
}

function Modulus_power ( a, e ) {
}    // TODO

var ModulusPrototype = Modulus.prototype = new BigNumber;
ModulusPrototype.reduce = Modulus_reduce;

/**
 * Montgomery reduction
 */
function Montgomery ( modulus ) {
    BigNumber.apply( this, arguments );

    if ( this.valueOf() < 1 )
        throw new RangeError();

    var comodulus;

    if ( this.bitLength <= 32 )
        return;

    if ( this.limbs[0] & 1 ) {
        var bitlen = ( (this.bitLength+31) & -32 ) + 1, limbs = new Uint32Array( (bitlen+31) >> 5 );
        limbs[limbs.length-1] = 1;
        comodulus = new BigNumber();
        comodulus.sign = 1;
        comodulus.bitLength = bitlen;
        comodulus.limbs = limbs;
    }
    else {
        throw new IllegalArgumentError("bad modulus");
    }

    this.comodulus = comodulus;
    this.comodulusRemainder = comodulus.divide(this).remainder;
    this.comodulusRemainderSquare = comodulus.square().divide(this).remainder;

    var k = BigNumber_extGCD( comodulus, this ).y.clamp(comodulus.bitLength-1);
    this.bezoutCoefficient = k.sign < 0 ? k.negate() : comodulus.subtract(k).clamp(comodulus.bitLength-1);
}

function Montgomery_reduce ( a ) {
    if ( !( a instanceof BigNumber ) )
        a = new BigNumber(a);

    var alimbs = a.limbs, alimbcnt = alimbs.length,
        nlimbs = this.limbs, nlimbcnt = nlimbs.length,
        ylimbs = this.bezoutCoefficient.limbs, ylimbcnt = ylimbs.length;

    _bigint_asm.sreset();

    var pA = _bigint_asm.salloc( alimbcnt<<2 ),
        pN = _bigint_asm.salloc( nlimbcnt<<2 ),
        pY = _bigint_asm.salloc( ylimbcnt<<2 ),
        pR = _bigint_asm.salloc( nlimbcnt<<2 );

    _bigint_asm.z( pR-pA+(nlimbcnt<<2), 0, pA );

    _bigint_heap.set( alimbs, pA>>2 );
    _bigint_heap.set( nlimbs, pN>>2 );
    _bigint_heap.set( ylimbs, pY>>2 );

    _bigint_asm.monred( pA, alimbcnt<<2, (this.comodulus.bitLength-1)>>5, pN, nlimbcnt<<2, pY, ylimbcnt<<2, pR );

    var result = new BigNumber();
    result.limbs = new Uint32Array( _bigint_heap.subarray( pR>>2, (pR>>2)+nlimbcnt ) );
    result.bitLength = this.bitLength;
    result.sign = 1;

    return result;
}

var MontgomeryPrototype = Montgomery.prototype = new BigNumber;
MontgomeryPrototype.reduce = Montgomery_reduce;
