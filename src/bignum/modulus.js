/**
 * Modulus
 */
function Modulus () {
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

        var k = BigNumber_extGCD( comodulus, this ).y.clamp(comodulus.bitLength-1);
        this.bezoutCoefficient = k.sign < 0 ? k.negate() : comodulus.subtract(k).clamp(comodulus.bitLength-1);
    }
    else {
        // TODO Montgomery reduction with respect to (pseudo-)Mersenne prime
        // TODO Barrett reduction for even moduli greater than the largest configured pseudo-Mersenne prime
        return;
    }

    this.comodulus = comodulus;
    this.comodulusRemainder = comodulus.divide(this).remainder;
    this.comodulusRemainderSquare = comodulus.square().divide(this).remainder;
}

function Modulus_reduce ( a ) {
    if ( !( a instanceof BigNumber ) )
        a = new BigNumber(a);

    if ( a.bitLength <= 32 && this.bitLength <= 32 )
        return new BigNumber( a.valueOf() % this.valueOf() );

    if ( a.bitLength === this.bitLength ) {
        if ( a.compare(this) < 0 )
            return a;

        return a.subtract(this).clamp(this.bitLength);
    }

    return a.divide(this).remainder;
}

function Modulus_reciprocal ( a ) {
    a = this.reduce(a);

    var k = BigNumber_extGCD( this, a ).y;
    if ( k.sign < 0 ) k = k.add(this).clamp(this.bitLength);

    return k;
}

function Modulus_power ( a, e ) {
    // TODO
}

var ModulusPrototype = Modulus.prototype = new BigNumber;
ModulusPrototype.reduce = Modulus_reduce;
ModulusPrototype.reciprocal = Modulus_reciprocal;

/**
 * Montgomery reduction
 *
 * Reduction modulo `M` made using Montgomery method:
 *  - with respect to co-modulus `R=2^(32*m) > M` for odd `M` or,
 *  - TODO with respect to (pseudo-)Mersenne prime co-modulus `R=2^(32*m)-k > M` for even `M`.
 *
 * Since `GCD(M, R) = 1` for arbitrary `M < R` this method always work
 * and reduction modulo `R` is made easy (see HAC 14.32, 14.47).
 */
function Montgomery () {
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

    _bigint_asm.mredc_odd( pA, alimbcnt<<2, pN, nlimbcnt<<2, ylimbs[0], pR );

    var result = new BigNumber();
    result.limbs = new Uint32Array( _bigint_heap.subarray( pR>>2, (pR>>2)+nlimbcnt ) );
    result.bitLength = this.bitLength;
    result.sign = 1;

    return result;
}

var MontgomeryPrototype = Montgomery.prototype = new BigNumber;
MontgomeryPrototype.reduce = Montgomery_reduce;
