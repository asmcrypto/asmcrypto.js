/**
 * Generate RSA key pair
 *
 * @param bitlen desired modulus length, default is 2048
 * @param e public exponent, default is 65537
 */
function RSA_generateKey ( bitlen, e ) {
    bitlen = bitlen || 2048;
    e = e || 65537;

    if ( bitlen < 512 )
        throw new IllegalArgumentError("bit length is too small");
    if ( pow2_ceil(bitlen) !== bitlen )
        throw new IllegalArgumentError("bit length should be a power of 2");

    var limbcnt = ((bitlen>>1) + 31) >> 5;

    var p = new BigNumber;
    p.sign = 1;
    p.bitLength = bitlen>>1;
    p.limbs = new Uint32Array(limbcnt);
    while ( true ) {
        Random_getBytes(p.limbs.buffer); p.limbs[0] |= 1;
        p.limbs[limbcnt-1] &= pow2_ceil( (bitlen>>1) & 31 ) - 1;
        if ( p.isProbablePrime(100) ) break;
    }
    var p1 = new BigNumber(p); p1.limbs[0] ^= 1;

    var q = new BigNumber;
    q.sign = 1;
    q.bitLength = bitlen>>1;
    q.limbs = new Uint32Array(limbcnt);
    while ( true ) {
        Random_getBytes(q.limbs.buffer); q.limbs[0] |= 1;
        q.limbs[limbcnt-1] &= pow2_ceil( (bitlen>>1) & 31 ) - 1;
        if ( q.isProbablePrime(100) ) break;
    }
    var q1 = new BigNumber(q); q1.limbs[0] ^= 1;

    var m = new Modulus( p.multiply(q) );

    var d = new Modulus( p1.multiply(q1) ).inverse(e);

    var dp = d.divide(p1).remainder,
        dq = d.divide(q1).remainder;

    p = new Modulus(p),
    q = new Modulus(q);

    var u = p.inverse(q);

    return [ m, e, d, p, q, dp, dq, u ];
}

RSA.generateKey = RSA_generateKey;
