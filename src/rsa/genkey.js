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

    var m, e, d, p, q, p1, q1, dp, dq, u;

    var pbitlen = bitlen >> 1, plimbcnt = (pbitlen + 31) >> 5, plimbs;

    var qbitlen = bitlen - pbitlen, qlimbcnt = (qbitlen + 31) >> 5, qlimbs;

    p = new BigNumber({ sign: 1, bitLength: pbitlen, limbs: plimbcnt }), plimbs = p.limbs;
    while ( true ) {
        Random_getBytes(plimbs.buffer);
        plimbs[0] |= 1;
        plimbs[plimbcnt-1] |= 1 << ((pbitlen - 1) & 31);
        if ( pbitlen & 31 ) plimbs[plimbcnt-1] &= pow2_ceil(pbitlen & 31) - 1;
        if ( p.isProbablePrime(100) ) break;
    }

    q = new BigNumber({ sign: 1, bitLength: qbitlen, limbs: qlimbcnt }), qlimbs = q.limbs;
    while ( true ) {
        Random_getBytes(qlimbs.buffer);
        qlimbs[0] |= 1;
        qlimbs[qlimbcnt-1] |= 1 << ((qbitlen - 1) & 31);
        if ( qbitlen & 31 ) qplimbs[qlimbcnt-1] &= pow2_ceil(qbitlen & 31) - 1;
        if ( q.isProbablePrime(2) ) {
            m = new Modulus( p.multiply(q) );
            if ( m.splice(bitlen-1).valueOf() && q.isProbablePrime(98) ) break;
        }
    }

    var p1 = new BigNumber(p); p1.limbs[0] ^= 1;
    var q1 = new BigNumber(q); q1.limbs[0] ^= 1;

    var d = new Modulus( p1.multiply(q1) ).inverse(e);

    var dp = d.divide(p1).remainder,
        dq = d.divide(q1).remainder;

    p = new Modulus(p),
    q = new Modulus(q);

    var u = p.inverse(q);

    return [ m, e, d, p, q, dp, dq, u ];
}

RSA.generateKey = RSA_generateKey;
