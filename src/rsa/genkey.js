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

    var pbitlen = bitlen >> 1,
        plimbcnt = (pbitlen + 31) >> 5,
        plimbs, p1limbs;

    var qbitlen = bitlen - pbitlen,
        qlimbcnt = (qbitlen + 31) >> 5,
        qlimbs, q1limbs;

    p = new BigNumber({ sign: 1, bitLength: pbitlen, limbs: plimbcnt }), plimbs = p.limbs;
    p1 = new BigNumber({ sign: 1, bitLength: pbitlen, limbs: plimbcnt }), p1limbs = p1.limbs;
    while ( true ) {
        // populate `p` with random bits, clamp to the appropriate bit length
        Random_getValues(plimbs);
        plimbs[0] |= 1;
        plimbs[plimbcnt-1] |= 1 << ((pbitlen - 1) & 31);
        if ( pbitlen & 31 ) plimbs[plimbcnt-1] &= pow2_ceil(pbitlen & 31) - 1;

        // small "magic" divisors test
        if ( !p.isProbablePrime(2) ) continue;

        // p-1
        p1limbs.set(plimbs);
        p1limbs[0] -= 1;

        // check `GCD( e, p-1 ) = 1`
        // TODO `dp` is actually calculated here, use it instead of calculating later
        if ( BigNumber_extGCD( e, p1 ).gcd.valueOf() !== 1 ) continue;

        // proceed to Miller-Rabin test
        if ( p.isProbablePrime(100) ) break;
    }

    q = new BigNumber({ sign: 1, bitLength: qbitlen, limbs: qlimbcnt }), qlimbs = q.limbs;
    q1 = new BigNumber({ sign: 1, bitLength: qbitlen, limbs: qlimbcnt }), q1limbs = q1.limbs;
    while ( true ) {
        // populate `q` with random bits, clamp to the appropriate bit length
        Random_getValues(qlimbs);
        qlimbs[0] |= 1;
        qlimbs[qlimbcnt-1] |= 1 << ((qbitlen - 1) & 31);
        if ( qbitlen & 31 ) qplimbs[qlimbcnt-1] &= pow2_ceil(qbitlen & 31) - 1;

        // small "magic" divisors test
        if ( !q.isProbablePrime(2) ) continue;

        // check `p*q` bit length
        m = new Modulus( p.multiply(q) );
        if ( !m.limbs[ ( (bitlen + 31) >> 5 ) - 1 ] >>> ( (bitlen - 1) & 31) ) continue;

        // q-1
        q1limbs.set(qlimbs);
        q1limbs[0] -= 1;

        // check `GCD( e, q-1 ) = 1`
        // TODO `dq` is actually calculated here, use it instead of calculating later
        if ( BigNumber_extGCD( e, q1 ).gcd.valueOf() !== 1 ) continue;

        // proceed to Miller-Rabin test
        if ( q.isProbablePrime(100) ) break;
    }

    d = new Modulus( p1.multiply(q1) ).inverse(e);

    dp = d.divide(p1).remainder,
    dq = d.divide(q1).remainder;

    p = new Modulus(p),
    q = new Modulus(q);

    var u = p.inverse(q);

    return [ m, e, d, p, q, dp, dq, u ];
}

RSA.generateKey = RSA_generateKey;
