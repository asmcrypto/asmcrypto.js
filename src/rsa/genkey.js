/**
 * Generate RSA key pair
 *
 * @param bitlen desired modulus length, default is 2048
 * @param e public exponent, default is 65537
 */
function RSA_generateKey ( bitlen, e ) {
    bitlen = bitlen || 2048;
    e      = e      || 65537;

    if ( bitlen < 512 )
        throw new IllegalArgumentError("bit length is too small");

    var m, e, d, p, q, p1, q1, dp, dq, u;

    p = BigNumber_randomProbablePrime(
        bitlen >> 1,
        function ( p ) {
            p1 = p.subtract(BigNumber_ONE);
            return BigNumber_extGCD( p1, e ).gcd.valueOf() == 1;
        }
    );

    q = BigNumber_randomProbablePrime(
        bitlen - (bitlen >> 1),
        function ( q ) {
            m = new Modulus( p.multiply(q) );
            if ( !( m.limbs[ ( (bitlen + 31) >> 5 ) - 1 ] >>> ( (bitlen - 1) & 31) ) ) return false;
            q1 = q.subtract(BigNumber_ONE);
            return BigNumber_extGCD( q1, e ).gcd.valueOf() == 1;
        }
    );

    d = new Modulus( p1.multiply(q1) ).inverse(e);

    dp = d.divide(p1).remainder,
    dq = d.divide(q1).remainder;

    p = new Modulus(p),
    q = new Modulus(q);

    var u = p.inverse(q);

    return [ m, e, d, p, q, dp, dq, u ];
}

RSA.generateKey = RSA_generateKey;
