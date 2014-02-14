function bignum_extGCD ( a, b ) {
    if ( !( a instanceof bignum_constructor ) )
        a = new bignum_constructor(a);

    if ( !( b instanceof bignum_constructor ) )
        b = new bignum_constructor(b);

    var sa = a.sign, sb = b.sign;

    if ( sa < 0 )
        a = a.negate();

    if ( sb < 0 )
        b = b.negate();

    if ( a.compare(b) < 0 ) {
        var t = a; a = b, b = t;
    }

    var xi = bignum_one, xj = bignum_zero, lx = b.bitLength,
        yi = bignum_zero, yj = bignum_one, ly = a.bitLength,
        z, r, q;

    z = a.divide(b);
    while ( (r = z.remainder) !== bignum_zero ) {
        q = z.quotient;

        z = xi.subtract( q.multiply(xj).clamp(lx) ).clamp(lx), xi = xj, xj = z;
        z = yi.subtract( q.multiply(yj).clamp(ly) ).clamp(ly), yi = yj, yj = z;

        a = b, b = r;

        z = a.divide(b);
    }

    if ( sa < 0 )
        xj = xj.negate();

    if ( sb < 0 )
        yj = yj.negate();

    return {
        gcd: b,
        x: xj,
        y: yj
    };
}
