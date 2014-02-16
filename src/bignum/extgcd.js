function BigNumber_extGCD ( a, b ) {
    if ( !( a instanceof BigNumber ) )
        a = new BigNumber(a);

    if ( !( b instanceof BigNumber ) )
        b = new BigNumber(b);

    var sa = a.sign, sb = b.sign;

    if ( sa < 0 )
        a = a.negate();

    if ( sb < 0 )
        b = b.negate();

    var a_cmp_b = a.compare(b);
    if ( a_cmp_b < 0 ) {
        var t = a; a = b, b = t;
        t = sa; sa = sb; sb = t;
    }

    var xi = BigNumber_ONE, xj = BigNumber_ZERO, lx = b.bitLength,
        yi = BigNumber_ZERO, yj = BigNumber_ONE, ly = a.bitLength,
        z, r, q;

    z = a.divide(b);
    while ( (r = z.remainder) !== BigNumber_ZERO ) {
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

    if ( a_cmp_b < 0 ) {
        var t = xj; xj = yj, yj = t;
    }

    return {
        gcd: b,
        x: xj,
        y: yj
    };
}
