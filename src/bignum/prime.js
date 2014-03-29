function BigNumber_isProbablePrime ( paranoia ) {
    paranoia = paranoia || 100;

    var limbs = this.limbs,
        i = 0;

    //
    // Oddity test
    // (50% prime probability)
    //

    if ( ( limbs[0] & 1 ) === 0 ) return false;
    if ( paranoia <= 1 ) return true;

    //
    // Magic divisors (3, 5, 17) test
    // (~75% prime probability)
    //

    var s3 = 0, s5 = 0, s17 = 0;
    for ( i = 0; i < limbs.length; i++ ) {
        var l3 = limbs[i];
        while ( l3 ) {
            s3 += (l3 & 3);
            l3 >>>= 2;
        }

        var l5 = limbs[i];
        while ( l5 ) {
            s5 += (l5 & 3);
            l5 >>>= 2;
            s5 -= (l5 & 3);
            l5 >>>= 2;
        }

        var l17 = limbs[i];
        while ( l17 ) {
            s17 += (l17 & 15);
            l17 >>>= 4;
            s17 -= (l17 & 15);
            l17 >>>= 4;
        }
    }
    if ( !(s3 % 3) || !(s5 % 5) || !(s17 % 17) ) return false;
    if ( paranoia <= 2 ) return true;

    //
    // Miller-Rabin test
    // (1-0.25^(paranoia/2) prime probability)
    //

    var t = new BigNumber(this),
        s = 0;
    t.limbs[0] -= 1;
    while ( t.limbs[s>>5] === 0 ) s += 32;
    while ( ( ( t.limbs[s>>5] >> (s & 31) ) & 1 ) === 0 ) s++;
    t = t.splice(s);

    var m = new Modulus(this),
        m1 = this.subtract(BigNumber_ONE),
        a = new BigNumber(this),
        l = this.limbs.length-1;
    while ( a.limbs[l] === 0 ) l--;

    paranoia >>>= 1;
    while ( --paranoia >= 0 ) {
        Random_getBytes(a.limbs.buffer);
        if ( a.limbs[0] < 2 ) a.limbs[0] += 2;
        while ( a.compare(m1) >= 0 ) a.limbs[l] >>>= 1;

        var x = m.power( a, t );
        if ( x.compare(BigNumber_ONE) === 0 ) continue;
        if ( x.compare(m1) === 0 ) continue;

        var c = s;
        while ( --c > 0 ) {
            x = x.square().divide(m).remainder;
            if ( x.compare(BigNumber_ONE) === 0 ) return false;
            if ( x.compare(m1) === 0 ) break;
        }

        if ( c === 0 ) return false;
    }

    return true;
}

BigNumberPrototype.isProbablePrime = BigNumber_isProbablePrime;
