// Small primes for trial division
var _small_primes = [ 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997 ];

function BigNumber_isProbablePrime ( r ) {
    r = r || (this.bitLength >> 1);

    var limbs = this.limbs,
        i = 0;

    //
    // Oddity test
    // (50% prime probability)
    //
    if ( ( limbs[0] & 1 ) === 0 ) return false;
    if ( r <= 1 ) return true;

    //
    // Magic divisors (3, 5, 7) test
    // (~77% prime probability)
    //
    var s3 = 0, s5 = 0, s7 = 0;
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

        var l7 = limbs[i];
        while ( l7 ) {
            s7 += (l7 & 7);
            l7 >>>= 3;
        }
    }
    if ( (s3 % 3) === 0 || (s5 % 5) === 0 || (s7 % 7) === 0 ) return false;
    if ( r <= 2 ) return true;

    //
    // Small prime divisors test
    // (~92% prime probability)
    // TODO

    //
    // Miller-Rabin test
    // (1-0.5^r prime probability)
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

    r >>>= 1;
    while ( --r >= 0 ) {
        Random_getBytes(a.limbs);
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

BigNumberPrototype.isProbablePrime = BigNumberPrototype_isProbablePrime;
