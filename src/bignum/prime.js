// Tests if the number supplied is a Miller-Rabin strong probable prime
import {BigNumber_constructor} from './bignum';
import {pow2_ceil} from '../utils';
import {Random_getValues} from '../random/random';
import {Modulus} from './modulus';

function _BigNumber_isMillerRabinProbablePrime (rounds ) {
    var t = new BigNumber_constructor(this),
        s = 0;
    t.limbs[0] -= 1;
    while ( t.limbs[s>>5] === 0 ) s += 32;
    while ( ( ( t.limbs[s>>5] >> (s & 31) ) & 1 ) === 0 ) s++;
    t = t.slice(s);

    var m = new Modulus(this),
        m1 = this.subtract(BigNumber_constructor.ONE),
        a = new BigNumber_constructor(this),
        l = this.limbs.length-1;
    while ( a.limbs[l] === 0 ) l--;

    while ( --rounds >= 0 ) {
        Random_getValues(a.limbs);
        if ( a.limbs[0] < 2 ) a.limbs[0] += 2;
        while ( a.compare(m1) >= 0 ) a.limbs[l] >>>= 1;

        var x = m.power( a, t );
        if ( x.compare(BigNumber_constructor.ONE) === 0 ) continue;
        if ( x.compare(m1) === 0 ) continue;

        var c = s;
        while ( --c > 0 ) {
            x = x.square().divide(m).remainder;
            if ( x.compare(BigNumber_constructor.ONE) === 0 ) return false;
            if ( x.compare(m1) === 0 ) break;
        }

        if ( c === 0 ) return false;
    }

    return true;
}

function BigNumber_isProbablePrime ( paranoia ) {
    paranoia = paranoia || 80;

    var limbs = this.limbs,
        i = 0;

    // Oddity test
    // (50% false positive probability)
    if ( ( limbs[0] & 1 ) === 0 ) return false;
    if ( paranoia <= 1 ) return true;

    // Magic divisors (3, 5, 17) test
    // (~25% false positive probability)
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

    // Miller-Rabin test
    // (≤ 4^(-k) false positive probability)
    return _BigNumber_isMillerRabinProbablePrime.call( this, paranoia >>> 1 );
}

// Small primes for trail division
var _primes = [ 2, 3 /* and so on, computed lazily */ ];

// Returns an array populated with first n primes.
function _small_primes ( n ) {
    if ( _primes.length >= n )
        return _primes.slice( 0, n );

    for ( var p = _primes[_primes.length-1] + 2; _primes.length < n; p += 2 ) {
        for ( var i = 0, d = _primes[i]; d*d <= p; d = _primes[++i] ) {
            if ( p % d == 0 ) break;
        }
        if ( d*d > p ) _primes.push(p);
    }

    return _primes;
}

// Returns strong pseudoprime of a specified bit length
export function BigNumber_randomProbablePrime ( bitlen, filter ) {
    var limbcnt = (bitlen + 31) >> 5,
        prime = new BigNumber_constructor({ sign: 1, bitLength: bitlen, limbs: limbcnt }),
        limbs = prime.limbs;

    // Number of small divisors to try that minimizes the total cost of the trial division
    // along with the first round of Miller-Rabin test for a certain bit length.
    var k = 10000;
    if ( bitlen <= 512 ) k = 2200;
    if ( bitlen <= 256 ) k = 600;

    var divisors = _small_primes(k),
        remainders = new Uint32Array(k);

    // Number of Miller-Rabin iterations for an error rate  of less than 2^-80
    // Damgaard, Landrock, Pomerance: Average case error estimates for the strong probable prime test.
    var s = (bitlen * Math.LN2) | 0,
        r = 27;
    if ( bitlen >= 250 ) r = 12;
    if ( bitlen >= 450 ) r = 6;
    if ( bitlen >= 850 ) r = 3;
    if ( bitlen >= 1300 ) r = 2;

    while ( true ) {
        // populate `prime` with random bits, clamp to the appropriate bit length
        Random_getValues(limbs);
        limbs[0] |= 1;
        limbs[limbcnt-1] |= 1 << ((bitlen - 1) & 31);
        if ( bitlen & 31 ) limbs[limbcnt-1] &= pow2_ceil((bitlen + 1) & 31) - 1;

        // remainders from division to small primes
        remainders[0] = 1;
        for ( var i = 1; i < k; i++ ) {
            remainders[i] = prime.divide( divisors[i] ).remainder.valueOf();
        }

        // try no more than `s` subsequent candidates
        seek:
        for ( var j = 0; j < s; j += 2, limbs[0] += 2 ) {
            // check for small factors
            for ( var i = 1; i < k; i++ ) {
                if ( ( remainders[i] + j ) % divisors[i] === 0 ) continue seek;
            }

            // additional check just before the heavy lifting
            if ( typeof filter === 'function' && !filter(prime) ) continue;

            // proceed to Miller-Rabin test
            if ( _BigNumber_isMillerRabinProbablePrime.call( prime, r ) ) return prime;
        }
    }
}

BigNumber_constructor.prototype.isProbablePrime = BigNumber_isProbablePrime;

BigNumber_constructor.randomProbablePrime = BigNumber_randomProbablePrime;
