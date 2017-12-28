/**
 * Generate RSA key pair
 *
 * @param bitlen desired modulus length, default is 2048
 * @param e public exponent, default is 65537
 */
import {RSA} from './rsa';
import {BigNumber_randomProbablePrime} from '../bignum/prime';
import {BigNumber_extGCD} from '../bignum/extgcd';
import {BigNumber_constructor, is_big_number} from '../bignum/bignum';
import {Modulus} from '../bignum/modulus';
import {is_buffer, is_bytes, is_number, is_string, string_to_bytes} from '../utils';
import {IllegalArgumentError} from '../errors';

export function RSA_generateKey (bitlen, e ) {
    bitlen = bitlen || 2048;
    e      = e      || 65537;

    if ( bitlen < 512 )
        throw new IllegalArgumentError("bit length is too small");

    if ( is_string(e) )
        e = string_to_bytes(e);

    if ( is_buffer(e) )
        e = new Uint8Array(e);

    if ( is_bytes(e) || is_number(e) || is_big_number(e) ) {
        e = new BigNumber_constructor(e);
    }
    else {
        throw new TypeError("unexpected exponent type");
    }

    if ( ( e.limbs[0] & 1 ) === 0 )
        throw new IllegalArgumentError("exponent must be an odd number");

    var m, e, d, p, q, p1, q1, dp, dq, u;

    p = BigNumber_randomProbablePrime(
        bitlen >> 1,
        function ( p ) {
            p1 = new BigNumber_constructor(p); p1.limbs[0] -= 1;
            return BigNumber_extGCD( p1, e ).gcd.valueOf() == 1;
        }
    );

    q = BigNumber_randomProbablePrime(
        bitlen - (bitlen >> 1),
        function ( q ) {
            m = new Modulus( p.multiply(q) );
            if ( !( m.limbs[ ( (bitlen + 31) >> 5 ) - 1 ] >>> ( (bitlen - 1) & 31) ) ) return false;
            q1 = new BigNumber_constructor(q); q1.limbs[0] -= 1;
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

export default RSA;
