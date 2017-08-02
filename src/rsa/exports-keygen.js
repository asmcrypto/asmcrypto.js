/**
 * RSA keygen exports
 */
import {is_big_number} from '../bignum/bignum';
import {RSA_generateKey} from './genkey';

function rsa_generate_key (bitlen, e ) {
    if ( bitlen === undefined ) throw new SyntaxError("bitlen required");
    if ( e === undefined ) throw new SyntaxError("e required");
    var key = RSA_generateKey( bitlen, e );
    for ( var i = 0; i < key.length; i++ ) {
        if ( is_big_number(key[i]) )
            key[i] = key[i].toBytes();
    }
    return key;
}

export const RSA = {
    generateKey: rsa_generate_key
};
