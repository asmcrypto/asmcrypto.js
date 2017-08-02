/**
 * RSA-PSS-SHA1 exports
 */

import {RSA_PSS } from './pkcs1';
import {get_sha1_instance} from '../hash/sha1/sha1';
import {SecurityError} from '../errors';

function rsa_pss_sha1_sign_bytes (data, key, slen ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA_PSS({ hash: get_sha1_instance(), key: key, saltLength: slen })).sign(data).result;
}

function rsa_pss_sha1_verify_bytes ( signature, data, key, slen ) {
    if ( signature === undefined ) throw new SyntaxError("signature required");
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    try {
        (new RSA_PSS({ hash: get_sha1_instance(), key: key, saltLength: slen })).verify(signature, data);
        return true;
    }
    catch ( e ) {
        if ( !( e instanceof SecurityError ) )
            throw e;
    }
    return false;
}

export var RSA_PSS_SHA1 = {
    sign: rsa_pss_sha1_sign_bytes,
    verify: rsa_pss_sha1_verify_bytes
};
