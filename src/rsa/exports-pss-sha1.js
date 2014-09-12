/**
 * RSA-PSS-SHA1 exports
 */

function rsa_pss_sha1_sign_bytes ( data, key, slen ) {
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

exports.RSA_PSS = RSA_PSS;

exports.RSA_PSS_SHA1 = {
    sign: rsa_pss_sha1_sign_bytes,
    verify: rsa_pss_sha1_verify_bytes
};
