/**
 * RSA-PSS-SHA256 exports
 */

function rsa_pss_sha256_sign_bytes ( data, key, slen ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return (new RSA_PSS({ hash: get_sha256_instance(), key: key, saltLength: slen })).sign(data).result;
}

function rsa_pss_sha256_verify_bytes ( signature, data, key, slen ) {
    if ( signature === undefined ) throw new SyntaxError("signature required");
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    try {
        (new RSA_PSS({ hash: get_sha256_instance(), key: key, saltLength: slen })).verify(signature, data);
        return true;
    }
    catch ( e ) {
        if ( !( e instanceof SecurityError ) )
            throw e;
    }
    return false;
}

exports.RSA_PSS_SHA256 = {
    sign: rsa_pss_sha256_sign_bytes,
    verify: rsa_pss_sha256_verify_bytes
};
