/**
 * RSA keygen exports
 */
function rsa_generate_key ( bitlen, e ) {
    if ( bitlen === undefined ) throw new SyntaxError("bitlen required");
    if ( e === undefined ) throw new SyntaxError("e required");
    var key = RSA_generateKey( bitlen, e );
    for ( var i = 0; i < key.length; i++ ) {
        if ( is_big_number(key[i]) )
            key[i] = key[i].toBytes();
    }
    return key;
}

exports.RSA = {
    generateKey: rsa_generate_key
};
