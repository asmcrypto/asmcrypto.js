/**
 * AES-CBC exports
 */

function AES_CBC_encrypt_bytes ( data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return get_AES_CBC_instance( { key: key, padding: padding, iv: iv } ).encrypt(data).result;
}

function AES_CBC_decrypt_bytes ( data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return get_AES_CBC_instance( { key: key, padding: padding, iv: iv } ).decrypt(data).result;
}

exports.AES_CBC = createSimpleCipherInterface( AES_CBC );
exports.AES_CBC.encrypt = AES_CBC_encrypt_bytes;
exports.AES_CBC.decrypt = AES_CBC_decrypt_bytes;

exports.AES_CBC.Encrypt = createProgressiveCipherInterface( AES_CBC_Encrypt );
exports.AES_CBC.Decrypt = createProgressiveCipherInterface( AES_CBC_Decrypt );

