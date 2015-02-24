/**
 * AES-CCM exports
 */

function AES_CCM_encrypt_bytes ( data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    var dataLength = data.length || 0;
    return get_AES_CCM_instance( { key: key, nonce: nonce, adata: adata, tagSize: tagSize, dataLength: dataLength } ).encrypt(data).result;
}

function AES_CCM_decrypt_bytes ( data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    var dataLength = data.length || 0;
    tagSize = tagSize || _aes_block_size;
    return get_AES_CCM_instance( { key: key, nonce: nonce, adata: adata, tagSize: tagSize, dataLength: dataLength-tagSize } ).decrypt(data).result;
}

exports.AES_CCM = createSimpleCipherInterface( AES_CCM );
exports.AES_CCM.encrypt = AES_CCM_encrypt_bytes;
exports.AES_CCM.decrypt = AES_CCM_decrypt_bytes;

exports.AES_CCM.Encrypt = createProgressiveCipherInterface( AES_CCM_Encrypt );
exports.AES_CCM.Decrypt = createProgressiveCipherInterface( AES_CCM_Decrypt );
