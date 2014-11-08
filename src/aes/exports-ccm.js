/**
 * AES-CCM exports
 */

var ccm_aes_instance = new ccm_aes_constructor( { heap: _aes_heap, asm: _aes_asm } );

function ccm_aes_encrypt_bytes ( data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    var dataLength = data.length || 0;
    return ccm_aes_instance.reset( { key: key, nonce: nonce, adata: adata, tagSize: tagSize, dataLength: dataLength } ).encrypt(data).result;
}

function ccm_aes_decrypt_bytes ( data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    var dataLength = data.length || 0;
    tagSize = tagSize || _aes_block_size;
    return ccm_aes_instance.reset( { key: key, nonce: nonce, adata: adata, tagSize: tagSize, dataLength: dataLength-tagSize } ).decrypt(data).result;
}

exports.AES_CCM = {
    encrypt: ccm_aes_encrypt_bytes,
    decrypt: ccm_aes_decrypt_bytes
};
