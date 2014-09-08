/**
 * AES-GCM exports
 */

var gcm_aes_instance = new gcm_aes_constructor( { heap: _aes_heap, asm: _aes_asm } );

function gcm_aes_encrypt_bytes ( data, key, iv, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( iv === undefined ) throw new SyntaxError("iv required");
    return gcm_aes_instance.reset( { key: key, iv: iv, adata: adata, tagSize: tagSize } ).encrypt(data).result;
}

function gcm_aes_decrypt_bytes ( data, key, iv, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( iv === undefined ) throw new SyntaxError("iv required");
    return gcm_aes_instance.reset( { key: key, iv: iv, adata: adata, tagSize: tagSize } ).decrypt(data).result;
}

exports.AES_GCM = {
    encrypt: gcm_aes_encrypt_bytes,
    decrypt: gcm_aes_decrypt_bytes
};
