/**
 * AES-CCM exports
 */

var ccm_aes_instance = new ccm_aes_constructor( { heap: _aes_heap_instance, asm: _aes_asm_instance } );

function ccm_aes_encrypt_bytes ( data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    var dataLength = data.byteLength || data.length || 0;
    return ccm_aes_instance.reset( { key: key, nonce: nonce, adata: adata, tagSize: tagSize, dataLength: dataLength } ).encrypt(data).result;
}

function ccm_aes_decrypt_bytes ( data, key, nonce, adata, tagSize ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    if ( nonce === undefined ) throw new SyntaxError("nonce required");
    var dataLength = data.byteLength || data.length || 0;
    tagSize = tagSize || _aes_block_size;
    return ccm_aes_instance.reset( { key: key, nonce: nonce, adata: adata, tagSize: tagSize, dataLength: dataLength-tagSize } ).decrypt(data).result;
}

function create_ccm_aes_decrypt_progressive() {
    return new ccm_aes_decrypt_constructor( { heapSize: 0x100000 } );
}

function create_ccm_aes_encrypt_progressive() {
    return new ccm_aes_encrypt_constructor( { heapSize: 0x100000 } );
}

ccm_aes_constructor.encrypt = ccm_aes_encrypt_bytes;
ccm_aes_constructor.decrypt = ccm_aes_decrypt_bytes;

ccm_aes_constructor.progressive = {
    encrypt: create_ccm_aes_encrypt_progressive,
    decrypt: create_ccm_aes_decrypt_progressive
};

exports.AES_CCM = ccm_aes_constructor;
