/**
 * AES-CTR exports
 */

var ctr_aes_instance = new ctr_aes_constructor( { heap: _aes_heap, asm: _aes_asm } );

function ctr_aes_encrypt_bytes ( data, key, nonce ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return ctr_aes_instance.reset( { key: key, nonce: nonce } ).encrypt(data).result;
}

exports.AES_CTR = {
    encrypt: ctr_aes_encrypt_bytes,
    decrypt: ctr_aes_encrypt_bytes
};
