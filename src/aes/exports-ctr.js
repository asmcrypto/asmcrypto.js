/**
 * AES-CTR exports
 */

var ctr_aes_instance = new ctr_aes_constructor( { heap: _aes_heap_instance, asm: _aes_asm_instance } );

function ctr_aes_encrypt_bytes ( data, key, nonce ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return ctr_aes_instance.reset( { key: key, nonce: nonce } ).encrypt(data).result;
}

ctr_aes_constructor.encrypt = ctr_aes_encrypt_bytes;
ctr_aes_constructor.decrypt = ctr_aes_encrypt_bytes;

exports.AES_CTR = ctr_aes_constructor;
