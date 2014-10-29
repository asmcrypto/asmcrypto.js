/**
 * AES-CTR exports
 */

var ctr_aes_instance = new ctr_aes_constructor( { heap: _aes_heap_instance, asm: _aes_asm_instance } );

function ctr_aes_encrypt_bytes ( data, key, nonce ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return ctr_aes_instance.reset( { key: key, nonce: nonce } ).encrypt(data).result;
}

function create_ctr_aes_progressive() {
    return new cfb_aes_encrypt_constructor( { heapSize: 0x100000 } );
}

ctr_aes_constructor.encrypt = ctr_aes_encrypt_bytes;
ctr_aes_constructor.decrypt = ctr_aes_encrypt_bytes;

ctr_aes_constructor.progressive = {
    encrypt: create_ctr_aes_progressive,
    decrypt: create_ctr_aes_progressive
};

exports.AES_CTR = ctr_aes_constructor;
