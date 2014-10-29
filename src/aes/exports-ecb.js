/**
 * AES-ECB exports
 */

var ecb_aes_instance = new ecb_aes_constructor( { heap: _aes_heap_instance, asm: _aes_asm_instance } );

function ecb_aes_encrypt_bytes ( data, key, padding ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return ecb_aes_instance.reset( { key: key, padding: padding } ).encrypt(data).result;
}

function ecb_aes_decrypt_bytes ( data, key, padding ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return ecb_aes_instance.reset( { key: key, padding: padding } ).decrypt(data).result;
}

function create_ecb_aes_decrypt_progressive() {
    return new ecb_aes_decrypt_constructor( { heapSize: 0x100000 } );
}

function create_ecb_aes_encrypt_progressive() {
    return new ecb_aes_encrypt_constructor( { heapSize: 0x100000 } );
}

ecb_aes_constructor.encrypt = ecb_aes_encrypt_bytes;
ecb_aes_constructor.decrypt = ecb_aes_decrypt_bytes;

ecb_aes_constructor.progressive = {
    encrypt: create_ecb_aes_encrypt_progressive,
    decrypt: create_ecb_aes_decrypt_progressive
};

exports.AES_ECB = ecb_aes_constructor;
