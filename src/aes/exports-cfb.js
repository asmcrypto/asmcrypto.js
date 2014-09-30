/**
 * AES-CFB exports
 */

var cfb_aes_instance = new cfb_aes_constructor( { heap: _aes_heap_instance, asm: _aes_asm_instance } );

function cfb_aes_encrypt_bytes ( data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return cfb_aes_instance.reset( { key: key, padding: padding, iv: iv } ).encrypt(data).result;
}

function cfb_aes_decrypt_bytes ( data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return cfb_aes_instance.reset( { key: key, padding: padding, iv: iv } ).decrypt(data).result;
}

function create_cfb_aes_decrypt_progressive() {
    return new cfb_aes_decrypt_constructor( { heapSize: 0x100000 } );
}

function create_cfb_aes_encrypt_progressive() {
    return new cfb_aes_encrypt_constructor( { heapSize: 0x100000 } );
}

cfb_aes_constructor.encrypt = cfb_aes_encrypt_bytes;
cfb_aes_constructor.decrypt = cfb_aes_decrypt_bytes;

cfb_aes_constructor.progressive = {
    encrypt: create_cfb_aes_encrypt_progressive,
    decrypt: create_cfb_aes_decrypt_progressive
};

exports.AES_CFB = cfb_aes_constructor;
