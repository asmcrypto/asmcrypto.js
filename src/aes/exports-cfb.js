/**
 * AES-CFB exports
 */

var cfb_aes_instance = new cfb_aes_constructor( { heap: _aes_heap, asm: _aes_asm } );

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

exports.AES_CFB = {
    encrypt: cfb_aes_encrypt_bytes,
    decrypt: cfb_aes_decrypt_bytes
};
