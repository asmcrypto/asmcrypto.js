/**
 * AES-CBC exports
 */

var cbc_aes_instance = new cbc_aes_constructor( { heap: _aes_heap_instance, asm: _aes_asm_instance } );

function cbc_aes_encrypt_bytes ( data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return cbc_aes_instance.reset( { key: key, padding: padding, iv: iv } ).encrypt(data).result;
}

function cbc_aes_decrypt_bytes ( data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return cbc_aes_instance.reset( { key: key, padding: padding, iv: iv } ).decrypt(data).result;
}

cbc_aes_constructor.encrypt = cbc_aes_encrypt_bytes;
cbc_aes_constructor.decrypt = cbc_aes_decrypt_bytes;

exports.AES_CBC = cbc_aes_constructor;

/**
 * New AES-CBC exports
 */

var cbc_naes_instance = new cbc_naes_constructor();

function cbc_naes_encrypt_bytes ( data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return cbc_naes_instance.reset( { key: key, padding: padding, iv: iv } ).encrypt(data).result;
}

function cbc_naes_decrypt_bytes ( data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return cbc_naes_instance.reset( { key: key, padding: padding, iv: iv } ).decrypt(data).result;
}

cbc_naes_constructor.encrypt = cbc_naes_encrypt_bytes;
cbc_naes_constructor.decrypt = cbc_naes_decrypt_bytes;

exports.NEW_AES_CBC = cbc_naes_constructor;
