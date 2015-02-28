/**
 * AES-ECB exports
 */

function AES_ECB_encrypt_bytes ( data, key, padding ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_ECB( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, padding: padding } ).encrypt(data).result;
}

function AES_ECB_decrypt_bytes ( data, key, padding ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_ECB( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, padding: padding } ).decrypt(data).result;
}

exports.AES_ECB = AES_ECB;
exports.AES_ECB.encrypt = AES_ECB_encrypt_bytes;
exports.AES_ECB.decrypt = AES_ECB_decrypt_bytes;

exports.AES_ECB.Encrypt = AES_ECB_Encrypt;
exports.AES_ECB.Decrypt = AES_ECB_Decrypt;
