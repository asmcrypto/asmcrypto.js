/**
 * AES-OFB exports
 */

function AES_OFB_crypt_bytes ( data, key, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_OFB( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, iv: iv } ).encrypt(data).result;
}

exports.AES_OFB = AES_OFB;
exports.AES_OFB.encrypt = AES_OFB_crypt_bytes;
exports.AES_OFB.decrypt = AES_OFB_crypt_bytes;

exports.AES_OFB.Encrypt =
exports.AES_OFB.Decrypt = AES_OFB_Crypt;
