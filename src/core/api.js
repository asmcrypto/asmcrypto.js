/**
 * Error definitions
 */

global.IllegalStateError = IllegalStateError;
global.IllegalArgumentError = IllegalArgumentError;
global.SecurityError = SecurityError;

/**
 * Util exports
 */

exports.string_to_bytes = string_to_bytes;
exports.hex_to_bytes = hex_to_bytes;
exports.base64_to_bytes = base64_to_bytes;
exports.bytes_to_string = bytes_to_string;
exports.bytes_to_hex = bytes_to_hex;
exports.bytes_to_base64 = bytes_to_base64;

/**
 * SHA256 exports
 */

var SHA256_instance = new sha256_constructor( { heapSize: 0x100000 } );

function sha256_bytes ( data ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    return SHA256_instance.reset().process(data).finish().result;
}

function sha256_hex ( data ) {
    var result = sha256_bytes(data);
    return bytes_to_hex(result);
}

function sha256_base64 ( data ) {
    var result = sha256_bytes(data);
    return bytes_to_base64(result);
}

exports.SHA256 = {
    bytes: sha256_bytes,
    hex: sha256_hex,
    base64: sha256_base64
};

/**
 * HMAC-SHA256 exports
 */

var hmac_sha256_instance = new hmac_sha256_constructor( { hash: SHA256_instance } );

function hmac_sha256_bytes ( data, password ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( password === undefined ) throw new SyntaxError("password required");
    return hmac_sha256_instance.reset( { password: password } ).process(data).finish().result;
}

function hmac_sha256_hex ( data, password ) {
    var result = hmac_sha256_bytes( data, password );
    return bytes_to_hex(result);
}

function hmac_sha256_base64 ( data, password ) {
    var result = hmac_sha256_bytes( data, password );
    return bytes_to_base64(result);
}

exports.HMAC =
exports.HMAC_SHA256 = {
    bytes: hmac_sha256_bytes,
    hex: hmac_sha256_hex,
    base64: hmac_sha256_base64
};

/**
 * PBKDF2-HMAC-SHA256 exports
 */

var pbkdf2_hmac_sha256_instance = new pbkdf2_hmac_sha256_constructor( { hmac: hmac_sha256_instance } );

function pbkdf2_hmac_sha256_bytes ( password, salt, iterations, dklen ) {
    if ( password === undefined ) throw new SyntaxError("password required");
    if ( salt === undefined ) throw new SyntaxError("salt required");
    return pbkdf2_hmac_sha256_instance.reset( { password: password } ).generate( salt, iterations, dklen ).result;
}

function pbkdf2_hmac_sha256_hex ( password, salt, iterations, dklen ) {
    var result = pbkdf2_hmac_sha256_bytes( password, salt, iterations, dklen );
    return bytes_to_hex(result);
}

function pbkdf2_hmac_sha256_base64 ( password, salt, iterations, dklen ) {
    var result = pbkdf2_hmac_sha256_bytes( password, salt, iterations, dklen );
    return bytes_to_base64(result);
}

exports.PBKDF2 =
exports.PBKDF2_HMAC_SHA256 = {
    bytes: pbkdf2_hmac_sha256_bytes,
    hex: pbkdf2_hmac_sha256_hex,
    base64: pbkdf2_hmac_sha256_base64
};

/**
 * AES-CBC exports
 */

var cbc_aes_instance = new cbc_aes_constructor( { heapSize: 0x100000 } );

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

exports.AES =
exports.AES_CBC = {
    encrypt: cbc_aes_encrypt_bytes,
    decrypt: cbc_aes_decrypt_bytes
};

/**
 * AES-CCM exports
 */

var ccm_aes_instance = new ccm_aes_constructor( { heap: cbc_aes_instance.heap, asm: cbc_aes_instance.asm } );

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

exports.AES_CCM = {
    encrypt: ccm_aes_encrypt_bytes,
    decrypt: ccm_aes_decrypt_bytes
};


/**
 * AES-CFB exports
 */

var cfb_aes_instance = new cfb_aes_constructor( { heap: cbc_aes_instance.heap, asm: cbc_aes_instance.asm } );

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
