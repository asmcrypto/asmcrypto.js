// shared asm.js module and heap
var _aes_heap = new Uint8Array(0x100000),
    _aes_asm  = aes_asm( global, null, _aes_heap.buffer );

/**
 * AES-ECB exports
 */
if ( typeof ecb_aes_constructor !== 'undefined' )
{
    var ecb_aes_instance = new ecb_aes_constructor( { heap: _aes_heap, asm: _aes_asm } );

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

    exports.AES_ECB = {
        encrypt: ecb_aes_encrypt_bytes,
        decrypt: ecb_aes_decrypt_bytes
    };
}

/**
 * AES-CBC exports
 */
if ( typeof cbc_aes_constructor !== 'undefined' )
{
    var cbc_aes_instance = new cbc_aes_constructor( { heap: _aes_heap, asm: _aes_asm } );

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

    exports.AES_CBC = {
        encrypt: cbc_aes_encrypt_bytes,
        decrypt: cbc_aes_decrypt_bytes
    };
}

/**
 * AES-CCM exports
 */
if ( typeof ccm_aes_constructor !== 'undefined' )
{
    var ccm_aes_instance = new ccm_aes_constructor( { heap: _aes_heap, asm: _aes_asm } );

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
}

/**
 * AES-CFB exports
 */
if ( typeof cfb_aes_constructor !== 'undefined' )
{
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
}
