/**
 * Cipher Feedback Mode (CFB)
 */

function AES_CFB ( options ) {
    this.iv = null;

    AES.call( this, options );

    this.mode = 'CFB';
}

var AES_CFB_prototype = AES_CFB.prototype;
AES_CFB_prototype.reset = AES_reset;
AES_CFB_prototype.encrypt = AES_Encrypt_finish;
AES_CFB_prototype.decrypt = AES_Decrypt_finish;

function AES_CFB_Encrypt ( options ) {
    AES_CFB.call( this, options );
}

var AES_CFB_Encrypt_prototype = AES_CFB_Encrypt.prototype;
AES_CFB_Encrypt_prototype.reset = AES_reset;
AES_CFB_Encrypt_prototype.process = AES_Encrypt_process;
AES_CFB_Encrypt_prototype.finish = AES_Encrypt_finish;

function AES_CFB_Decrypt ( options ) {
    AES_CFB.call( this, options );
}

var AES_CFB_Decrypt_prototype = AES_CFB_Decrypt.prototype;
AES_CFB_Decrypt_prototype.reset = AES_reset;
AES_CFB_Decrypt_prototype.process = AES_Decrypt_process;
AES_CFB_Decrypt_prototype.finish = AES_Decrypt_finish;

var get_AES_CFB_instance = function ()
{
    var _instance = null;

    return function ( options ) {
        if ( _instance ) return _instance.reset(options);

//        options = options || {};
//        options.heap = options.heap || _aes_heap_instance;
//        options.asm = options.asm || _aes_asm_instance;

        return _instance = new AES_CFB(options);
    };
}();
