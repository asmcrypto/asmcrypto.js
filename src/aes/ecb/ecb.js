/**
 * Electronic Code Book Mode (ECB)
 */

function AES_ECB ( options ) {
    this.padding = true;

    AES.call( this, options );

    this.mode = 'ECB';
}

var AES_ECB_prototype = AES_ECB.prototype;
AES_ECB_prototype.reset = AES_reset;
AES_ECB_prototype.encrypt = AES_Encrypt_finish;
AES_ECB_prototype.decrypt = AES_Decrypt_finish;

function AES_ECB_Encrypt ( options ) {
    AES_ECB.call( this, options );
}

var AES_ECB_Encrypt_prototype = AES_ECB_Encrypt.prototype;
AES_ECB_Encrypt_prototype.reset = AES_reset;
AES_ECB_Encrypt_prototype.process = AES_Encrypt_process;
AES_ECB_Encrypt_prototype.finish = AES_Encrypt_finish;

function AES_ECB_Decrypt ( options ) {
    AES_ECB.call( this, options );
}

var AES_ECB_Decrypt_prototype = AES_ECB_Decrypt.prototype;
AES_ECB_Decrypt_prototype.reset = AES_reset;
AES_ECB_Decrypt_prototype.process = AES_Decrypt_process;
AES_ECB_Decrypt_prototype.finish = AES_Decrypt_finish;

var get_AES_ECB_instance = function ()
{
    var _instance = null;

    return function ( options ) {
        if ( _instance ) return _instance.reset(options);

//        options = options || {};
//        options.heap = options.heap || _aes_heap_instance;
//        options.asm = options.asm || _aes_asm_instance;

        return _instance = new AES_ECB(options);
    };
}();
