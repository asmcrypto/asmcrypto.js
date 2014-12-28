/**
 * Counter Mode (CTR)
 */

function AES_CTR ( options ) {
    this.iv = null;

    AES.call( this, options );

    this.mode = 'CTR';
}

function AES_CTR_Crypt ( options ) {
    AES_CTR.call( this, options );
}

var AES_CTR_prototype = AES_CTR.prototype;
AES_CTR_prototype.reset = AES_reset;
AES_CTR_prototype.encrypt = AES_Encrypt_finish;
AES_CTR_prototype.decrypt = AES_Encrypt_finish;

var AES_CTR_Crypt_prototype = AES_CTR_Crypt.prototype;
AES_CTR_Crypt_prototype.reset = AES_reset;
AES_CTR_Crypt_prototype.process = AES_Encrypt_process;
AES_CTR_Crypt_prototype.finish = AES_Encrypt_finish;

var get_AES_CTR_instance = function ()
{
    var _instance = null;

    return function ( options ) {
        if ( _instance ) return _instance.reset(options);

//        options = options || {};
//        options.heap = options.heap || _aes_heap_instance;
//        options.asm = options.asm || _aes_asm_instance;

        return _instance = new AES_CTR(options);
    };
}();
