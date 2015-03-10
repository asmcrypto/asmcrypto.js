/**
 * Cipher Block Chaining Mode (CBC)
 */

function AES_CBC ( options ) {
    this.padding = true;
    this.iv = null;

    AES.call( this, options );

    this.mode = 'CBC';
}

var AES_CBC_prototype = AES_CBC.prototype;
AES_CBC_prototype.BLOCK_SIZE = 16;
AES_CBC_prototype.reset = AES_reset;
AES_CBC_prototype.encrypt = AES_Encrypt_finish;
AES_CBC_prototype.decrypt = AES_Decrypt_finish;

function AES_CBC_Encrypt ( options ) {
    AES_CBC.call( this, options );
}

var AES_CBC_Encrypt_prototype = AES_CBC_Encrypt.prototype;
AES_CBC_Encrypt_prototype.BLOCK_SIZE = 16;
AES_CBC_Encrypt_prototype.reset = AES_reset;
AES_CBC_Encrypt_prototype.process = AES_Encrypt_process;
AES_CBC_Encrypt_prototype.finish = AES_Encrypt_finish;

function AES_CBC_Decrypt ( options ) {
    AES_CBC.call( this, options );
}

var AES_CBC_Decrypt_prototype = AES_CBC_Decrypt.prototype;
AES_CBC_Decrypt_prototype.BLOCK_SIZE = 16;
AES_CBC_Decrypt_prototype.reset = AES_reset;
AES_CBC_Decrypt_prototype.process = AES_Decrypt_process;
AES_CBC_Decrypt_prototype.finish = AES_Decrypt_finish;
