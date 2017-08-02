/**
 * Output Feedback (OFB)
 */

import {AES, AES_Encrypt_finish, AES_Encrypt_process, AES_reset} from '../aes';

export function AES_OFB_constructor (options ) {
    this.iv = null;

    AES.call( this, options );

    this.mode = 'OFB';
}

export function AES_OFB_Crypt ( options ) {
    AES_OFB_constructor.call( this, options );
}

var AES_OFB_prototype = AES_OFB_constructor.prototype;
AES_OFB_prototype.BLOCK_SIZE = 16;
AES_OFB_prototype.reset = AES_reset;
AES_OFB_prototype.encrypt = AES_Encrypt_finish;
AES_OFB_prototype.decrypt = AES_Encrypt_finish;

var AES_OFB_Crypt_prototype = AES_OFB_Crypt.prototype;
AES_OFB_Crypt_prototype.BLOCK_SIZE = 16;
AES_OFB_Crypt_prototype.reset = AES_reset;
AES_OFB_Crypt_prototype.process = AES_Encrypt_process;
AES_OFB_Crypt_prototype.finish = AES_Encrypt_finish;
