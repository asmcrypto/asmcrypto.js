/**
 * Electronic Code Book Mode (ECB)
 */

import {AES, AES_Decrypt_finish, AES_Decrypt_process, AES_Encrypt_finish, AES_Encrypt_process, AES_reset} from '../aes';

export function AES_ECB_constructor (options ) {
    this.padding = true;

    AES.call( this, options );

    this.mode = 'ECB';
}

var AES_ECB_prototype = AES_ECB_constructor.prototype;
AES_ECB_prototype.BLOCK_SIZE = 16;
AES_ECB_prototype.reset = AES_reset;
AES_ECB_prototype.encrypt = AES_Encrypt_finish;
AES_ECB_prototype.decrypt = AES_Decrypt_finish;

export function AES_ECB_Encrypt ( options ) {
    AES_ECB_constructor.call( this, options );
}

var AES_ECB_Encrypt_prototype = AES_ECB_Encrypt.prototype;
AES_ECB_Encrypt_prototype.BLOCK_SIZE = 16;
AES_ECB_Encrypt_prototype.reset = AES_reset;
AES_ECB_Encrypt_prototype.process = AES_Encrypt_process;
AES_ECB_Encrypt_prototype.finish = AES_Encrypt_finish;

export function AES_ECB_Decrypt ( options ) {
    AES_ECB_constructor.call( this, options );
}

var AES_ECB_Decrypt_prototype = AES_ECB_Decrypt.prototype;
AES_ECB_Decrypt_prototype.BLOCK_SIZE = 16;
AES_ECB_Decrypt_prototype.reset = AES_reset;
AES_ECB_Decrypt_prototype.process = AES_Decrypt_process;
AES_ECB_Decrypt_prototype.finish = AES_Decrypt_finish;
