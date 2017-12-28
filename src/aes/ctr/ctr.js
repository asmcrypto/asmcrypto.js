/**
 * Counter Mode (CTR)
 */

import {AES, AES_Encrypt_finish, AES_Encrypt_process, AES_reset} from '../aes';
import {is_buffer, is_bytes, is_number, is_string, string_to_bytes} from '../../utils';
import {IllegalArgumentError} from '../../errors';

export function AES_CTR_constructor (options ) {
    this.nonce = null,
    this.counter = 0,
    this.counterSize = 0;

    AES.call( this, options );

    this.mode = 'CTR';
}

export function AES_CTR_Crypt ( options ) {
    AES_CTR_constructor.call( this, options );
}

export function AES_CTR_set_options ( nonce, counter, size ) {
    if ( size !== undefined ) {
        if ( size < 8 || size > 48 )
            throw new IllegalArgumentError("illegal counter size");

        this.counterSize = size;

        var mask = Math.pow( 2, size ) - 1;
        this.asm.set_mask( 0, 0, (mask / 0x100000000)|0, mask|0 );
    }
    else {
        this.counterSize = size = 48;
        this.asm.set_mask( 0, 0, 0xffff, 0xffffffff );
    }

    if ( nonce !== undefined ) {
        if ( is_buffer(nonce) || is_bytes(nonce) ) {
            nonce = new Uint8Array(nonce);
        }
        else if ( is_string(nonce) ) {
            nonce = string_to_bytes(nonce);
        }
        else {
            throw new TypeError("unexpected nonce type");
        }

        var len = nonce.length;
        if ( !len || len > 16 )
            throw new IllegalArgumentError("illegal nonce size");

        this.nonce = nonce;

        var view = new DataView( new ArrayBuffer(16) );
        new Uint8Array(view.buffer).set(nonce);

        this.asm.set_nonce( view.getUint32(0), view.getUint32(4), view.getUint32(8), view.getUint32(12) );
    }
    else {
        throw new Error("nonce is required");
    }

    if ( counter !== undefined ) {
        if ( !is_number(counter) )
            throw new TypeError("unexpected counter type");

        if ( counter < 0 || counter >= Math.pow( 2, size ) )
            throw new IllegalArgumentError("illegal counter value");

        this.counter = counter;

        this.asm.set_counter( 0, 0, (counter / 0x100000000)|0, counter|0 );
    }
    else {
        this.counter = counter = 0;
    }
}

function AES_CTR_reset ( options ) {
    options = options || {};

    AES_reset.call( this, options );

    AES_CTR_set_options.call( this, options.nonce, options.counter, options.counterSize );

    return this;
}

var AES_CTR_prototype = AES_CTR_constructor.prototype;
AES_CTR_prototype.BLOCK_SIZE = 16;
AES_CTR_prototype.reset = AES_CTR_reset;
AES_CTR_prototype.encrypt = AES_Encrypt_finish;
AES_CTR_prototype.decrypt = AES_Encrypt_finish;

var AES_CTR_Crypt_prototype = AES_CTR_Crypt.prototype;
AES_CTR_Crypt_prototype.BLOCK_SIZE = 16;
AES_CTR_Crypt_prototype.reset = AES_CTR_reset;
AES_CTR_Crypt_prototype.process = AES_Encrypt_process;
AES_CTR_Crypt_prototype.finish = AES_Encrypt_finish;
