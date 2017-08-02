import {hmac_constructor, hmac_process, _hmac_init_verify, _hmac_key} from './hmac';
import {_sha256_hash_size, get_sha256_instance, sha256_constructor} from '../hash/sha256/sha256';
import {is_string, string_to_bytes} from '../utils';

export function hmac_sha256_constructor (options ) {
    options = options || {};

    if ( !( options.hash instanceof sha256_constructor ) )
        options.hash = get_sha256_instance();

    hmac_constructor.call( this, options );

    return this;
}

function hmac_sha256_reset ( options ) {
    options = options || {};

    this.result = null;
    this.hash.reset();

    var password = options.password;
    if ( password !== undefined ) {
        if ( is_string(password) )
            password = string_to_bytes(password);

        var key = this.key = _hmac_key( this.hash, password );
        this.hash.reset().asm.hmac_init(
            (key[0]<<24)|(key[1]<<16)|(key[2]<<8)|(key[3]),
            (key[4]<<24)|(key[5]<<16)|(key[6]<<8)|(key[7]),
            (key[8]<<24)|(key[9]<<16)|(key[10]<<8)|(key[11]),
            (key[12]<<24)|(key[13]<<16)|(key[14]<<8)|(key[15]),
            (key[16]<<24)|(key[17]<<16)|(key[18]<<8)|(key[19]),
            (key[20]<<24)|(key[21]<<16)|(key[22]<<8)|(key[23]),
            (key[24]<<24)|(key[25]<<16)|(key[26]<<8)|(key[27]),
            (key[28]<<24)|(key[29]<<16)|(key[30]<<8)|(key[31]),
            (key[32]<<24)|(key[33]<<16)|(key[34]<<8)|(key[35]),
            (key[36]<<24)|(key[37]<<16)|(key[38]<<8)|(key[39]),
            (key[40]<<24)|(key[41]<<16)|(key[42]<<8)|(key[43]),
            (key[44]<<24)|(key[45]<<16)|(key[46]<<8)|(key[47]),
            (key[48]<<24)|(key[49]<<16)|(key[50]<<8)|(key[51]),
            (key[52]<<24)|(key[53]<<16)|(key[54]<<8)|(key[55]),
            (key[56]<<24)|(key[57]<<16)|(key[58]<<8)|(key[59]),
            (key[60]<<24)|(key[61]<<16)|(key[62]<<8)|(key[63])
        );
    }
    else {
        this.hash.asm.hmac_reset();
    }

    var verify = options.verify;
    if ( verify !== undefined ) {
        _hmac_init_verify.call( this, verify );
    }
    else {
        this.verify = null;
    }

    return this;
}

function hmac_sha256_finish () {
    if ( this.key === null )
        throw new IllegalStateError("no key is associated with the instance");

    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    var hash = this.hash,
        asm = this.hash.asm,
        heap = this.hash.heap;

    asm.hmac_finish( hash.pos, hash.len, 0 );

    var verify = this.verify;
    var result = new Uint8Array(_sha256_hash_size);
    result.set( heap.subarray( 0, _sha256_hash_size ) );

    if ( verify ) {
        if ( verify.length === result.length ) {
            var diff = 0;
            for ( var i = 0; i < verify.length; i++ ) {
                diff |= ( verify[i] ^ result[i] );
            }
            this.result = !diff;
        } else {
            this.result = false;
        }
    }
    else {
        this.result = result;
    }

    return this;
}

hmac_sha256_constructor.BLOCK_SIZE = sha256_constructor.BLOCK_SIZE;
hmac_sha256_constructor.HMAC_SIZE = sha256_constructor.HASH_SIZE;

var hmac_sha256_prototype = hmac_sha256_constructor.prototype;
hmac_sha256_prototype.reset = hmac_sha256_reset;
hmac_sha256_prototype.process = hmac_process;
hmac_sha256_prototype.finish = hmac_sha256_finish;

var hmac_sha256_instance = null;

export function get_hmac_sha256_instance () {
    if ( hmac_sha256_instance === null ) hmac_sha256_instance = new hmac_sha256_constructor();
    return hmac_sha256_instance;
}
