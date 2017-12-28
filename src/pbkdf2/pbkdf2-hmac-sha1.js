import {get_hmac_sha1_instance, hmac_sha1_constructor} from '../hmac/hmac-sha1';
import {pbkdf2_constructor, pbkdf2_reset} from './pbkdf2';
import {is_string} from '../utils';
import {IllegalArgumentError, IllegalStateError} from '../errors';

export function pbkdf2_hmac_sha1_constructor (options ) {
    options = options || {};

    if ( !( options.hmac instanceof hmac_sha1_constructor ) )
        options.hmac = get_hmac_sha1_instance();

    pbkdf2_constructor.call( this, options );

    return this;
}

function pbkdf2_hmac_sha1_generate ( salt, count, length ) {
    if ( this.result !== null )
        throw new IllegalStateError("state must be reset before processing new data");

    if ( !salt && !is_string(salt) )
        throw new IllegalArgumentError("bad 'salt' value");

    count = count || this.count;
    length = length || this.length;

    this.result = new Uint8Array(length);

    var blocks = Math.ceil( length / this.hmac.HMAC_SIZE );

    for ( var i = 1; i <= blocks; ++i ) {
        var j = ( i - 1 ) * this.hmac.HMAC_SIZE;
        var l = ( i < blocks ? 0 : length % this.hmac.HMAC_SIZE ) || this.hmac.HMAC_SIZE;

        this.hmac.reset().process(salt);
        this.hmac.hash.asm.pbkdf2_generate_block( this.hmac.hash.pos, this.hmac.hash.len, i, count, 0 );

        this.result.set( this.hmac.hash.heap.subarray( 0, l ), j );
    }

    return this;
}

var pbkdf2_hmac_sha1_prototype = pbkdf2_hmac_sha1_constructor.prototype;
pbkdf2_hmac_sha1_prototype.reset =   pbkdf2_reset;
pbkdf2_hmac_sha1_prototype.generate = pbkdf2_hmac_sha1_generate;

var pbkdf2_hmac_sha1_instance = null;

export function get_pbkdf2_hmac_sha1_instance () {
    if ( pbkdf2_hmac_sha1_instance === null ) pbkdf2_hmac_sha1_instance = new pbkdf2_hmac_sha1_constructor();
    return pbkdf2_hmac_sha1_instance;
}
