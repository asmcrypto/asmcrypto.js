import {sha1_asm} from './sha1.asm';
import {hash_finish, hash_process, hash_reset} from '../hash';
import {_heap_init} from '../../utils';

export var _sha1_block_size = 64;
export var _sha1_hash_size = 20;

export function sha1_constructor ( options ) {
    options = options || {};

    this.heap = _heap_init( Uint8Array, options.heap );
    this.asm = options.asm || sha1_asm( { Uint8Array: Uint8Array }, null, this.heap.buffer );

    this.BLOCK_SIZE = _sha1_block_size;
    this.HASH_SIZE = _sha1_hash_size;

    this.reset();
}

sha1_constructor.BLOCK_SIZE = _sha1_block_size;
sha1_constructor.NAME = "sha1";

sha1_constructor.HASH_SIZE = _sha1_hash_size;
var sha1_prototype = sha1_constructor.prototype;
sha1_prototype.reset =   hash_reset;
sha1_prototype.process = hash_process;
sha1_prototype.finish =  hash_finish;

var sha1_instance = null;

export function get_sha1_instance () {
    if ( sha1_instance === null ) sha1_instance = new sha1_constructor( { heapSize: 0x100000 } );
    return sha1_instance;
}
