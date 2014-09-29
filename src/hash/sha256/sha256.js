var _sha256_block_size = 64,
    _sha256_hash_size = 32;

function sha256_constructor ( options ) {
    options = options || {};
    options.heapSize = options.heapSize || 4096;

    if ( options.heapSize <= 0 || options.heapSize % 4096 )
        throw new IllegalArgumentError("heapSize must be a positive number and multiple of 4096");

    this.heap = options.heap || new Uint8Array(options.heapSize);
    this.asm = options.asm || sha256_asm( global, null, this.heap.buffer );

    this.BLOCK_SIZE = _sha256_block_size;
    this.HASH_SIZE = _sha256_hash_size;

    this.reset();
}

sha256_constructor.BLOCK_SIZE = _sha256_block_size;
sha256_constructor.HASH_SIZE = _sha256_hash_size;
var sha256_prototype = sha256_constructor.prototype;
sha256_prototype.reset =   hash_reset;
sha256_prototype.process = hash_process;
sha256_prototype.finish =  hash_finish;

var sha256_instance = null;

function get_sha256_instance () {
    if ( sha256_instance === null ) sha256_instance = new sha256_constructor( { heapSize: 0x100000 } );
    return sha256_instance;
}
