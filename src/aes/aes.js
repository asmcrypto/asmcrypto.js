var _aes_block_size = 16;

function _aes_constructor ( options ) {
    options = options || {};

    this.BLOCK_SIZE = _aes_block_size;

    this.heap = _heap_init( Uint8Array, options );
    this.asm = options.asm || aes_asm( global, null, this.heap.buffer );
    this.pos = _aes_heap_start;
    this.len = 0;

    this.key = null;
    this.result = null;

    this.reset( options );
}

function _aes_reset ( options ) {
    options = options || {};

    this.result = null;
    this.pos = _aes_heap_start;
    this.len = 0;

    var asm = this.asm;

    var key = options.key;
    if ( key !== undefined ) {
        if ( is_buffer(key) || is_bytes(key) ) {
            key = new Uint8Array(key);
        }
        else if ( is_string(key) ) {
            key = string_to_bytes(key);
        }
        else {
            throw new TypeError("unexpected key type");
        }

        if ( key.length === 16 ) {
            asm.init_key_128( key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]);
        }
        else if ( key.length === 24 ) {
            // TODO support of 192-bit keys
            throw new IllegalArgumentError("illegal key size");
        }
        else if ( key.length === 32 ) {
            asm.init_key_256( key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15], key[16], key[17], key[18], key[19], key[20], key[21], key[22], key[23], key[24], key[25], key[26], key[27], key[28], key[29], key[30], key[31]);
        }
        else {
            throw new IllegalArgumentError("illegal key size");
        }

        this.key = key;
    }

    return this;
}

function _aes_init_iv ( iv ) {
    var asm = this.asm;

    if ( iv !== undefined ) {
        if ( is_buffer(iv) || is_bytes(iv) ) {
            iv = new Uint8Array(iv);
        }
        else if ( is_string(iv) ) {
            iv = string_to_bytes(iv);
        }
        else {
            throw new TypeError("unexpected iv type");
        }

        if ( iv.length !== _aes_block_size )
            throw new IllegalArgumentError("illegal iv size");

        this.iv = iv;
        asm.init_state( iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], iv[12], iv[13], iv[14], iv[15] );
    }
    else {
        this.iv = null;
        asm.init_state( 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 );
    }
}
