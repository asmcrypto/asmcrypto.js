var _global_console = global.console,
    _global_crypto = global.crypto,
    _global_date_now = global.Date.now,
    _global_math_random = global.Math.random,
    _global_performance = global.performance;

var _isaac_rand = ISAAC.rand,
    _isaac_seed = ISAAC.seed;

var _random_weak_seeded = false,
    _bytes_entropy_required = 64,
    _random_seeded = false;


function _bytes_entropy_estimate(byte_array) {
    var counts = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    for (var i = 0; i < byte_array.length; i++) {
        var lo = byte_array[i] & 0xf;
        var hi = (byte_array[i] >> 4) & 0xf;
        counts[lo]++;
        counts[hi]++;
    }
    return counts.map(function(x) {
        return x ? -(x/byte_array.length/2 * Math.log(x/byte_array.length/2) / Math.log(2)): 0;
    }).reduce(function(a, b){
        return a+b;
    }, 0) / 4 * byte_array.length;
}


function _random_weak_seed() {
    var buffer = new Float64Array(3);
    buffer[0] = _global_date_now();
    buffer[1] = _global_math_random();
    if ( _global_performance !== undefined ) buffer[2] = _global_performance.now();

    buffer = new Uint32Array( pbkdf2_hmac_sha256_bytes( buffer.buffer, global.location.href, 4096, 1024 ).buffer );

    if ( _global_performance !== undefined ) buffer[0] ^= 1000 * _global_performance.now() | 0;

    _isaac_seed(buffer);
    _random_weak_seeded = true;
}


/**
 * seed
 *
 * Seeds PRNG with supplied random values if these values have enough entropy.
 * Returns true if seeding took place, otherwise false.
 *
 * A false return value means the input was not secure; however a true return
 * value does NOT mean the input is necessarily secure.
 *
 * The input buffer will be zeroed to discourage reuse. You should not copy it
 * or use it anywhere else before passing it into this function.
 *
 * **DISCLAIMER!** Seeding with a poor values is an easiest way shoot your legs, so
 * do not seed until you're know what entropy is and how to obtail high-quality random values,
 * **DO NOT SEED WITH CONSTANT VALUE! YOU'LL GET NO RANDOMNESS FROM CONSTANT!**
 */
function Random_seed ( buffer ) {
    var bpos = buffer.byteOffset || 0,
        blen = buffer.byteLength || buffer.length,
        bytes = new Uint8Array( ( buffer.buffer || buffer ), bpos, blen );

    if (_bytes_entropy_estimate(bytes) < _bytes_entropy_required) {
        return false;
    } else {
        _isaac_seed(bytes);
        // don't let the user use these bytes again
        for (var i=0; i<bytes.length; i++) bytes[i] = 0;
        return _random_seeded = true;
    }
}

/**
 * getValues
 *
 * Populates the buffer with cryptographically secure random values.
 * Delegates to `crypto.getRandomValues` if it is available.
 *
 * Otherwise, we fall back to asmCrypto's own implementation of the ISAAC PRNG.
 * This must be first seeded using `Random.seed`, which has requirements on
 * the randomness you give it.
 *
 * If you don't manually call `Random.seed`, and allow_weak is true, we will
 * proceed using a weak seed from things like high-resolution time and one
 * single value from the insecure Math.random(). In this case you'll still get
 * warnings into the console every time you request new random values.
 *
 * Take a note that, as PRNG is guaranteed to have cycles at least 2^40 values long,
 * it must be reseeded from time to time. It happens automatically every time 2^40 values
 * are produced and performed by calling seeding routine without arguments (see docs above).
 */
function Random_getValues ( buffer, allow_weak ) {
    if ( !is_buffer(buffer) && !is_typed_array(buffer) )
        throw new TypeError("unexpected buffer type");

    var bpos = buffer.byteOffset || 0,
        blen = buffer.byteLength || buffer.length,
        bytes = new Uint8Array( ( buffer.buffer || buffer ), bpos, blen ),
        i, r;

    // if we don't have a strong rng
    if ( !_global_crypto && !_random_seeded ) {
        // set a weak seed
        if ( allow_weak && !_random_weak_seeded )
            _random_weak_seed();

        // warn or error
        if ( !allow_weak ) {
            throw new Error("WebCrypto not available, and asmCrypto PRNG hasn't been properly seeded");
        } else if ( _global_console !== undefined ) {
            _global_console.warn("asmCrypto PRNG hasn't been properly seeded " +
                "and produces potentially weak values");
        }
    }

    if ( _global_crypto ) {
        _global_crypto.getRandomValues(bytes);
    }

    // TODO reseed upon reaching 2^40 mark
    for ( i = 0; i < blen; i++ ) {
        if ( (i & 3) === 0 ) r = _isaac_rand();
        bytes[i] ^= r;
        r >>>= 8;
    }
}
