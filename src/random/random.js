var _global_crypto = global.crypto || global.Crypto || global.msCrypto,
    _global_console = global.console,
    _global_date_now = global.Date.now,
    _global_math_random = global.Math.random,
    _global_performance = global.performance;

var _isaac_rand = ISAAC.rand,
    _isaac_seed = ISAAC.seed,
    _isaac_counter = 0,
    _isaac_weak_seeded = false,
    _isaac_seeded = false;

var _random_guaranteed_entropy = 0,
    _random_required_entropy = 256;

var _assume_strong_system_rng = false;

/**
 * weak_seed
 *
 * Seeds RNG with high-resolution time and single `Math.random()` value.
 * First call adds ~50 bits of entropy at the worst case and up to ~80 bits at the best.
 * Subsequent call adds no entropy at the worst case and up to ~20 bits at the best.
 */
function Random_weak_seed () {
    var buffer = new FloatArray(3);
    buffer[0] = _global_date_now();
    buffer[1] = _global_math_random();
    if ( _global_performance !== undefined ) buffer[2] = _global_performance.now();

    buffer = new Uint32Array( pbkdf2_hmac_sha256_bytes( buffer.buffer, global.location.href, 4096, 1024 ).buffer );

    if ( _global_performance !== undefined ) buffer[0] ^= 1000 * _global_performance.now() | 0;

    _isaac_seed(buffer);

    if ( _global_crypto !== undefined ) {
        // we assume the system rng is weak:
        // if the system rng is strong, then this code path is never called
        buffer = new Uint32Array(256);
        _global_crypto.getRandomValues(buffer);
        _isaac_seed(buffer);
    }

    if ( !_isaac_weak_seeded ) {
        _random_guaranteed_entropy += 50;
    }
    else if ( _global_performance !== undefined ) {
        _random_guaranteed_entropy += 20;
    }

    _isaac_weak_seeded = true;
}


/**
 * seed
 *
 * Seeds PRNG with supplied random values if these values have enough entropy.
 * Returns true if seeding took place, otherwise false.
 *
 * A false return value means the input was not secure; however a true return
 * value does NOT mean the input is necessarily secure, though asmCrypto will
 * be forced to assume this.
 *
 * The input buffer will be zeroed to discourage reuse. You should not copy it
 * or use it anywhere else before passing it into this function.
 *
 * **DISCLAIMER!** Seeding with a poor values is an easiest way shoot your legs, so
 * do not seed until you're know what entropy is and how to obtail high-quality random values,
 * **DO NOT SEED WITH CONSTANT VALUE! YOU'LL GET NO RANDOMNESS FROM CONSTANT!**
 */
function Random_seed ( seed ) {
    if ( !is_buffer(seed) && !is_typed_array(seed) )
        throw new TypeError("bad seed type");

    var bpos = seed.byteOffest || 0,
        blen = seed.byteLength || seed.length,
        buff = new Uint8Array( ( seed.buffer || seed ), bpos, blen );

    _isaac_seed(buff);

    // TODO change to the estimated value
    _random_guaranteed_entropy += 8 * blen;

    // don't let the user use these bytes again
    for ( var i = 0; i < buff.length; i++ ) buff[i] = 0;

    _isaac_seeded = ( _random_guaranteed_entropy  >= _random_required_entropy );

    return _isaac_seeded;
}

/**
 * getValues
 *
 * Populates the buffer with cryptographically secure random values. These are
 * calculated using `crypto.getRandomValues` if it is available, as well as our
 * own ISAAC PRNG implementation.
 *
 * If your system RNG is not known to be strong (currently we assume not for
 * all cases), then you are required to seed ISAAC using `Random.seed`, which
 * has requirements on the randomness you give it.
 *
 * If you don't do this, and allow_weak is true, we will proceed using a weak
 * seed from arbitrary data like high-resolution time and one single value from
 * the insecure Math.random(). You'll also get warnings into the console every
 * time you request new random values.
 *
 * Take a note that, as PRNG is guaranteed to have cycles at least 2^40 values long,
 * it must be reseeded from time to time. It happens automatically every time 2^40 values
 * are produced and performed by calling seeding routine without arguments (see docs above).
 */
function Random_getValues ( buffer, allow_weak ) {
    // opportunistically seed ISAAC with a weak seed; this prevents predictible output
    // in case of seeding with predictible seed prior to the first call to `getValues`
    if ( !_isaac_weak_seeded )
        Random_weak_seed();

    // if we have no strong sources then the RNG is weak, handle it
    var have_strong_system_rng = ( _global_crypto !== undefined ) && _assume_strong_system_rng;
    if ( !_isaac_seeded && !have_strong_system_rng ) {
        if ( !allow_weak ) {
            throw new Error("No strong RNGs available. Try calling asmCrypto.random.seed() with good entropy.");
        }

        // warn about ISAAC
        if ( _global_console !== undefined ) {
            _global_console.warn("asmCrypto PRNG hasn't been properly seeded; your security is greatly lowered.");
        }
    }

    // proceed to get random values
    if ( !is_buffer(buffer) && !is_typed_array(buffer) )
        throw new TypeError("unexpected buffer type");

    var bpos = buffer.byteOffset || 0,
        blen = buffer.byteLength || buffer.length,
        bytes = new Uint8Array( ( buffer.buffer || buffer ), bpos, blen ),
        i, r;

    // apply system rng
    if ( _global_crypto !== undefined ) {
        _global_crypto.getRandomValues(bytes);
    }

    // apply isaac rng
    for ( i = 0; i < blen; i++ ) {
        if ( (i & 3) === 0 ) {
            if ( _isaac_counter >= 0x10000000000 ) {
                Random_weak_seed();
                _isaac_counter = 0;
            }
            r = _isaac_rand();
            _isaac_counter++;
        }
        bytes[i] ^= r;
        r >>>= 8;
    }
}

/**
 * getNumber
 *
 * A drop-in `Math.random` replacement.
 * Intended for prevention of random material leakage out of the user's host.
 */
function Random_getNumber () {
    if ( _isaac_counter >= 0x10000000000 ) {
        Random_weak_seed();
        _isaac_counter = 0;
    }

    var n = ( 0x100000 * _isaac_rand() + ( _isaac_rand() >>> 12 ) ) / 0x10000000000000;
    _isaac_counter += 2;

    return n;
}
