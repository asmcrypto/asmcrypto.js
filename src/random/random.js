var _global_console = global.console,
    _global_crypto = global.crypto,
    _global_date_now = global.Date.now,
    _global_math_random = global.Math.random,
    _global_performance = global.performance;

var _isaac_rand = ISAAC.rand,
    _isaac_seed = ISAAC.seed;

var _random_is_seeded = false,
    _random_is_seed_supplied = false;

/**
 * seed
 *
 * Seeds PRNG with supplied random values.
 *
 * **DISCLAIMER!** Seeding with a poor values is an easiest way shoot your legs, so
 * do not seed until you're know what entropy is and how to obtail high-quality random values,
 * **DO NOT SEED WITH CONSTANT VALUE! YOU'LL GET NO RANDOMNESS FROM CONSTANT!**
 *
 * When no values supplied **and** PRNG hasn't been seeded yet, seeds with:
 *
 * - `crypto.getRandomValues` output (if available, fast method), **or**
 *
 * - special seeding steps are performed (fallback slow method):
 *      - collect entropy from `Date.now` (~ 10 bits), `Math.random` (~50 bits), `performance.now` (if available, µs resolution adds ~10 bits to `Date.now`'s entropy);
 *      - perform key derivation with 4096-rounded `PBKDF2-HMAC-SHA256` salted by `location.href` in order to make seed guessing impractical;
 *      - collect additional entropy from `performance.now` (if available, adds ~10 bits of entropy more);
 *      - seed PRNG with these values (containing ~50 bits of entropy at the worst case and up to ~80 bits at the best).
 *
 * Note that in case of fallback seeding you'll get warning into the console every time you request new random values.
 */
function Random_seed ( buffer ) {
    if ( buffer !== undefined ) {
        _isaac_seed(buffer);
        _random_is_seed_supplied = true;
    }
    else if ( !_random_is_seeded ) {
        if ( _global_crypto !== undefined ) {
            buffer = new Uint32Array(256);
            _global_crypto.getRandomValues(buffer);

            _isaac_seed(buffer);

            _random_is_seed_supplied = true;
        }
        else {
            buffer = new Float64Array(3);
            buffer[0] = _global_date_now();
            buffer[1] = _global_math_random();
            if ( _global_performance !== undefined ) buffer[2] = _global_performance.now();

            buffer = new Uint32Array( pbkdf2_hmac_sha256_bytes( buffer.buffer, global.location.href, 4096, 1024 ).buffer );

            if ( _global_performance !== undefined ) buffer[0] ^= 1000 * _global_performance.now() | 0;

            _isaac_seed(buffer);

            _random_is_seed_supplied = false;
        }
    }
    else {
        throw new IllegalArgumentError("bad seed");
    }

    _random_is_seeded = true;
}

/**
 * getValues
 *
 * Populates the buffer with cryptographically secure random values.
 * A drop-in replacement for `crypto.getRandomValues`.
 *
 * First call also seeds the PRNG if it hasn't been seeded yet, so it may halt for a moment.
 *
 * Take a note that, as PRNG is guaranteed to have cycles at least 2^40 values long,
 * it must be reseeded from time to time. It happens automatically every time 2^40 values
 * are produced and performed by calling seeding routine without arguments (see docs above).
 *
 * Also note that in case of fallback seeding (see docs) you'll get warning into the console every time you request new random values.
 */
function Random_getValues ( buffer ) {
    if ( !_random_is_seeded )
        Random_seed();

    if ( !_random_is_seed_supplied && _global_console !== undefined )
        _global_console.warn("Random number generator hasn't been properly seeded and produces potentially weak values, though it has at least 50 bits of entropy.");

    if ( !is_buffer(buffer) && !is_typed_array(buffer) )
        throw new TypeError("unexpected buffer type");

    var bpos = buffer.byteOffset || 0,
        blen = buffer.byteLength || buffer.length,
        bytes = new Uint8Array( ( buffer.buffer || buffer ), bpos, blen ),
        i, r;

    // TODO reseed upon reaching 2^40 mark
    for ( i = 0; i < blen; i++ ) {
        if ( (i & 3) === 0 ) r = _isaac_rand();
        bytes[i] = r;
        r >>>= 8;
    }
}
