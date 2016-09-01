var _global_console = global.console,
    _global_date_now = global.Date.now,
    _global_math_random = global.Math.random,
    _global_performance = global.performance,
    _global_crypto = global.crypto || global.msCrypto,
    _global_crypto_getRandomValues;

if ( _global_crypto !== undefined )
    _global_crypto_getRandomValues = _global_crypto.getRandomValues;

var _isaac_rand = ISAAC.rand,
    _isaac_seed = ISAAC.seed,
    _isaac_counter = 0,
    _isaac_weak_seeded = false,
    _isaac_seeded = false;

var _random_estimated_entropy = 0,
    _random_required_entropy = 256,
    _random_allow_weak = false,
    _random_skip_system_rng_warning = false,
    _random_warn_callstacks = {};

var _hires_now;
if ( _global_performance !== undefined ) {
    _hires_now = function () { return 1000 * _global_performance.now() | 0 };
}
else {
    var _hires_epoch = 1000 * _global_date_now() | 0;
    _hires_now = function () { return 1000 * _global_date_now() - _hires_epoch | 0 };
}

/**
 * weak_seed
 *
 * Seeds RNG with native `crypto.getRandomValues` output or with high-resolution
 * time and single `Math.random()` value, and various other sources.
 *
 * We estimate this may give at least ~50 bits of unpredictableness,
 * but this has not been analysed thoroughly or precisely.
 */
function Random_weak_seed () {
    if ( _global_crypto !== undefined ) {
        buffer = new Uint8Array(32);
        _global_crypto_getRandomValues.call( _global_crypto, buffer );

        _isaac_seed(buffer);
    }
    else {
        // Some clarification about brute-force attack cost:
        // - entire bitcoin network operates at ~10^16 hash guesses per second;
        // - each PBKDF2 iteration requires the same number of hashing operations as bitcoin nonce guess;
        // - attacker having such a hashing power is able to break worst-case 50 bits of the randomness in ~3 hours;
        // Sounds sad though attacker having such a hashing power more likely would prefer to mine bitcoins.
        var buffer = new FloatArray(3),
            i, t;

        buffer[0] = _global_math_random();
        buffer[1] = _global_date_now();
        buffer[2] = _hires_now();

        buffer = new Uint8Array(buffer.buffer);

        var pbkdf2 = get_pbkdf2_hmac_sha256_instance();
        for ( i = 0; i < 100; i++ ) {
            buffer = pbkdf2.reset( { password: buffer } ).generate( global.location.href, 1000, 32 ).result;
            t = _hires_now();
            buffer[0] ^= t >>> 24, buffer[1] ^= t >>> 16, buffer[2] ^= t >>> 8, buffer[3] ^= t;
        }

        _isaac_seed(buffer);
    }

    _isaac_counter = 0;

    _isaac_weak_seeded = true;
}

/**
 * seed
 *
 * Seeds PRNG with supplied random values if these values have enough entropy.
 *
 * A false return value means the RNG is currently insecure; however a true
 * return value does not mean it is necessarily secure (depending on how you
 * collected the seed) though asmCrypto will be forced to assume this.
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

    var bpos = seed.byteOffset || 0,
        blen = seed.byteLength || seed.length,
        buff = new Uint8Array( ( seed.buffer || seed ), bpos, blen );

    _isaac_seed(buff);

    _isaac_counter = 0;

    // don't let the user use these bytes again
    var nonzero = 0;
    for ( var i = 0; i < buff.length; i++ ) {
        nonzero |= buff[i];
        buff[i] = 0;
    }

    if ( nonzero !== 0 ) {
        // TODO we could make a better estimate, but half-length is a prudent
        // simple measure that seems unlikely to over-estimate
        _random_estimated_entropy += 4 * blen;
    }

    _isaac_seeded = ( _random_estimated_entropy  >= _random_required_entropy );

    return _isaac_seeded;
}

/**
 * getValues
 *
 * Populates the buffer with cryptographically secure random values. These are
 * calculated using `crypto.getRandomValues` if it is available, as well as our
 * own ISAAC PRNG implementation.
 *
 * If the former is not available (older browsers such as IE10 [1]), then the
 * latter *must* be seeded using `Random.seed`, unless `asmCrypto.random.allowWeak` is true.
 *
 * *We assume the system RNG is strong*; if you cannot afford this risk, then
 * you should also seed ISAAC using `Random.seed`. This is advisable for very
 * important situations, such as generation of long-term secrets. See also [2].
 *
 * [1] https://developer.mozilla.org/en-US/docs/Web/API/window.crypto.getRandomValues
 * [2] https://en.wikipedia.org/wiki/Dual_EC_DRBG
 *
 * In all cases, we opportunistically seed using various arbitrary sources
 * such as high-resolution time and one single value from the insecure
 * Math.random(); however this is not reliable as a strong security measure.
 */
function Random_getValues ( buffer ) {
    // opportunistically seed ISAAC with a weak seed; this hopefully makes an
    // attack harder in the case where the system RNG is weak *and* we haven't
    // seeded ISAAC. but don't make any guarantees to the user about this.
    if ( !_isaac_weak_seeded )
        Random_weak_seed();

    // if we have no strong sources then the RNG is weak, handle it
    if ( !_isaac_seeded && _global_crypto === undefined ) {
        if ( !_random_allow_weak )
            throw new SecurityError("No strong PRNGs available. Use asmCrypto.random.seed().");

        if ( _global_console !== undefined )
            _global_console.error("No strong PRNGs available; your security is greatly lowered. Use asmCrypto.random.seed().");
    }

    // separate warning about assuming system RNG strong
    if ( !_random_skip_system_rng_warning && !_isaac_seeded && _global_crypto !== undefined && _global_console !== undefined ) {
        // Hacky way to get call stack
        var s = new Error().stack;
        _random_warn_callstacks[s] |= 0;
        if ( !_random_warn_callstacks[s]++ )
            _global_console.warn("asmCrypto PRNG not seeded; your security relies on your system PRNG. If this is not acceptable, use asmCrypto.random.seed().");
    }

    // proceed to get random values
    if ( !is_buffer(buffer) && !is_typed_array(buffer) )
        throw new TypeError("unexpected buffer type");

    var bpos = buffer.byteOffset || 0,
        blen = buffer.byteLength || buffer.length,
        bytes = new Uint8Array( ( buffer.buffer || buffer ), bpos, blen ),
        i, r;

    // apply system rng
    if ( _global_crypto !== undefined )
        _global_crypto_getRandomValues.call( _global_crypto, bytes );

    // apply isaac rng
    for ( i = 0; i < blen; i++ ) {
        if ( (i & 3) === 0 ) {
            if ( _isaac_counter >= 0x10000000000 ) Random_weak_seed();
            r = _isaac_rand();
            _isaac_counter++;
        }
        bytes[i] ^= r;
        r >>>= 8;
    }

    return buffer;
}

/**
 * getNumber
 *
 * A drop-in `Math.random` replacement.
 * Intended for prevention of random material leakage out of the user's host.
 */
function Random_getNumber () {
    if ( !_isaac_weak_seeded || _isaac_counter >= 0x10000000000 )
        Random_weak_seed();

    var n = ( 0x100000 * _isaac_rand() + ( _isaac_rand() >>> 12 ) ) / 0x10000000000000;
    _isaac_counter += 2;

    return n;
}
