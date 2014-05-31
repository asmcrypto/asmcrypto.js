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

var _random_estimated_entropy = 0,
    _random_required_entropy = 256;

var _assume_strong_system_rng = true;

/**
 * weak_seed
 *
 * Seeds RNG with high-resolution time and single `Math.random()` value, and
 * various other sources. We estimate this may give between ~50-~80 bits of
 * unpredictableness, but this has not been analysed thoroughly or precisely.
 */
function Random_weak_seed () {
    var buffer = new FloatArray(3);
    buffer[0] = _global_date_now();
    buffer[1] = _global_math_random();
    if ( _global_performance !== undefined ) buffer[2] = _global_performance.now();

    // Some clarification about brute-force attack cost:
    // - entire bitcoin network network at ~10^16 hash guesses per second;
    // - each PBKDF2 iteration requires the same number of hashing operations as bitcoin nonce guess;
    // - attacker having such a hashing power is able to break worst-case 50 bits of the randomness in ~3 hours;
    // Sounds sad though attacker having such a hashing power more likely would prefer to mine bitcoins and earn ~$100000 in 3 hours.
    buffer = new Uint32Array( pbkdf2_hmac_sha256_bytes( buffer.buffer, global.location.href, 100000, 32 ).buffer );

    if ( _global_performance !== undefined ) buffer[0] ^= 1000 * _global_performance.now() | 0;

    _isaac_seed(buffer);

    if ( _global_crypto !== undefined ) {
        // if we're seeding ISAAC then assume the system RNG is weak
        buffer = new Uint32Array(256);
        _global_crypto.getRandomValues(buffer);
        _isaac_seed(buffer);
    }

    if ( !_isaac_weak_seeded ) {
        _random_estimated_entropy += 50;
    }
    else if ( _global_performance !== undefined ) {
        _random_estimated_entropy += 20;
    }

    _isaac_weak_seeded = true;
}

/**
 * seed
 *
 * Seeds PRNG with supplied random values if these values have enough entropy.

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

    var bpos = seed.byteOffest || 0,
        blen = seed.byteLength || seed.length,
        buff = new Uint8Array( ( seed.buffer || seed ), bpos, blen );

    _isaac_seed(buff);

    // don't let the user use these bytes again
    var saw_nonzero = false;
    for ( var i = 0; i < buff.length; i++ ) {
        if ( buff[i] ) saw_nonzero = true;
        buff[i] = 0;
    }

    if ( saw_nonzero ) {
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
 * latter *must* be seeded using `Random.seed`, unless `allow_weak` is true.
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
function Random_getValues ( buffer, allow_weak ) {
    // opportunistically seed ISAAC with a weak seed; this hopefully makes an
    // attack harder in the case where the system RNG is weak *and* we haven't
    // seeded ISAAC. but don't make any guarantees to the user about this.
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
