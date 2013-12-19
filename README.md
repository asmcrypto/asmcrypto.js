asmCrypto
=========

JavaScript implementation of popular cryptographic utilities with performance in mind.

[Grunt](http://gruntjs.com/) is required to build this.

Synopsis
--------

Add `<script src="path/to/asmcrypto.js"></script>` into your page.

    // Hash whole string at once
    digest = asmCrypto.SHA256.hex("The quick brown fox jumps over the lazy dog");

    // Or hash it chunk-by-chunk
    hash = new asmCrypto.SHA256;
    hash.process("The quick brown");
    hash.process(" fox jumps over the ");
    hash.process("lazy dog");
    digest = hash.finish().asHex(); // also you can chain method calls

Index
-----

* [Download] (#download)
* [Build & Test](#build--test)
* [Performance](#performance)
* [API Reference](#api-reference)
    * [Message Digest](#sha256)
        * [SHA256](#sha256)
    * [Hash-based Message Authentication](#hmac)
        * [HMAC-SHA256](#hmac_sha256)
    * [Password-based Key Derivation](#pbkdf2)
        * [PBKDF2-HMAC-SHA256](#pbkdf2_hmac_sha256)
    * [Block Cipher](#aes)
        * [AES](#aes)
* [Bugs & TODO](#bugs--todo)
* [Donate](#donate)

Download
--------

* [Compressed JS file](http://vibornoff.com/asmcrypto.js) 67KB,
* [Source Map file](http://vibornoff.com/asmcrypto.js.map) 33KB,
* [All-in-One archive](http://vibornoff.com/asmcrypto.tar.gz) 56KB.

Build & Test
------------

Before you start check that [Grunt](http://gruntjs.com/) is installed:

    grunt --version

Then download and build the stuff:

    git clone https://github.com/vibornoff/asmcrypto.js.git
    cd asmcrypto.js/
    git submodule update --init
    npm install
    grunt

After build is complete open `test.html` in your browser and check that all tests are passed.

Congratulations! Now you have your `asmcrypto.js` and `asmcrypto.js.map` ready to use ☺

Performance
-----------

In the development of this project, special attention was paid to the performance issues.
In the result of all the optimizations made this stuff is pretty fast under Firefox and Chrome.

My *Intel® Core™ i7-3770 CPU @ 3.40GHz* typical processing speeds are:
* *Chrome/31.0*
    * SHA256: 51 MiB/s (**9 times faster** than *SJCL* and *CryptoJS*)
    * AES-CBC: 47 MiB/s (**13 times faster** than *CryptoJS* and **20 times faster** than *SJCL*)
* *Firefox/26.0*
    * SHA256: 144 MiB/s (**5 times faster** than *CryptoJS* and **20 times faster** than *SJCL*)
    * AES-CBC: 81 MiB/s (**3 times faster** than *CryptoJS* and **8 times faster** than *SJCL*)

See benchmarks:
* [SHA256](http://jsperf.com/sha256/34),
* [HMAC-SHA256](http://jsperf.com/hmac-sha256/1),
* [PBKDF2-HMAC-SHA256](http://jsperf.com/pbkdf2-hmac-sha256/2),
* [AES](http://jsperf.com/aes).

API Reference
-------------

### SHA256

[Secure Hash Algorithm](http://en.wikipedia.org/wiki/SHA-2) — a cryptographic hash function with 256-bit output.

#### Static methods and constants

##### SHA256.BLOCK_SIZE = 64

##### SHA256.HASH_SIZE = 32

##### SHA256.hex( data )

Shorthand for `staticSha256Instance.reset().process(data).finish().asHex()`.

Calculates message digest of the supplied input `data` (can be a binary string or `ArrayBuffer`/`Uint8Array` object).

Returns a string containing hex-encoded message digest.

Throws
* `TypeError` when something ridiculous is supplied as input data.

##### SHA256.base64( data )

Shorthand for `staticSha256Instance.reset().process(data).finish().asBase64()`.

Calculates message digest of the supplied input `data` (can be a binary string or `ArrayBuffer`/`Uint8Array` object).

Returns a string containing hex-encoded message digest.

Throws
* `TypeError` when something ridiculous is supplied as input data.

#### Constructor

##### SHA256(options)

Constructs new instance of `SHA256` object.

Advanced `options`:
* `heapSize` — asm.js heap size to allocate for hasher, must be a multiple of 4096, default is 4096.

#### Methods and properties

##### sha256.BLOCK_SIZE = 64

##### sha256.HASH_SIZE = 32

##### sha256.reset()

Resets internal state.

##### sha256.process( data )

Updates internal state with the supplied input `data` (can be a binary string or `ArrayBuffer`/`Uint8Array` object).

Throws
* `IllegalStateError` when trying to update finish'ed state,
* `TypeError` when something ridiculous is supplied as input data.

##### sha256.finish()

Finishes hash calculation.

Throws
* `IllegalStateError` when trying to finish already finish'ed state,

##### sha256.asHex()

Returns string representing hex-encoded message digest.

Throws
* `IllegalStateError` when trying to get non-`finish`'ed state.

##### sha256.asBase64()

Returns string representing base64-encoded message digest.

Throws
* `IllegalStateError` when trying to get non-`finish`'ed state.

##### sha256.asArrayBuffer()

Returns raw message digest as an `ArrayBuffer` object.

Throws
* `IllegalStateError` when trying to get non-`finish`'ed state.

##### sha256.asBinaryString()

Returns raw message digest as a binary string.

Throws
* `IllegalStateError` when trying to get non-`finish`'ed state.

### HMAC

[Hash-based Message Authentication Code](http://en.wikipedia.org/wiki/HMAC)

Used to calculate message authentication code with a cryptographic hash function
in combination with a secret cryptographic key.

#### Static methods and constants

#### HMAC_SHA256.BLOCK_SIZE = 64

#### HMAC_SHA256.HMAC_SIZE = 32

#### HMAC_SHA256.hex( password, data )

Shorthand for `staticHmacSha256Instance.reset(password).process(data).finish().asHex()`.

Calculates HMAC-SHA256 of `data` with `password`. Both can be either binary strings or `Uint8Array`/`ArrayBuffer` objects.

Returns a string containing hex-encoded message authentication code.

Throws
* `TypeError` when something ridiculous is supplied as input data.

#### HMAC_SHA256.base64( password, data )

Shorthand for `staticHmacSha256Instance.reset(password).process(data).finish().asBase64()`.

Calculates HMAC-SHA256 of `data` with `password`. Both can be either binary strings or `Uint8Array`/`ArrayBuffer` objects.

Returns a string containing base64-encoded message authentication code.

Throws
* `TypeError` when something ridiculous is supplied as input data.

#### Constructors

##### HMAC_SHA256( password, options )

Constructs an instatnce of HMAC with SHA256 underlying hash function.

If `password` is specified associates it with the instance.

Advanced options can be passed via an `options` object:
* `heapSize` — asm.js heap size to allocate for hasher, must be a multiple of 4096, default is 4096.

#### Methods and properties

##### hmac.BLOCK_SIZE

Size (in bytes) of the underlying hash function block.

##### hmac.HMAC_SIZE

Size (in bytes) of the output.

##### hmac.reset( password )

Resets internal state.

If `password` is specified reassociates it with the instance (or associates it
for the first time if it wasn't associated before).

Throws
* `IllegalStateError` when `password` is required to be associated for the first time,
* `TypeError` when something strange provided instead of the password.

##### hmac.process( data )

Updates internal state with the supplied input `data`.

Input data can be a binary string or instance of `ArrayBuffer`/`Uint8Array` object.

Throws
* `IllegalStateError` when trying to update `finish`'ed state or when no password associated with the instance,
* `TypeError` when something ridiculous is supplied as input data.

##### hmac.finish()

Finishes HMAC calculation.

Throws
* `IllegalStateError` when trying to finish already `finish`'ed state or when no password associated with the instance,

##### hmac.asHex(), hmac.asBase64(), hmac.asArrayBuffer(), hmac.asBinaryString()

Same as for [SHA256](#sha256).

### PBKDF2

[Password-Based Key Derivation Function 2](http://en.wikipedia.org/wiki/PBKDF2)

Applies a cryptographic hash function to the input password or passphrase along with a salt value and repeats the process many times to produce a derived key,
which can then be used as a cryptographic key in subsequent operations. The added computational work makes password cracking much more difficult.

#### Constructors

##### PBKDF2_HMAC_SHA256( password, options )

Constructs an instatce of PBKDF2 key deriver with HMAC-SHA256 used as pseudo-random function.

If `password` is supplied, associates it with the instance.

Additional options can be passed via an `options` object:
* `count` — number of iterations to perform, default is 4096;
* `length` — desired output key length in bytes, default is 32.

Advanced options:
* `heapSize` — asm.js heap size to allocate, must be a multiple of 4096, default is 4096.

#### Methods and properties

##### pbkdf2.count

Number of iterations to perform.

##### pbkdf2.length

Desired key length.

##### pbkdf2.result

Derived key value.

##### pbkdf2.reset( password )

Reset internal state.

If `password` is supplied reassociates it with the instance.

Returns `this` object so method calls could be chained.

Throws
* `TypeError` when password of unsupported type is supplied.

##### pbkdf2.generate( salt, count, length )

Performs key derivation along with the `salt`.

If `count` is supplied overrides previous setting.

If `length` is supplied overrides previous setting.

Returns `this` object so method calls could be chained.

Throws
* `TypeError` when salt of unsupported type is supplied.

##### pbkdf2.asHex(), pbkdf2.asBase64(), pbkdf2.asArrayBuffer(), pbkdf2.asBinaryString()

Same as for [SHA256](#sha256).

### AES

Advanced Encryption Standard

TODO progressive ciphering docs

#### Static methods and constants

##### AES.BLOCK_SIZE = 16

##### AES.encrypt( data, key, options )

Shorthand for `staticAesCbcInstance.reset(key, options).encrypt(input).result`.

Encrypts supplied `data` with `key` in CBC mode. Both can be either binary strings or `Uint8Array` objects or `ArrayBuffer` objects.

Additional `options` object can be passed to override default settings ([see below](#aesencrypt-data-options-)).

Returns encrypted data as `Uint8Array`.

##### AES.decrypt( data, key, options )

Shorthand for `staticAesCbcInstance.reset(key, options).dencrypt(input).result`.

Decrypts supplied `data` with `key` in CBC mode. Both can be either binary strings or `Uint8Array` objects or `ArrayBuffer` objects.

Additional `options` object can be passed to override default settings ([see below](#aesdecrypt-data-options-)).

Returns decrypted data as `Uint8Array` object.

#### Constructors

##### CBC_AES( key, options )

Constructs an instance of AES cipher in CBC mode.

If `key` is supplied creates new key schedule, `key` can be either a binary string or `Uint8Array` object or `ArrayBuffer` object.

Additional `options` object can be passed:
* `iv` — initialization vector to be used, binary string/`Uint8Array`/`ArrayBuffer`, when ommited default all-zeros-value is used;
* `padding` — boolean value to turn on/off PKCS#7 padding, default is `true`.

Advanced options:
* `heapSize` — asm.js heap size to allocate for cipher, must be a multiple of 4096, default is 4096.

##### CCM_AES( key, options )

Constructs an instance of AES cipher in CCM mode.

Due to JS limitations (counter is 32-bit unsigned) maximum encrypted message length is limited to near 64 GiB ( 2^36 - 16 )
per `nonce`-`key` pair. That also limits `lengthSize` parameter maximum value to 5 (not 8 as described in RFC3610).

Additional authenticated data `adata` maximum length is limited to 65279 bytes ( 2^16 - 2^8 ),
wich is considered enough for the most of use-cases.

If `key` is supplied creates new key schedule, `key` can be either a binary string or `Uint8Array` object or `ArrayBuffer` object.

Additional `options` object can be passed:
* `tagSize` — size of the authentication tag, allowed valued are 4, 6, 8, 12, 16 (default);
* `lengthSize` — message length field size, allowed values are 2…5, default is 4;
* `nonce` — nonce of length `(15-lengthSize)` to be used, **same nonce must not be used more than once with the same key**, can be a binary string or `Uint8Array`/`ArrayBuffer` object;
* `adata` — additional authenticated data of length no more than 65279 bytes, can be a binary string or `Uint8Array`/`ArrayBuffer` object.

Advanced options:
* `heapSize` — asm.js heap size to allocate for cipher, must be a multiple of 4096, default is 4096.

Progressive ciphering options:
* `iv` — initialization vector to be used, a binary string or `Uint8Array`/`ArrayBuffer` object, when ommited default all-zeros-value is used;
* `counter` — initial internal counter value, default is 1,
* `dataLength` — length of the ciphered data, maximum value is 68719476720 bytes.

#### Methods and properties

##### aes.BLOCK_SIZE = 16

##### aes.KEY_SIZE = 16

##### aes.result

Cipher operation result as `Uint8Array` object.

##### aes.reset( key, options )

Reset internal state. Both arguments are optional.

If `key` is supplied, creates new key schedule.

If either `options.iv` or `options.padding` is supplied, replaces defaults.

Returns `this` object so method calls could be chained.

Throws
* `TypeError` when something ridiculous is supplied instead of the key/iv,
* `IllegalArgumentError` when the key/iv of illegal or unsupported size is supplied.

##### aes.encrypt( data, options )

Encrypts the supplied `data`, it can be either binary string or `Uint8Array` object or `ArrayBuffer` object.

Additional `options` object can be passed to override corresponding settings.

Returns `this` object so method calls could be chained.

Throws
* `TypeError` in case of bizzarie stuff supplied instead of the data,
* `IllegalArgumentError` when padding is turned off and data length isn't multiple of block size,
* `IllegalStateError` when trying to encrypt data without the key being initialized prior.

##### aes.decrypt( data, options )

Decrypts the supplied `data`, it can be either binary string or `Uint8Array` object or `ArrayBuffer` object.

Additional `options` object can be passed to override corresponding settings.

Returns `this` object so method calls could be chained.

Throws
* `TypeError` in case of bizzarie stuff supplied instead of data,
* `IllegalArgumentError` when data length isn't multiple of block size,
* `IllegalStateError` when trying to decrypt data without the key being initialized prior.

Bugs & TODO
-----------

* PBKDF2-HMAC-SHA256: probable OOB write during first iteration of a block;
* AES: testing of progressive ciphering needed
* Moar docs needed ☺

Not yet implemented:
* aes-gcm,
* scrypt,
* rsa, dsa, ecdsa.

Donate
------

If you like this stuff feel free to donate some funds to:
* My Bitcoin address `1CiGzP1EFLTftqkfvVtbwvZ9Koiuoc4FSC`
* [My Flattr account](https://flattr.com/submit/auto?user_id=vibornoff&url=https%3A%2F%2Fgithub.com%2Fvibornoff%2Fasmcrypto.js&title=asmCrypto.js&language=en_US&&category=software)
