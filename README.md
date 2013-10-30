asmcrypto.js
============

Asm.js implementation of popular cryptographic utilities.

[UglifyJS2](https://github.com/mishoo/UglifyJS2) is required to build this.

Synopsis
--------

Add `<script src="path/to/asmcrypto.js"></script>` to your page.

    // Hash whole string at once
    digest = asmCrypto.sha256_hex("The quick brown fox jumps over the lazy dog");

    // Or hash it chunk-by-chunk
    hash = new asmCrypto.sha256;
    hash.update("The quick brown");
    hash.update(" fox jumps over the ");
    hash.update("lazy dog");
    digest = hash.finish().asHex(); // also you can chain method calls

Build & Test
------------

Before you start check that [UglifyJS2](https://github.com/mishoo/UglifyJS2) is installed:

    uglifyjs -V

Then download and build the stuff:

    git clone https://github.com/vibornoff/asmcrypto.js.git
    cd asmcrypto.js
    make

After build is complete open `test.html` in your browser and check that all tests are passed.

Congratulations! Now you have your `asmcrypto.js` and `asmcrypto.js.map` ready to use ☺

API
---

### SHA-256

Implementation of Secure Hash 2 algorithm.

#### Static methods

##### asmCrypto.sha256_hex(input)

Same as `staticInstance.reset().update(input).finish().asHex()` (see below).

##### asmCrypto.sha256_base64(input)

Same as `staticInstance.reset().update(input).finish().asBase64()` (see below).

#### Constructor

##### asmCrypto.sha256(options)

Constructs new instance of `sha256` object.

Optional `options` object can be passed. When ommited, next defaults are used:

    {
        heapSize: 4096  // must be a multiple of 4096 as asm.js requires
    }

#### Methods

##### reset()

Resets internal state into initial.

##### update(input)

Updates internal state with the supplied `input` data.

Input data can be a string or instance of `ArrayBuffer` or `ArrayBufferView`.

Throws
* `new Error("Illegal state")` when trying to update `finish`'ed state,
* `new ReferenceError("Illegal argument")` when something ridiculous is supplied as input data.

##### finish()

Finishes hash calculation.

Throws
* `new Error("Illegal state")` when trying to finish already `finish`'ed state,

##### asHex()

Returns string representing hex-encoded message digest.

Throws
* `new Error("Illegal state")` when trying to get non-`finish`'ed state.

##### asBase64()

Returns string representing base64-encoded message digest.

Throws
* `new Error("Illegal state")` when trying to get non-`finish`'ed state.

##### asArrayBuffer()

Returns raw message digest as an `ArrayBuffer` object.

Throws
* `new Error("Illegal state")` when trying to get non-`finish`'ed state.

##### asBinaryString()

Returns raw message digest as a binary string.

Throws
* `new Error("Illegal state")` when trying to get non-`finish`'ed state.

Performance
-----------

This stuff is pretty fast under Firefox and Chrome.

See benchmark at [jsperf.com/sha256/30](http://jsperf.com/sha256/30).

TODO
----

* aes, cbc, ctr, gcm
* hmac
* pbkdf2, scrypt
* rsa, dsa, ecdsa
