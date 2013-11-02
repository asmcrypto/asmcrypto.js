asmcrypto.js
============

Asm.js implementation of popular cryptographic utilities.

[UglifyJS2](https://github.com/mishoo/UglifyJS2) is required to build this.

Synopsis
--------

Add `<script src="path/to/asmcrypto.js"></script>` to your page.

    // Hash whole string at once
    digest = asmCrypto.SHA256.hex("The quick brown fox jumps over the lazy dog");

    // Or hash it chunk-by-chunk
    hash = new asmCrypto.SHA256;
    hash.process("The quick brown");
    hash.process(" fox jumps over the ");
    hash.process("lazy dog");
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

### SHA256

Implementation of Secure Hash 2 algorithm with 256-bit output length.

#### Static methods and constants

##### SHA256.BLOCK_SIZE = 64

##### SHA256.HASH_SIZE = 32

##### SHA256.hex(input)

Same as `staticInstance.reset().process(input).finish().asHex()` (see below).

##### SHA256.base64(input)

Same as `staticInstance.reset().process(input).finish().asBase64()` (see below).

#### Constructor

##### SHA256(options)

Constructs new instance of `SHA256` object.

Optional `options` object can be passed. When ommited, next defaults are used:

    {
        heapSize: 4096  // must be a multiple of 4096 as asm.js requires
    }

#### Methods and properties

##### sha256.BLOCK_SIZE = 64

##### sha256.HASH_SIZE = 32

##### sha256.reset()

Resets internal state into initial.

##### sha256.process(input)

Updates internal state with the supplied `input` data.

Input data can be a string or instance of `ArrayBuffer` or `ArrayBufferView`.

Throws
* `new Error("Illegal state")` when trying to update `finish`'ed state,
* `new ReferenceError("Illegal argument")` when something ridiculous is supplied as input data.

##### sha256.finish()

Finishes hash calculation.

Throws
* `new Error("Illegal state")` when trying to finish already `finish`'ed state,

##### sha256.asHex()

Returns string representing hex-encoded message digest.

Throws
* `new Error("Illegal state")` when trying to get non-`finish`'ed state.

##### sha256.asBase64()

Returns string representing base64-encoded message digest.

Throws
* `new Error("Illegal state")` when trying to get non-`finish`'ed state.

##### sha256.asArrayBuffer()

Returns raw message digest as an `ArrayBuffer` object.

Throws
* `new Error("Illegal state")` when trying to get non-`finish`'ed state.

##### sha256.asBinaryString()

Returns raw message digest as a binary string.

Throws
* `new Error("Illegal state")` when trying to get non-`finish`'ed state.

### HMAC

TODO

### HMAC_SHA256

TODO

Performance
-----------

This stuff is pretty fast under Firefox and Chrome.

See benchmarks:
* [SHA256](http://jsperf.com/sha256/30),
* [HMAC-SHA256](http://jsperf.com/hmac-sha256/1).

TODO
----

* aes, cbc, ctr, gcm
* pbkdf2, scrypt
* rsa, dsa, ecdsa
