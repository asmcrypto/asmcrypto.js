asmCrypto 
=========

Not maintained anymore, use a native or WASM implementation instead.

JavaScript implementation of popular cryptographic utilities with performance in mind.

Build & Test
------------

Then download and build the stuff:

    git clone https://github.com/asmcrypto/asmcrypto.js.git
    cd asmcrypto.js/
    npm install

Running tests is always a good idea:

    npm test

Congratulations! Now you have your `asmcrypto.js` ready to use ☺

Support
-----------

* NodeJS 10
* IE11
* last two Chrome versions
* last two Firefox versions and the latest Firefox ESR
* last two Edge versions
* last two Safari versions

AsmCrypto 2.0
-----------

* Moved to TypeScript
* I have no confident knowledge on random generation, so I don't feel right maintaining it. As of 2.0 all custom random generation and seeding code is removed, the underlying browsers and environments have to provide secure random.  
