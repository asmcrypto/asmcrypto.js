module("SHA512 stuff");

///////////////////////////////////////////////////////////////////////////////

var sha512_vectors = [
    [ 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e', '' ],
    [ 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f', 'abc' ],
    [ '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909', 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu' ],
    [ '07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6', 'The quick brown fox jumps over the lazy dog' ],
    [ '91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed', 'The quick brown fox jumps over the lazy dog.' ],
];

test( "asmCrypto.SHA512.hex", function () {
    for ( var i = 0; i < sha512_vectors.length; ++i ) {
        equal(
            asmCrypto.SHA512.hex( sha512_vectors[i][1] ),
            sha512_vectors[i][0],
            "vector " + i
        );
    }
});

///////////////////////////////////////////////////////////////////////////////

var hmac_sha512_vectors = [
    [ '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854', asmCrypto.hex_to_bytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'), 'Hi There'],
    [ '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737', 'Jefe', 'what do ya want for nothing?' ],
    [ '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598', asmCrypto.hex_to_bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), 'Test Using Larger Than Block-Size Key - Hash Key First'],
];

test( "asmCrypto.HMAC_SHA512.hex", function () {
    for ( var i = 0; i < hmac_sha512_vectors.length; ++i ) {
        equal(
            asmCrypto.HMAC_SHA512.hex( hmac_sha512_vectors[i][2], hmac_sha512_vectors[i][1] ),
            hmac_sha512_vectors[i][0],
                "vector " + i
        );
    }
});

///////////////////////////////////////////////////////////////////////////////

var pbkdf2_hmac_sha512_vectors = [
    [ '867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce', 'password', 'salt', 1, 64 ],
    [ '867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce', asmCrypto.string_to_bytes('password'), asmCrypto.string_to_bytes('salt'), 1, 64 ],
    [ 'e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e', 'password', 'salt', 2, 64 ],
    [ 'd197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5', 'password', 'salt', 4096, 64 ],
    [ '8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 64 ],
];

test( "asmCrypto.PBKDF2_HMAC_SHA512.hex", function () {
    for ( var i = 0; i < pbkdf2_hmac_sha512_vectors.length; ++i ) {
        equal(
            // got
            asmCrypto.PBKDF2_HMAC_SHA512.hex(
                pbkdf2_hmac_sha512_vectors[i][1],   // password
                pbkdf2_hmac_sha512_vectors[i][2],   // salt
                pbkdf2_hmac_sha512_vectors[i][3],   // count
                pbkdf2_hmac_sha512_vectors[i][4]    // dklen
            ),

            // expect
            pbkdf2_hmac_sha512_vectors[i][0],

            // comment
                "asmCrypto.PBKDF2_HMAC_SHA512.hex('"
                +pbkdf2_hmac_sha512_vectors[i][1]+"', '"
                +pbkdf2_hmac_sha512_vectors[i][2]+"', '"
                +pbkdf2_hmac_sha512_vectors[i][3]+"', '"
                +pbkdf2_hmac_sha512_vectors[i][4]
                +"') is equal to '"+pbkdf2_hmac_sha512_vectors[i][0]+"'"
        );
    }
});
