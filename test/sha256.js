module("SHA256");

///////////////////////////////////////////////////////////////////////////////

if ( typeof asmCrypto.SHA256 !== 'undefined' )
{
    var sha256_vectors = [
        [ 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '' ],
        [ 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'abc' ],
        [ 'f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650', 'message digest' ],
        [ 'f30ceb2bb2829e79e4ca9753d35a8ecc00262d164cc077080295381cbd643f0d', 'secure hash algorithm' ],
        [ '6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630', 'SHA256 is considered to be safe' ],
        [ '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1', 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' ],
        [ 'f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342', 'For this sample, this 63-byte string will be used as input data' ],
        [ 'ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8', 'This is exactly 64 bytes long, not counting the terminating byte' ],
        [ '11b4099132815e057ef4db0350ad5eaf0e0e179009b52421c2fd761928edd587', 'This string contains UTF8 characters - Ͼ' ],
    ];

    test( "asmCrypto.SHA256.hex", function () {
        for ( var i = 0; i < sha256_vectors.length; ++i ) {
            equal(
                asmCrypto.SHA256.hex( sha256_vectors[i][1] ),
                sha256_vectors[i][0],
                "vector " + i
            );
        }
    });
}
else
{
    skip( "asmCrypto.SHA256" );
}

///////////////////////////////////////////////////////////////////////////////

if ( typeof asmCrypto.HMAC_SHA256 !== 'undefined' )
{
    var hmac_sha256_vectors = [
        [ 'b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad', '', '' ],
        [ 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8', 'key', 'The quick brown fox jumps over the lazy dog' ],
        [ 'b54d57e9b21940b6496b58d5ac120eda9f1637788b5df058928637f2eca40cd9', 'MyVeeeeeeeeeeeeeryVeeeeeeeeeeeeeryVeeeeeeeeeeeeeryLoooooooooongPassword', 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.' ],
        [ '8608ee9fb1c93ce173d1d188bcb669a5c3e5154f352f106c4cee31fe61622f22', 'This data contains UTF8 characters - Ͼ', 'This password contains UTF8 characters - Ͼ' ],
    ];

    test( "asmCrypto.HMAC_SHA256.hex", function () {
        for ( var i = 0; i < hmac_sha256_vectors.length; ++i ) {
            equal(
                asmCrypto.HMAC_SHA256.hex( hmac_sha256_vectors[i][2], hmac_sha256_vectors[i][1] ),
                hmac_sha256_vectors[i][0],
                "vector " + i
            );
        }
    });
}
else
{
    skip( "asmCrypto.HMAC_SHA256" );
}

///////////////////////////////////////////////////////////////////////////////

if ( typeof asmCrypto.PBKDF2_HMAC_SHA256 !== 'undefined' )
{
    var pbkdf2_hmac_sha256_vectors = [
        [ '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b', 'password', 'salt', 1, 32 ],
        [ 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43', 'password', 'salt', 2, 32 ],
        [ 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a', 'password', 'salt', 4096, 32 ],
        [ '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 40 ],
        [ '89b69d0516f829893c696226650a8687', "pass\0word", "sa\0lt", 4096, 16 ],
        [ 'cdc8b1780ca68aba97f1f729c9d281719702eb4b308d7d87409817e60188be0d', 'MyVeeeeeeeeeeeeeryVeeeeeeeeeeeeeryVeeeeeeeeeeeeeryLoooooooooongPassword', 'MyVeeeeeeeeeeeeeryVeeeeeeeeeeeeeryVeeeeeeeeeeeeeryLoooooooooongPassword', 4096, 32 ],
        [ 'cfa8aa80136fbac4bf51ceca36745268d20953d189bf5a74852e459716737a8b', 'This data contains UTF8 characters - Ͼ', 'This password contains UTF8 characters - Ͼ', 1, 32 ],
    ];

    test( "asmCrypto.PBKDF2_HMAC_SHA256.hex", function () {
        for ( var i = 0; i < pbkdf2_hmac_sha256_vectors.length; ++i ) {
            equal(
                // got
                asmCrypto.PBKDF2_HMAC_SHA256.hex(
                    pbkdf2_hmac_sha256_vectors[i][1],   // password
                    pbkdf2_hmac_sha256_vectors[i][2],   // salt
                    pbkdf2_hmac_sha256_vectors[i][3],   // count
                    pbkdf2_hmac_sha256_vectors[i][4]    // dklen
                ),

                // expect
                pbkdf2_hmac_sha256_vectors[i][0],

                // comment
                "asmCrypto.PBKDF2_HMAC_SHA256.hex('"
                    +pbkdf2_hmac_sha256_vectors[i][1]+"', '"
                    +pbkdf2_hmac_sha256_vectors[i][2]+"', '"
                    +pbkdf2_hmac_sha256_vectors[i][3]+"', '"
                    +pbkdf2_hmac_sha256_vectors[i][4]
                    +"') is equal to '"+pbkdf2_hmac_sha256_vectors[i][0]+"'"
            );
        }
    });
}
else
{
    skip( "asmCrypto.PBKDF2_HMAC_SHA256" );
}
