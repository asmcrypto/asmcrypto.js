module("SHA1");

///////////////////////////////////////////////////////////////////////////////

if ( typeof asmCrypto.SHA1 !== 'undefined' )
{
    var sha1_vectors = [
        [ 'a9993e364706816aba3e25717850c26c9cd0d89d', 'abc'],
        [ '84983e441c3bd26ebaae4aa1f95129e5e54670f1', 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'],
        [ 'a49b2446a02c645bf419f995b67091253a04a259', 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu'],
        [ '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12', 'The quick brown fox jumps over the lazy dog' ],
        [ 'de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3', 'The quick brown fox jumps over the lazy cog' ],
        [ '9ace614c96c229d38b2143f6b165f775cc552740', 'This string contains UTF8 characters - Ͼ' ],
    ];

    test( "asmCrypto.SHA1.hex", function () {
        for ( var i = 0; i < sha1_vectors.length; ++i ) {
            equal(
                asmCrypto.SHA1.hex( sha1_vectors[i][1] ),
                sha1_vectors[i][0],
                "vector " + i
            );
        }
    });
}
else
{
    skip( "asmCrypto.SHA1" );
}

///////////////////////////////////////////////////////////////////////////////

if ( typeof asmCrypto.HMAC_SHA1 !== 'undefined' )
{
    var hmac_sha1_vectors = [
        [ '5fd596ee78d5553c8ff4e72d266dfd192366da29', asmCrypto.hex_to_bytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'), asmCrypto.hex_to_bytes('53616d706c65206d65737361676520666f72206b65796c656e3d626c6f636b6c656e') ],
        [ 'fbdb1d1b18aa6c08324b7d64b71fb76370690e1d', '', '' ],
        [ 'de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9', 'key', 'The quick brown fox jumps over the lazy dog' ],
        [ 'b617318655057264e28bc0b6fb378c8ef146be00', asmCrypto.hex_to_bytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'), 'Hi There' ],
        [ 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79', 'Jefe', 'what do ya want for nothing?'],
        [ '8b212826d2bf54e4ec797323ca7092edcf823765', 'This data contains UTF8 characters - Ͼ', 'This password contains UTF8 characters - Ͼ' ],
    ];

    test( "asmCrypto.HMAC_SHA1.hex", function () {
        for ( var i = 0; i < hmac_sha1_vectors.length; ++i ) {
            equal(
                asmCrypto.HMAC_SHA1.hex( hmac_sha1_vectors[i][2], hmac_sha1_vectors[i][1] ),
                hmac_sha1_vectors[i][0],
                "vector " + i
            );
        }
    });
}
else
{
    skip( "asmCrypto.HMAC_SHA1" );
}

///////////////////////////////////////////////////////////////////////////////

if ( typeof asmCrypto.PBKDF2_HMAC_SHA1 !== 'undefined' )
{
    var pbkdf2_hmac_sha1_vectors = [
        [ '0c60c80f961f0e71f3a9b524af6012062fe037a6', 'password', 'salt', 1, 20 ],
        [ 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957', 'password', 'salt', 2, 20 ],
        [ '4b007901b765489abead49d926f721d065a429c1', 'password', 'salt', 4096, 20 ],
        //[ 'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984', 'password', 'salt', 16777216, 20 ],
        [ '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25 ],
        [ '56fa6aa75548099dcc37d7f03425e0c3', "pass\0word", "sa\0lt", 4096, 16 ],
        [ 'cce786b3b45e56a778e70a28eaed5a4b8332bacf', 'This data contains UTF8 characters - Ͼ', 'This password contains UTF8 characters - Ͼ', 1, 20 ],
    ];

    test( "asmCrypto.PBKDF2_HMAC_SHA1.hex", function () {
        for ( var i = 0; i < pbkdf2_hmac_sha1_vectors.length; ++i ) {
            equal(
                // got
                asmCrypto.PBKDF2_HMAC_SHA1.hex(
                    pbkdf2_hmac_sha1_vectors[i][1],   // password
                    pbkdf2_hmac_sha1_vectors[i][2],   // salt
                    pbkdf2_hmac_sha1_vectors[i][3],   // count
                    pbkdf2_hmac_sha1_vectors[i][4]    // dklen
                ),

                // expect
                pbkdf2_hmac_sha1_vectors[i][0],

                // comment
                "asmCrypto.PBKDF2_HMAC_SHA1.hex('"
                    +pbkdf2_hmac_sha1_vectors[i][1]+"', '"
                    +pbkdf2_hmac_sha1_vectors[i][2]+"', '"
                    +pbkdf2_hmac_sha1_vectors[i][3]+"', '"
                    +pbkdf2_hmac_sha1_vectors[i][4]
                    +"') is equal to '"+pbkdf2_hmac_sha1_vectors[i][0]+"'"
            );
        }
    });
}
else
{
    skip( "asmCrypto.PBKDF2_HMAC_SHA1" );
}
