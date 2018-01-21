module("RSA");

///////////////////////////////////////////////////////////////////////////////

if ( typeof asmCrypto.RSA !== 'undefined' )
{
    var pubkey = [
        asmCrypto.hex_to_bytes('c13f894819c136381a94c193e619851ddfcde5eca770003ec354f3142e0f61f0676d7d4215cc7a13b06e0744aa8316c9c3766cbefa30b2346fba8f1236d7e6548cf87d9578e6904fc4291e096a2737fcd96624f72e762793505f9dfc5fa17b44611add54f5c00bf54373d720cb6f4e5cabae36c4442b39dbf49158414547f453'),
        asmCrypto.hex_to_bytes('10001')
    ];

    var privkey = [
        asmCrypto.hex_to_bytes('c13f894819c136381a94c193e619851ddfcde5eca770003ec354f3142e0f61f0676d7d4215cc7a13b06e0744aa8316c9c3766cbefa30b2346fba8f1236d7e6548cf87d9578e6904fc4291e096a2737fcd96624f72e762793505f9dfc5fa17b44611add54f5c00bf54373d720cb6f4e5cabae36c4442b39dbf49158414547f453'),
        asmCrypto.hex_to_bytes('10001'),
        asmCrypto.hex_to_bytes('75497aa8a7f8fc4f50d2b82a6b9d518db027e7449adaff4b18829685c8eecd227ba3984263b896df1c55ab53a1a9ae4b06b6f9896f8fde98b4b725de882ac13fc11b614cb2cc81bcc69b9ad167dda093c5c6637754acd0ec9e9845b1b2244d597c9f63d7ea076bda19feadcdb3bd1ba9018915fec981657fb7a4301cb87a3e1'),
        asmCrypto.hex_to_bytes('ef2f8d91d7cd96710d6b3b5ea1b6762b4214efe329e7d0609ab8419744ef8620391e423d5890c864aebb36c0daf5035d27f3427e6a84fde36466a14b56ad1cfb'),
        asmCrypto.hex_to_bytes('ced5477e0acb9c836c3c54e33268e064ce8cdfd40452c8b87ab838b36b498ae22fdbdb331f59f61dd3ca1512143e77a68f8f2400dbe9e576a000084e6fcbb689'),
        asmCrypto.hex_to_bytes('227882f9a2d5513a27c9ed7b7ce8d3ecf61018666fb2a5f85633f9d7f82a60f521e6377ba9d8ebd87eca2260f6ed5ab7c13b30b91156eb542b331349cd4b13a3'),
        asmCrypto.hex_to_bytes('4dea2a3460fcb2c90f4ceaed6b5ff6a802e72eaa3fb6afc64ef476e79fd2e46eb078b1ea60351371c906a7495836effbdeb89d67757076f068f59a2b7211db81'),
        asmCrypto.hex_to_bytes('261a93613a93e438fa62858758d1db3b3db8366319517c039acfcc0ce04cd0d7349d7e8d8cb0e8a05ac966d04c18c81c49025de2b50bb87f78facccd19cd8602')
    ];

    test( "asmCrypto.RSA", function () {
        equal( typeof asmCrypto.RSA, 'object', "RSA exported" );
    });

    test( "asmCrypto.RSA.generateKey", function () {
        var key = asmCrypto.RSA.generateKey( 1024, 3 );
        ok( key, "generateKey" );

        var m = new asmCrypto.Modulus( new asmCrypto.BigNumber(key[0]) ),
            e = new asmCrypto.BigNumber( key[1] ),
            d = new asmCrypto.BigNumber( key[2] ),
            p = new asmCrypto.BigNumber( key[3] ),
            q = new asmCrypto.BigNumber( key[4] ),
            dp = new asmCrypto.BigNumber( key[5] ),
            dq = new asmCrypto.BigNumber( key[6] ),
            qi = new asmCrypto.BigNumber( key[7] );

        equal( p.multiply(q).toString(16), m.toString(16), "m == p*q" );
        equal( e.multiply(d).divide(p.subtract(asmCrypto.BigNumber.fromNumber(1)).multiply(q.subtract(asmCrypto.BigNumber.fromNumber(1)))).remainder.toString(16), '1', "e*d == 1 mod (p-1)(q-1)" );
        equal( d.divide(p.subtract(asmCrypto.BigNumber.fromNumber(1))).remainder.toString(16), dp.toString(16), "dp == d mod (p-1)" );
        equal( d.divide(q.subtract(asmCrypto.BigNumber.fromNumber(1))).remainder.toString(16), dq.toString(16), "dq == d mod (q-1)" );
        equal( qi.multiply(q).divide(p).remainder.toString(16), '1', "qi*q == 1 mod p" );
        equal( m.slice(m.bitLength-1).valueOf(), 1, "m highest bit is 1" );
    });
}
else
{
    skip( "asmCrypto.RSA" );
}

///////////////////////////////////////////////////////////////////////////////

if ( typeof asmCrypto.RSA_RAW !== 'undefined' )
{
    test( "asmCrypto.RSA_RAW.encrypt", function () {
        var text = String.fromCharCode(1);

        var ciphertext = asmCrypto.RSA_RAW.encrypt( text, pubkey );
        equal( asmCrypto.bytes_to_hex(ciphertext).replace(/^0+/,''), '1', "ident encrypt" );

        var result = asmCrypto.RSA_RAW.decrypt( ciphertext, privkey );
        equal( asmCrypto.bytes_to_hex(result).replace(/^0+/,''), '1', "ident decrypt" );
    });
}
else
{
    skip( "asmCrypto.RSA_RAW" );
}

///////////////////////////////////////////////////////////////////////////////

if ( typeof asmCrypto.RSA_OAEP_SHA256 !== 'undefined' )
{
    test( "asmCrypto.RSA_OAEP_SHA256 encrypt/decrypt", function () {
        var cleartext = asmCrypto.string_to_bytes('HelloWorld!');

        var ciphertext = asmCrypto.RSA_OAEP_SHA256.encrypt( cleartext, pubkey, 'test' );
        ok( ciphertext, "encrypt" );

        var result = asmCrypto.RSA_OAEP_SHA256.decrypt( ciphertext, privkey, 'test' );
        equal( asmCrypto.bytes_to_string(result), 'HelloWorld!', "decrypt" );
    });
}
else
{
    skip( "asmCrypto.RSA_OAEP_SHA256" );
}

///////////////////////////////////////////////////////////////////////////////

if ( typeof asmCrypto.RSA_PSS_SHA256 !== 'undefined' )
{
    test( "asmCrypto.RSA_PSS_SHA256 sign/verify", function () {
        var text = 'HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!';

        var signature = asmCrypto.RSA_PSS_SHA256.sign( text, privkey );
        ok( signature, "sign" );

        var result = asmCrypto.RSA_PSS_SHA256.verify( signature, text, pubkey );
        ok( result, "verify" );
    });

    test( "asmCrypto.RSA_PSS_SHA256 verify OpenSSL-signed-data", function () {
        var key = [
            asmCrypto.hex_to_bytes('f30be5ce8941c8e6e764c78d12f3ce6e02a0dea03577bc0c16029de258321b74ceb43ea94f768aec900011c78eb247ab0e94b4477ea8f086ba7b5ce4b03c0ad7e0bf2f54ed509a536a0f179e27db539f729b38a279873f7b3a360690c8390e289dedca6da1ba232d8edc3c1eb229e1072716ddf3ef88caf4a824c152d6ad38f1'),
            asmCrypto.hex_to_bytes('10001'),
/*
            asmCrypto.hex_to_bytes('a2f4032c2ad2b4843bf851e2c0263eed7b4da875f9e3416d4904901ec5cb32a56a416711d5794143c278897326b5595fd2f2d8bc66ab96387ea75f6ce4cc1ce7ba0269a49ce03eb4aea16ca914938e88e5398b10b314276ba9f3f2e448a5f643515ee591cb4c4c5270edccacf7e5b88f86a0c08dc05311513a4ed01802de2511'),
            asmCrypto.hex_to_bytes('fc592285e370d57900bfd2f8c66b15274b3381ca7ec485091d5aa0092ca8f2b97f8796e608a2fc6aa1df3647b10198c49801e3201fefa72ef9d7ccafcdae5d37'),
            asmCrypto.hex_to_bytes('f6904d99d7cf9f1237c6798e5343fe730149be31e0363bf33039af84a09b5e9d0dd71239384b6cf6421e4ad41097b2cd09fd0114eb29a4339c433f37d7286f17'),
            asmCrypto.hex_to_bytes('252e1ce00d3abab9315b12028579918c50902e375fa624d3caf7674cf2bf91c3b2fe8f4525509e5037b9638dfc8e77abbf99c7951c1f7b4a78954b1b3bfaccd1'),
            asmCrypto.hex_to_bytes('9f036da89c10208cc53fd14142de0509f278b69abff8fa2cda9b3961159b5e2777b78edf2c3928aaa0f59c58abe2c9c3867f8ee508ccb04340b1f5e17377763d'),
            asmCrypto.hex_to_bytes('c07e9ca15c2cc38cc4faab0729403e02b33982b7d1219e15cd74614f3485437d2c800d66a0c368b3cf36513e4b1e05d31d7e0186f00cf036433e35f13b5cfda8')
*/
        ];

        var text = 'Hello There!';

        var signature = asmCrypto.hex_to_bytes('A68BE713861409B4E536C12066B3D30650C7578F9B7AB61C1A302B42ECA14D58AE11899BC55FCB838F0AE06B99381DE26CE8D6318BD59BBFC4FFF56A995E9EFB0306FF105766F508297D1E74F22648B6BD66C18E06F4748BD258358ECB5BB722AC4AFFA146C04EE7BE84AD77ED2A84B5458D6CA4A7DA4D86DAB3F2B39FD647F4');

        var saltlen = 32;

        var result = asmCrypto.RSA_PSS_SHA256.verify( signature, text, key, saltlen );
        ok( result, "verify" );
    });
}
else
{
    skip( "asmCrypto.RSA_PSS_SHA256" );
}
