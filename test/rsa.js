module("RSA");

test( "asmCrypto.RSA", function () {
    equal( typeof asmCrypto.RSA, 'object', "RSA API exported" );
    equal( typeof asmCrypto.RSA.encrypt, 'function', "RSA.encrypt is exported" );
    equal( typeof asmCrypto.RSA.decrypt, 'function', "RSA.decrypt is exported" );
});

test( "asmCrypto.RSA.encrypt", function () {
});

test( "asmCrypto.RSA.decrypt", function () {
});
