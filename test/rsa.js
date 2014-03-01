module("RSA");

var pubkey  = "-----BEGIN PUBLIC KEY-----\n"
            + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBP4lIGcE2OBqUwZPmGYUd383l\n"
            + "7KdwAD7DVPMULg9h8GdtfUIVzHoTsG4HRKqDFsnDdmy++jCyNG+6jxI21+ZUjPh9\n"
            + "lXjmkE/EKR4Jaic3/NlmJPcudieTUF+d/F+he0RhGt1U9cAL9UNz1yDLb05cq642\n"
            + "xEQrOdv0kVhBRUf0UwIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";

var privkey = "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIICWwIBAAKBgQDBP4lIGcE2OBqUwZPmGYUd383l7KdwAD7DVPMULg9h8GdtfUIV\n"
            + "zHoTsG4HRKqDFsnDdmy++jCyNG+6jxI21+ZUjPh9lXjmkE/EKR4Jaic3/NlmJPcu\n"
            + "dieTUF+d/F+he0RhGt1U9cAL9UNz1yDLb05cq642xEQrOdv0kVhBRUf0UwIDAQAB\n"
            + "AoGAB1SXqop/j8T1DSuCprnVGNsCfnRJra/0sYgpaFyO7NInujmEJjuJbfHFWrU6\n"
            + "GprksGtvmJb4/emLS3Jd6IKsE/wRthTLLMgbzGm5rRZ92gk8XGY3dUrNDsnphFsb\n"
            + "IkTVl8n2PX6gdr2hn+rc2zvRupAYkV/smBZX+3pDAcuHo+ECQQDvL42R182WcQ1r\n"
            + "O16htnYrQhTv4ynn0GCauEGXRO+GIDkeQj1YkMhkrrs2wNr1A10n80J+aoT942Rm\n"
            + "oUtWrRz7AkEAztVHfgrLnINsPFTjMmjgZM6M39QEUsi4erg4s2tJiuIv29szH1n2\n"
            + "HdPKFRIUPnemj48kANvp5XagAAhOb8u2iQJAIniC+aLVUTonye17fOjT7PYQGGZv\n"
            + "sqX4VjP51/gqYPUh5jd7qdjr2H7KImD27Vq3wTswuRFW61QrMxNJzUsTowJATeoq\n"
            + "NGD8sskPTOrta1/2qALnLqo/tq/GTvR255/S5G6weLHqYDUTcckGp0lYNu/73rid\n"
            + "Z3VwdvBo9ZorchHbgQJAJhqTYTqT5Dj6YoWHWNHbOz24NmMZUXwDms/MDOBM0Nc0\n"
            + "nX6NjLDooFrJZtBMGMgcSQJd4rULuH94+szNGc2GAg==\n"
            + "-----END RSA PRIVATE KEY-----\n";

test( "asmCrypto.RSA", function () {
    equal( typeof asmCrypto.RSA, 'function', "RSA API exported" );
//    equal( typeof asmCrypto.RSA, 'object', "RSA API exported" );
    equal( typeof asmCrypto.RSA.encrypt, 'function', "RSA.encrypt is exported" );
    equal( typeof asmCrypto.RSA.decrypt, 'function', "RSA.decrypt is exported" );
});

test( "asmCrypto.RSA constructor", function () {
    var pubrsa = new asmCrypto.RSA( { key: pubkey } );
    ok( pubrsa, "construct RSA pubkey" );
    equal( pubrsa.key[0].toString(16), 'c13f894819c136381a94c193e619851ddfcde5eca770003ec354f3142e0f61f0676d7d4215cc7a13b06e0744aa8316c9c3766cbefa30b2346fba8f1236d7e6548cf87d9578e6904fc4291e096a2737fcd96624f72e762793505f9dfc5fa17b44611add54f5c00bf54373d720cb6f4e5cabae36c4442b39dbf49158414547f453', "pubkey modulus ok" );
    equal( pubrsa.key[1].toString(16), '10001', "pubkey encrypting exponent ok" );

    var privrsa = new asmCrypto.RSA( { key: privkey } );
    ok( privrsa, "construct RSA privkey" );
    equal( privrsa.key[0].toString(16), 'c13f894819c136381a94c193e619851ddfcde5eca770003ec354f3142e0f61f0676d7d4215cc7a13b06e0744aa8316c9c3766cbefa30b2346fba8f1236d7e6548cf87d9578e6904fc4291e096a2737fcd96624f72e762793505f9dfc5fa17b44611add54f5c00bf54373d720cb6f4e5cabae36c4442b39dbf49158414547f453', "privkey modulus ok" );
    equal( privrsa.key[1].toString(16), '10001', "privkey public exponent ok" );
    equal( privrsa.key[2].toString(16), '75497aa8a7f8fc4f50d2b82a6b9d518db027e7449adaff4b18829685c8eecd227ba3984263b896df1c55ab53a1a9ae4b06b6f9896f8fde98b4b725de882ac13fc11b614cb2cc81bcc69b9ad167dda093c5c6637754acd0ec9e9845b1b2244d597c9f63d7ea076bda19feadcdb3bd1ba9018915fec981657fb7a4301cb87a3e1', "privkey decrypting exponent ok" );
    equal( privrsa.key[3].toString(16), 'ef2f8d91d7cd96710d6b3b5ea1b6762b4214efe329e7d0609ab8419744ef8620391e423d5890c864aebb36c0daf5035d27f3427e6a84fde36466a14b56ad1cfb', "privkey prime1 ok" );
    equal( privrsa.key[4].toString(16), 'ced5477e0acb9c836c3c54e33268e064ce8cdfd40452c8b87ab838b36b498ae22fdbdb331f59f61dd3ca1512143e77a68f8f2400dbe9e576a000084e6fcbb689', "privkey prime2 ok" );
    equal( privrsa.key[5].toString(16), '227882f9a2d5513a27c9ed7b7ce8d3ecf61018666fb2a5f85633f9d7f82a60f521e6377ba9d8ebd87eca2260f6ed5ab7c13b30b91156eb542b331349cd4b13a3', "privkey exponent1 ok" );
    equal( privrsa.key[6].toString(16), '4dea2a3460fcb2c90f4ceaed6b5ff6a802e72eaa3fb6afc64ef476e79fd2e46eb078b1ea60351371c906a7495836effbdeb89d67757076f068f59a2b7211db81', "privkey exponent2 ok" );
    equal( privrsa.key[7].toString(16), '261a93613a93e438fa62858758d1db3b3db8366319517c039acfcc0ce04cd0d7349d7e8d8cb0e8a05ac966d04c18c81c49025de2b50bb87f78facccd19cd8602', "privkey coefficient ok" );
});

test( "asmCrypto.RSA.encrypt", function () {
    var pubrsa = new asmCrypto.RSA( { key: pubkey } );

    pubrsa.reset().encrypt( new asmCrypto.BigNumber(1) );
    equal( pubrsa.result.valueOf(), 1, "ident encrypt ok" );

    pubrsa.reset().encrypt( new asmCrypto.BigNumber('322e393f76a1c22b147e7d193c00c023afb7c1500b006ff1bc1cc8d391fc38bd') );
    equal( pubrsa.result.toString(16), 'c04f466494abebb4defa00866fc5b22e7aef50a2c46f63333be21100f0fa53c686d9fdd31c1913a5950db574f0ecf216f822a95305e18c86f4de2ddc8f32a61a35957b3084addf4bb148a6222075dbc85bab1142632e0b3868eba07ccbeb1c05717a3df370fb2148d6b99558b42abe73babd742c351724014640461a484c192f', "vector 1 encrypt ok" );
});

test( "asmCrypto.RSA.decrypt", function () {
    var privrsa = new asmCrypto.RSA( { key: privkey } );

    privrsa.reset().decrypt( new asmCrypto.BigNumber(1) );
    equal( privrsa.result.valueOf(), 1, "ident decrypt ok" );

    privrsa.reset().decrypt( new asmCrypto.BigNumber('c04f466494abebb4defa00866fc5b22e7aef50a2c46f63333be21100f0fa53c686d9fdd31c1913a5950db574f0ecf216f822a95305e18c86f4de2ddc8f32a61a35957b3084addf4bb148a6222075dbc85bab1142632e0b3868eba07ccbeb1c05717a3df370fb2148d6b99558b42abe73babd742c351724014640461a484c192f') );
    equal( privrsa.result.toString(16), '322e393f76a1c22b147e7d193c00c023afb7c1500b006ff1bc1cc8d391fc38bd', "vector 1 decrypt ok" );
});
