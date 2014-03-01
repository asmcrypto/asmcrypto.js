module("RSA");

test( "asmCrypto.RSA", function () {
    equal( typeof asmCrypto.RSA, 'function', "RSA API exported" );
//    equal( typeof asmCrypto.RSA, 'object', "RSA API exported" );
    equal( typeof asmCrypto.RSA.encrypt, 'function', "RSA.encrypt is exported" );
    equal( typeof asmCrypto.RSA.decrypt, 'function', "RSA.decrypt is exported" );
});

test( "asmCrypto.RSA constructor", function () {
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

    var pubrsa = new asmCrypto.RSA( { key: pubkey } );
    ok( pubrsa, "construct RSA pubkey" );

    var privrsa = new asmCrypto.RSA( { key: privkey } );
    ok( privrsa, "construct RSA privkey" );
});

test( "asmCrypto.RSA.encrypt", function () {
});

test( "asmCrypto.RSA.decrypt", function () {
});
