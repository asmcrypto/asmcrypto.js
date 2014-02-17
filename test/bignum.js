module("BigNumber");

test( "new asmCrypto.BigNumber()", function () {
    var zero = new asmCrypto.BigNumber();
    ok( zero, "zero = new 0" );
    equal( zero.limbs.length, 0, "zero.limbs.length" );
    equal( zero.bitLength, 0, "zero.bitLength" );
    equal( zero.valueOf(), 0, "zero.valueOf()" );
    equal( zero.toString(), "0", "zero.toString()" );

    var one = new asmCrypto.BigNumber(1);
    ok( one, "one = new 1" );
    equal( one.limbs.length, 1, "one.limbs.length" );
    equal( one.limbs[0], 1, "one.limbs[0]" );
    equal( one.bitLength, 32, "one.bitLength" );
    equal( one.valueOf(), 1, "one.valueOf()" );
    equal( one.toString(), "1", "one.toString()" );

    var ten = new asmCrypto.BigNumber(10);
    ok( ten, "ten = new 10" );
    equal( ten.limbs.length, 1, "ten.limbs.length" );
    equal( ten.limbs[0], 10, "ten.limbs[0]" );
    equal( ten.bitLength, 32, "ten.bitLength" );
    equal( ten.valueOf(), 10, "ten.valueOf()" );
    equal( ten.toString(), "a", "ten.toString()" );

    var mten = new asmCrypto.BigNumber(-10);
    ok( mten, "mten = new -10" );
    equal( mten.limbs.length, 1, "mten.limbs.length" );
    equal( mten.limbs[0], 10, "mten.limbs[0]" );
    equal( mten.bitLength, 32, "mten.bitLength" );
    equal( mten.valueOf(), -10, "mten.valueOf()" );
    equal( mten.toString(), "-a", "mten.toString()" );

    var ffffffff = new asmCrypto.BigNumber(0xffffffff);
    ok( ffffffff, "ffffffff = new 0xfffffff" );
    equal( ffffffff.limbs.length, 1, "ffffffff.limbs.length" );
    equal( ffffffff.limbs[0], 0xffffffff, "ffffffff.limbs[0]" );
    equal( ffffffff.bitLength, 32, "ffffffff.bitLength" );
    equal( ffffffff.valueOf(), 0xffffffff, "ffffffff.valueOf()" );
    equal( ffffffff.toString(), "ffffffff", "ffffffff.toString()" );

    var deadbeefcafe = new asmCrypto.BigNumber(0xdeadbeefcafe);
    ok( deadbeefcafe, "deadbeefcafe = new 0xdeadbeefcafe" );
    equal( deadbeefcafe.limbs.length, 2, "deadbeefcafe.limbs.length" );
    equal( deadbeefcafe.limbs[0], 0xbeefcafe, "deadbeefcafe.limbs[0]" );
    equal( deadbeefcafe.limbs[1], 0xdead, "deadbeefcafe.limbs[1]" );
    equal( deadbeefcafe.bitLength, 52, "deadbeefcafe.bitLength" );
    equal( deadbeefcafe.valueOf(), 0xdeadbeefcafe, "deadbeefcafe.valueOf()" );
    equal( deadbeefcafe.toString(), "deadbeefcafe", "deadbeefcafe.toString()" );

    var verylarge = new asmCrypto.BigNumber("3f70f29d3f3ae354a6d2536ceafba83cfc787cd91e7acd2b6bde05e62beb8295ae18e3f786726f8d034bbc15bf8331df959f59d431736d5f306aaba63dacec279484e39d76db9b527738072af15730e8b9956a64e8e4dbe868f77d1414a8a8b8bf65380a1f008d39c5fabe1a9f8343929342ab7b4f635bdc52532d764701ff3d8072c475c012ff0c59373e8bc423928d99f58c3a6d9f6ab21ee20bc8e8818fc147db09f60c81906f2c6f73dc69725f075853a89f0cd02a30a8dd86b660ccdeffc292f398efb54088c822774445a6afde471f7dd327ef9996296898a5747726ccaeeceeb2e459df98b4128cb5ab8c7cd20c563f960a1aa770f3c81f13f967b6cc");
    ok( verylarge, "verylarge = new 3f70f29d…f967b6cc" );
    equal( verylarge.limbs.length, 64, "verylarge.limbs.length" );
    equal( verylarge.limbs[0], 0xf967b6cc, "verylarge.limbs[0]" );
    equal( verylarge.limbs[63], 0x3f70f29d, "verylarge.limbs[63]" );
    equal( verylarge.bitLength, 2048, "verylarge.bitLength" );
    equal( verylarge.valueOf(), Infinity, "verylarge.valueOf()" );
    equal( verylarge.toString(), "3f70f29d3f3ae354a6d2536ceafba83cfc787cd91e7acd2b6bde05e62beb8295ae18e3f786726f8d034bbc15bf8331df959f59d431736d5f306aaba63dacec279484e39d76db9b527738072af15730e8b9956a64e8e4dbe868f77d1414a8a8b8bf65380a1f008d39c5fabe1a9f8343929342ab7b4f635bdc52532d764701ff3d8072c475c012ff0c59373e8bc423928d99f58c3a6d9f6ab21ee20bc8e8818fc147db09f60c81906f2c6f73dc69725f075853a89f0cd02a30a8dd86b660ccdeffc292f398efb54088c822774445a6afde471f7dd327ef9996296898a5747726ccaeeceeb2e459df98b4128cb5ab8c7cd20c563f960a1aa770f3c81f13f967b6cc", "verylarge.toString()" );
});

test( "asmCrypto.BigNumber.compare", function () {
    var deadbeefcafe = new asmCrypto.BigNumber(0xdeadbeefcafe),
        ffffffff = new asmCrypto.BigNumber(0xffffffff),
        result = null;

    result = ffffffff.compare(0xffffffff);
    equal( result, 0, "ffffffff == 0xffffffff" );

    result = deadbeefcafe.compare(ffffffff);
    equal( result, 1, "deadbeefcafe > ffffffff" );

    result = ffffffff.compare(deadbeefcafe);
    equal( result, -1, "ffffffff > deadbeefcafe" );

    result = ffffffff.compare(-10);
    equal( result, 1, "ffffffff > -10" );
});

test( "asmCrypto.BigNumber.add", function () {
    var deadbeefcafe = new asmCrypto.BigNumber(0xdeadbeefcafe),
        ffffffff = new asmCrypto.BigNumber(0xffffffff),
        result = null;

    result = deadbeefcafe.add(ffffffff);
    equal( result.toString(16), "deaebeefcafd", "deadbeefcafe + ffffffff" );

    result = ffffffff.add(deadbeefcafe);
    equal( result.toString(16), "deaebeefcafd", "ffffffff + deadbeefcafe" );

    result = ffffffff.add(-4294967295);
    equal( result.valueOf(), 0, "ffffffff + (-ffffffff)" );

    result = (new asmCrypto.BigNumber('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')).add(new asmCrypto.BigNumber('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'));
    equal( result.toString(16), "10000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe", "large fff…fff" );
});

test( "asmCrypto.BigNumber.subtract", function () {
    var deadbeefcafe = new asmCrypto.BigNumber(0xdeadbeefcafe),
        ffffffff = new asmCrypto.BigNumber(0xffffffff),
        result = null;

    result = deadbeefcafe.subtract(ffffffff);
    equal( result.toString(16), "deacbeefcaff", "deadbeefcafe - ffffffff" );

    result = ffffffff.subtract(deadbeefcafe);
    equal( result.toString(16), "-deacbeefcaff", "ffffffff - deadbeefcafe" );

    result = (new asmCrypto.BigNumber('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')).subtract(new asmCrypto.BigNumber('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'));
    equal( result.toString(16), "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000", "large fff…fff" );
});

test( "asmCrypto.BigNumber.multiply", function () {
    var small = new asmCrypto.BigNumber(0xabcdabcd),
        large = new asmCrypto.BigNumber("322e393f76a1c22b147e7d193c00c023afb7c1500b006ff1bc1cc8d391fc38bd"),
        verylarge = new asmCrypto.BigNumber("3f70f29d3f3ae354a6d2536ceafba83cfc787cd91e7acd2b6bde05e62beb8295ae18e3f786726f8d034bbc15bf8331df959f59d431736d5f306aaba63dacec279484e39d76db9b527738072af15730e8b9956a64e8e4dbe868f77d1414a8a8b8bf65380a1f008d39c5fabe1a9f8343929342ab7b4f635bdc52532d764701ff3d8072c475c012ff0c59373e8bc423928d99f58c3a6d9f6ab21ee20bc8e8818fc147db09f60c81906f2c6f73dc69725f075853a89f0cd02a30a8dd86b660ccdeffc292f398efb54088c822774445a6afde471f7dd327ef9996296898a5747726ccaeeceeb2e459df98b4128cb5ab8c7cd20c563f960a1aa770f3c81f13f967b6cc"),
        result = null;

    result = small.multiply(0x1000);
    equal( result.toString(16), "abcdabcd000", "small product is ok" );

    result = large.multiply(large);
    equal( result.toString(16), "9d616b569f3248a3e8b0bdcbed25f33122fd4e63f46cdacf664809417b3af1210cfd498deef48381295f067280f14d9ec85fe251e545f5013048853daab3b89", "large product is ok");

    result = verylarge.multiply(verylarge);
    equal( result.toString(16), "fb8c93e94a3fb8c87d267c2550011118c118f0a8ed6b1f2a611a13d05c363e90514fd4e4b4f8485b9113846168ba5cca86bfb8faadd25a5b978da0e95432a4203ca0c58ad4c34a81acb7065dc182a58e5bbca29b1ab195209a48dd6429aaa29ea2109ba8ea28302108b7b1812dcbbf4221e72e7d1283264bf0a2e2cb180e8687892ba428b88b92bcfdc228b733a02dceec5e0ee501b81b4ee68d66e320e3aae26f63cbd2db9f01e43844b1c40c68dfd2f329925cd1334a5af0f33f8ea509c1bb9c810bed4a4e5d0b91504cf56178027af972130bc3eaaac52868b3b0c554204d55470e05ff5dd70d8b70b8c385277329d0d4d0a5aa7a1c555750eaee4f1e1581ab56e3b1210e14d46393539ccb793e3a6a6f15bcf61b1e8a9acdf36db03457a37a1ae522c0129c18d08345ccc2f44352ed159db24272d4ac2de9e5f6c361477826b9d62be54468a9c9949ba0c772548dd28eabb4e195bb87a01244c3d44462aaa0ab3f22b48693650da8a1ffddde979533709f4dfb2b1a7c6fa98646deeb4b97f29d8c79f74f3f537845b99f8564ff046d35fbe108e13cf17c3f1b9390512fc57cd2f66d6ff94a455ba646a3ebc7464376b63126c869e2b722510243ee579882540e3d02e796c997fe1d43e2364314ba3190bc8ff0ba09855df3ef9cd3277b4f4ffeba6aeafc9513d89c012507cc8a471ea2ab91b24898afd6575e572aeb290", "verylarge product is ok");
});

test( "asmCrypto.BigNumber.square", function () {
    var small = new asmCrypto.BigNumber("ffffffff"),
        medium = new asmCrypto.BigNumber("ffffffffffffffff"),
        medium2 = new asmCrypto.BigNumber("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        large = new asmCrypto.BigNumber("322e393f76a1c22b147e7d193c00c023afb7c1500b006ff1bc1cc8d391fc38bd"),
        verylarge = new asmCrypto.BigNumber("3f70f29d3f3ae354a6d2536ceafba83cfc787cd91e7acd2b6bde05e62beb8295ae18e3f786726f8d034bbc15bf8331df959f59d431736d5f306aaba63dacec279484e39d76db9b527738072af15730e8b9956a64e8e4dbe868f77d1414a8a8b8bf65380a1f008d39c5fabe1a9f8343929342ab7b4f635bdc52532d764701ff3d8072c475c012ff0c59373e8bc423928d99f58c3a6d9f6ab21ee20bc8e8818fc147db09f60c81906f2c6f73dc69725f075853a89f0cd02a30a8dd86b660ccdeffc292f398efb54088c822774445a6afde471f7dd327ef9996296898a5747726ccaeeceeb2e459df98b4128cb5ab8c7cd20c563f960a1aa770f3c81f13f967b6cc"),
        result;

    result = small.square();
    equal( result.toString(16), "fffffffe00000001", "small square is ok" );

    result = medium.square();
    equal( result.toString(16), "fffffffffffffffe0000000000000001", "medium square is ok" );

    result = medium2.square();
    equal( result.toString(16), "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000001", "medium2 square is ok" );

    result = large.square();
    equal( result.toString(16), "9d616b569f3248a3e8b0bdcbed25f33122fd4e63f46cdacf664809417b3af1210cfd498deef48381295f067280f14d9ec85fe251e545f5013048853daab3b89", "large square is ok");

    result = verylarge.square();
    equal( result.toString(16), "fb8c93e94a3fb8c87d267c2550011118c118f0a8ed6b1f2a611a13d05c363e90514fd4e4b4f8485b9113846168ba5cca86bfb8faadd25a5b978da0e95432a4203ca0c58ad4c34a81acb7065dc182a58e5bbca29b1ab195209a48dd6429aaa29ea2109ba8ea28302108b7b1812dcbbf4221e72e7d1283264bf0a2e2cb180e8687892ba428b88b92bcfdc228b733a02dceec5e0ee501b81b4ee68d66e320e3aae26f63cbd2db9f01e43844b1c40c68dfd2f329925cd1334a5af0f33f8ea509c1bb9c810bed4a4e5d0b91504cf56178027af972130bc3eaaac52868b3b0c554204d55470e05ff5dd70d8b70b8c385277329d0d4d0a5aa7a1c555750eaee4f1e1581ab56e3b1210e14d46393539ccb793e3a6a6f15bcf61b1e8a9acdf36db03457a37a1ae522c0129c18d08345ccc2f44352ed159db24272d4ac2de9e5f6c361477826b9d62be54468a9c9949ba0c772548dd28eabb4e195bb87a01244c3d44462aaa0ab3f22b48693650da8a1ffddde979533709f4dfb2b1a7c6fa98646deeb4b97f29d8c79f74f3f537845b99f8564ff046d35fbe108e13cf17c3f1b9390512fc57cd2f66d6ff94a455ba646a3ebc7464376b63126c869e2b722510243ee579882540e3d02e796c997fe1d43e2364314ba3190bc8ff0ba09855df3ef9cd3277b4f4ffeba6aeafc9513d89c012507cc8a471ea2ab91b24898afd6575e572aeb290", "verylarge square is ok");
});

test( "asmCrypto.BigNumber.divide", function () {
    var small = new asmCrypto.BigNumber("95705fac129de210", 16),
        small2 = new asmCrypto.BigNumber("fffffffe00000002", 16),
        small3 = new asmCrypto.BigNumber("ffffffff", 16),
        large = new asmCrypto.BigNumber("9d616b569f3248a3e8b0bdcbed25f33122fd4e63f46cdacf664809417b3af1210cfd498deef48381295f067280f14d9ec85fe251e545f5013048853daab3b89", 16),
        large2 = new asmCrypto.BigNumber("322e393f76a1c22b147e7d193c00c023afb7c1500b006ff1bc1cc8d391fc38bd", 16),
        result = null;

    result = small.divide(0xabcd);
    equal( result.remainder.toString(16), "aaaa", "small % 0xabcd" );
    equal( result.quotient.toString(16), "deadbeefcafe", "floor( small / 0xabcd )" );

    result = small2.divide(small3);
    equal( result.remainder.toString(16), "1", "small2 % small3" );
    equal( result.quotient.toString(16), "ffffffff", "floor( small2 / small3 )" );

    result = large.divide(large2);
    equal( result.remainder, asmCrypto.BigNumber.ZERO, "large % large2" );
    equal( result.quotient.toString(16), "322e393f76a1c22b147e7d193c00c023afb7c1500b006ff1bc1cc8d391fc38bd", "floor( large / large2 )" );
});

test( "asmCrypto.BigNumber.extGCD", function () {
    var z;

    z = asmCrypto.BigNumber.extGCD(3, 2);
    equal( z.gcd.valueOf(), 1, "gcd ok" );
    equal( z.x.valueOf(), 1, "x ok" );
    equal( z.y.valueOf(), -1, "y ok" );

    z = asmCrypto.BigNumber.extGCD(240, 46);
    equal( z.gcd.valueOf(), 2, "gcd ok" );
    equal( z.x.valueOf(), -9, "x ok" );
    equal( z.y.valueOf(), 47, "y ok" );

    z = asmCrypto.BigNumber.extGCD( "abcdabcdabcd", "20000000000000" );
    equal( z.gcd.valueOf(), 1, "gcd ok" );
    equal( z.x.toString(16), "9b51de3a73905", "x ok" );
    equal( z.y.toString(16), "-341e3c1e3c1e", "y ok" );

    z = asmCrypto.BigNumber.extGCD(
        "00:fc:bd:95:95:6b:ea:86:7f:e1:25:0b:17:9f:b2:d4:e0:c5:9c:4a:2f:e4:69:a0:1c:d9:05:09:d7:d7:c2:5c:df:84:f7:7e:ea:1f:be:50:92:69:81:9a:82:89:59:b3:9b:8f:54:a3:8a:6f:02:90:e4:8c:0f:3c:9c:45:b7:81:23",
        "00:d5:17:64:43:be:bb:2a:31:a4:4d:f7:11:ff:7c:98:23:95:c5:47:73:65:f3:61:83:98:fd:7d:37:fa:d4:d2:39:4f:94:58:c3:9d:ec:56:1d:ab:0b:c6:c7:ce:d1:c7:6b:29:cf:d2:e1:4e:c7:93:d5:d3:00:c7:0d:49:ad:a9:f1" );
    equal( z.gcd.valueOf(), 1, "gcd ok" );
});

test ( "asmCrypto.Modulus", function () {
    var M = new asmCrypto.Modulus(123456789);

    ok( M, "new Modulus" );
    ok( M instanceof asmCrypto.BigNumber, "instanceof Modulus" );
    equal( M.reduce(987654321).valueOf(), 9, "Modulus.reduce(small)" );

    var M2 = new asmCrypto.Modulus(0xabcdabcdabcd);
    equal( M2.comodulus.toString(16), "10000000000000", "M2 comodulus ok" );
    equal( M2.comodulusRemainder.toString(16), "908590859095", "M2 comodulus remainder ok" );
    equal( M2.comodulusRemainderSquare.toString(16), "1cf01cf02cf", "M2 comodulus remainder square ok" );
    equal( M2.bezoutCoefficient.toString(16), "64ae21c58c6fb", "M2 Bézout coefficent ok" );
    equal( M2.reduce(0x9bcdefabcdef).valueOf(), 0x9bcdefabcdef, "Modulus.reduce(medium)" );
});
