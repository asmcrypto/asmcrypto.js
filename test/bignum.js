module("BigNumber");

///////////////////////////////////////////////////////////////////////////////

if ( typeof asmCrypto.BigNumber !== 'undefined' )
{
    test( "new asmCrypto.BigNumber()", function () {
        var zero = new asmCrypto.BigNumber();
        ok( zero, "zero = new 0" );
        equal( zero.limbs.length, 0, "zero.limbs.length" );
        equal( zero.bitLength, 0, "zero.bitLength" );
        equal( zero.valueOf(), 0, "zero.valueOf()" );
        equal( zero.toString(16), '0', "zero.toString(16)" );

        var one = new asmCrypto.BigNumber(1);
        ok( one, "one = new 1" );
        equal( one.limbs.length, 1, "one.limbs.length" );
        equal( one.limbs[0], 1, "one.limbs[0]" );
        equal( one.bitLength, 32, "one.bitLength" );
        equal( one.valueOf(), 1, "one.valueOf()" );
        equal( one.toString(16), '1', "one.toString(16)" );

        var ten = new asmCrypto.BigNumber(10);
        ok( ten, "ten = new 10" );
        equal( ten.limbs.length, 1, "ten.limbs.length" );
        equal( ten.limbs[0], 10, "ten.limbs[0]" );
        equal( ten.bitLength, 32, "ten.bitLength" );
        equal( ten.valueOf(), 10, "ten.valueOf()" );
        equal( ten.toString(16), 'a', "ten.toString(16)" );

        var mten = new asmCrypto.BigNumber(-10);
        ok( mten, "mten = new -10" );
        equal( mten.limbs.length, 1, "mten.limbs.length" );
        equal( mten.limbs[0], 10, "mten.limbs[0]" );
        equal( mten.bitLength, 32, "mten.bitLength" );
        equal( mten.valueOf(), -10, "mten.valueOf()" );
        equal( mten.toString(16), '-a', "mten.toString(16)" );

        var ffffffff = new asmCrypto.BigNumber(0xffffffff);
        ok( ffffffff, "ffffffff = new 0xfffffff" );
        equal( ffffffff.limbs.length, 1, "ffffffff.limbs.length" );
        equal( ffffffff.limbs[0], 0xffffffff, "ffffffff.limbs[0]" );
        equal( ffffffff.bitLength, 32, "ffffffff.bitLength" );
        equal( ffffffff.valueOf(), 0xffffffff, "ffffffff.valueOf()" );
        equal( ffffffff.toString(16), 'ffffffff', "ffffffff.toString(16)" );

        var deadbeefcafe = new asmCrypto.BigNumber(0xdeadbeefcafe);
        ok( deadbeefcafe, "deadbeefcafe = new 0xdeadbeefcafe" );
        equal( deadbeefcafe.limbs.length, 2, "deadbeefcafe.limbs.length" );
        equal( deadbeefcafe.limbs[0], 0xbeefcafe, "deadbeefcafe.limbs[0]" );
        equal( deadbeefcafe.limbs[1], 0xdead, "deadbeefcafe.limbs[1]" );
        equal( deadbeefcafe.bitLength, 52, "deadbeefcafe.bitLength" );
        equal( deadbeefcafe.valueOf(), 0xdeadbeefcafe, "deadbeefcafe.valueOf()" );
        equal( deadbeefcafe.toString(16), 'deadbeefcafe', "deadbeefcafe.toString(16)" );

        var verylarge = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('3f70f29d3f3ae354a6d2536ceafba83cfc787cd91e7acd2b6bde05e62beb8295ae18e3f786726f8d034bbc15bf8331df959f59d431736d5f306aaba63dacec279484e39d76db9b527738072af15730e8b9956a64e8e4dbe868f77d1414a8a8b8bf65380a1f008d39c5fabe1a9f8343929342ab7b4f635bdc52532d764701ff3d8072c475c012ff0c59373e8bc423928d99f58c3a6d9f6ab21ee20bc8e8818fc147db09f60c81906f2c6f73dc69725f075853a89f0cd02a30a8dd86b660ccdeffc292f398efb54088c822774445a6afde471f7dd327ef9996296898a5747726ccaeeceeb2e459df98b4128cb5ab8c7cd20c563f960a1aa770f3c81f13f967b6cc'));
        ok( verylarge, "verylarge = new 3f70f29d…f967b6cc" );
        equal( verylarge.limbs.length, 64, "verylarge.limbs.length" );
        equal( verylarge.limbs[0], 0xf967b6cc, "verylarge.limbs[0]" );
        equal( verylarge.limbs[63], 0x3f70f29d, "verylarge.limbs[63]" );
        equal( verylarge.bitLength, 2048, "verylarge.bitLength" );
        equal( verylarge.valueOf(), Infinity, "verylarge.valueOf()" );
        equal( verylarge.toString(16), '3f70f29d3f3ae354a6d2536ceafba83cfc787cd91e7acd2b6bde05e62beb8295ae18e3f786726f8d034bbc15bf8331df959f59d431736d5f306aaba63dacec279484e39d76db9b527738072af15730e8b9956a64e8e4dbe868f77d1414a8a8b8bf65380a1f008d39c5fabe1a9f8343929342ab7b4f635bdc52532d764701ff3d8072c475c012ff0c59373e8bc423928d99f58c3a6d9f6ab21ee20bc8e8818fc147db09f60c81906f2c6f73dc69725f075853a89f0cd02a30a8dd86b660ccdeffc292f398efb54088c822774445a6afde471f7dd327ef9996296898a5747726ccaeeceeb2e459df98b4128cb5ab8c7cd20c563f960a1aa770f3c81f13f967b6cc', "verylarge.toString()" );
    });

    test( "asmCrypto.BigNumber.splice", function () {
        var deadbeefcafe = new asmCrypto.BigNumber(0xdeadbeefcafe);
        equal( deadbeefcafe.splice(0).valueOf(), 0xdeadbeefcafe, "splice(0)" );
        equal( deadbeefcafe.splice(52).valueOf(), 0, "splice(bitLength)" );
        equal( deadbeefcafe.splice(24,16).valueOf(), 0xadbe, "splice(middle)" );
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
        equal( result.toString(16), 'deaebeefcafd', "deadbeefcafe + ffffffff" );

        result = ffffffff.add(deadbeefcafe);
        equal( result.toString(16), 'deaebeefcafd', "ffffffff + deadbeefcafe" );

        result = ffffffff.add(-4294967295);
        equal( result.valueOf(), 0, "ffffffff + (-ffffffff)" );

        result = (new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'))).add(new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')));
        equal( result.toString(16), '10000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe', "large fff…fff" );
    });

    test( "asmCrypto.BigNumber.subtract", function () {
        var deadbeefcafe = new asmCrypto.BigNumber(0xdeadbeefcafe),
            ffffffff = new asmCrypto.BigNumber(0xffffffff),
            result = null;

        result = deadbeefcafe.subtract(ffffffff);
        equal( result.toString(16), 'deacbeefcaff', "deadbeefcafe - ffffffff" );

        result = ffffffff.subtract(deadbeefcafe);
        equal( result.toString(16), '-deacbeefcaff', "ffffffff - deadbeefcafe" );

        result = (new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'))).subtract(new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')));
        equal( result.toString(16), 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000', "large fff…fff" );
    });

    test( "asmCrypto.BigNumber.multiply", function () {
        var small = new asmCrypto.BigNumber(0xabcdabcd),
            large = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('322e393f76a1c22b147e7d193c00c023afb7c1500b006ff1bc1cc8d391fc38bd')),
            verylarge = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('3f70f29d3f3ae354a6d2536ceafba83cfc787cd91e7acd2b6bde05e62beb8295ae18e3f786726f8d034bbc15bf8331df959f59d431736d5f306aaba63dacec279484e39d76db9b527738072af15730e8b9956a64e8e4dbe868f77d1414a8a8b8bf65380a1f008d39c5fabe1a9f8343929342ab7b4f635bdc52532d764701ff3d8072c475c012ff0c59373e8bc423928d99f58c3a6d9f6ab21ee20bc8e8818fc147db09f60c81906f2c6f73dc69725f075853a89f0cd02a30a8dd86b660ccdeffc292f398efb54088c822774445a6afde471f7dd327ef9996296898a5747726ccaeeceeb2e459df98b4128cb5ab8c7cd20c563f960a1aa770f3c81f13f967b6cc')),
            result = null;

        result = small.multiply(0x1000);
        equal( result.toString(16), 'abcdabcd000', "small product is ok" );

        result = large.multiply(large);
        equal( result.toString(16), '9d616b569f3248a3e8b0bdcbed25f33122fd4e63f46cdacf664809417b3af1210cfd498deef48381295f067280f14d9ec85fe251e545f5013048853daab3b89', "large product is ok");

        result = verylarge.multiply(verylarge);
        equal( result.toString(16), 'fb8c93e94a3fb8c87d267c2550011118c118f0a8ed6b1f2a611a13d05c363e90514fd4e4b4f8485b9113846168ba5cca86bfb8faadd25a5b978da0e95432a4203ca0c58ad4c34a81acb7065dc182a58e5bbca29b1ab195209a48dd6429aaa29ea2109ba8ea28302108b7b1812dcbbf4221e72e7d1283264bf0a2e2cb180e8687892ba428b88b92bcfdc228b733a02dceec5e0ee501b81b4ee68d66e320e3aae26f63cbd2db9f01e43844b1c40c68dfd2f329925cd1334a5af0f33f8ea509c1bb9c810bed4a4e5d0b91504cf56178027af972130bc3eaaac52868b3b0c554204d55470e05ff5dd70d8b70b8c385277329d0d4d0a5aa7a1c555750eaee4f1e1581ab56e3b1210e14d46393539ccb793e3a6a6f15bcf61b1e8a9acdf36db03457a37a1ae522c0129c18d08345ccc2f44352ed159db24272d4ac2de9e5f6c361477826b9d62be54468a9c9949ba0c772548dd28eabb4e195bb87a01244c3d44462aaa0ab3f22b48693650da8a1ffddde979533709f4dfb2b1a7c6fa98646deeb4b97f29d8c79f74f3f537845b99f8564ff046d35fbe108e13cf17c3f1b9390512fc57cd2f66d6ff94a455ba646a3ebc7464376b63126c869e2b722510243ee579882540e3d02e796c997fe1d43e2364314ba3190bc8ff0ba09855df3ef9cd3277b4f4ffeba6aeafc9513d89c012507cc8a471ea2ab91b24898afd6575e572aeb290', "verylarge product is ok");

        result = (new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('3f70f29d3f3ae354a6d2536ceafba83cfc787cd91e7acd2b6bde05e62beb8295ae18e3f786726f8d034bbc15bf8331df959f59d431736d5f306aaba63dacec279484e39d76db9b527738072af15730e8b9956a64e8e4dbe868f77d1414a8a8b8bf65380a1f008d39c5fabe1a9f8343929342ab7b4f635bdc52532d764701ff3d8072c475c012ff0c59373e8bc423928d99f58c3a6d9f6ab21ee20bc8e8818fc147db09f60c81906f2c6f73dc69725f075853a89f0cd02a30a8dd86b660ccdeffc292f398efb54088c822774445a6afde471f7dd327ef9996296898a5747726ccaeeceeb2e459df98b4128cb5ab8c7cd20c563f960a1aa770f3c81f13f967b6cc'))).multiply(asmCrypto.hex_to_bytes('100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'));
        equal( result.toString(16), '3f70f29d3f3ae354a6d2536ceafba83cfc787cd91e7acd2b6bde05e62beb8295ae18e3f786726f8d034bbc15bf8331df959f59d431736d5f306aaba63dacec279484e39d76db9b527738072af15730e8b9956a64e8e4dbe868f77d1414a8a8b8bf65380a1f008d39c5fabe1a9f8343929342ab7b4f635bdc52532d764701ff3d8072c475c012ff0c59373e8bc423928d99f58c3a6d9f6ab21ee20bc8e8818fc147db09f60c81906f2c6f73dc69725f075853a89f0cd02a30a8dd86b660ccdeffc292f398efb54088c822774445a6afde471f7dd327ef9996296898a5747726ccaeeceeb2e459df98b4128cb5ab8c7cd20c563f960a1aa770f3c81f13f967b6cc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', "verylarge2 product is ok");
    });

    test( "asmCrypto.BigNumber.square", function () {
        var small = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('ffffffff')),
            medium = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('ffffffffffffffff')),
            medium2 = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')),
            large = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('322e393f76a1c22b147e7d193c00c023afb7c1500b006ff1bc1cc8d391fc38bd')),
            verylarge = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('3f70f29d3f3ae354a6d2536ceafba83cfc787cd91e7acd2b6bde05e62beb8295ae18e3f786726f8d034bbc15bf8331df959f59d431736d5f306aaba63dacec279484e39d76db9b527738072af15730e8b9956a64e8e4dbe868f77d1414a8a8b8bf65380a1f008d39c5fabe1a9f8343929342ab7b4f635bdc52532d764701ff3d8072c475c012ff0c59373e8bc423928d99f58c3a6d9f6ab21ee20bc8e8818fc147db09f60c81906f2c6f73dc69725f075853a89f0cd02a30a8dd86b660ccdeffc292f398efb54088c822774445a6afde471f7dd327ef9996296898a5747726ccaeeceeb2e459df98b4128cb5ab8c7cd20c563f960a1aa770f3c81f13f967b6cc')),
            result;

        result = small.square();
        equal( result.toString(16), 'fffffffe00000001', "small square is ok" );

        result = medium.square();
        equal( result.toString(16), 'fffffffffffffffe0000000000000001', "medium square is ok" );

        result = medium2.square();
        equal( result.toString(16), 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000001', "medium2 square is ok" );

        result = large.square();
        equal( result.toString(16), '9d616b569f3248a3e8b0bdcbed25f33122fd4e63f46cdacf664809417b3af1210cfd498deef48381295f067280f14d9ec85fe251e545f5013048853daab3b89', "large square is ok");

        result = verylarge.square();
        equal( result.toString(16), 'fb8c93e94a3fb8c87d267c2550011118c118f0a8ed6b1f2a611a13d05c363e90514fd4e4b4f8485b9113846168ba5cca86bfb8faadd25a5b978da0e95432a4203ca0c58ad4c34a81acb7065dc182a58e5bbca29b1ab195209a48dd6429aaa29ea2109ba8ea28302108b7b1812dcbbf4221e72e7d1283264bf0a2e2cb180e8687892ba428b88b92bcfdc228b733a02dceec5e0ee501b81b4ee68d66e320e3aae26f63cbd2db9f01e43844b1c40c68dfd2f329925cd1334a5af0f33f8ea509c1bb9c810bed4a4e5d0b91504cf56178027af972130bc3eaaac52868b3b0c554204d55470e05ff5dd70d8b70b8c385277329d0d4d0a5aa7a1c555750eaee4f1e1581ab56e3b1210e14d46393539ccb793e3a6a6f15bcf61b1e8a9acdf36db03457a37a1ae522c0129c18d08345ccc2f44352ed159db24272d4ac2de9e5f6c361477826b9d62be54468a9c9949ba0c772548dd28eabb4e195bb87a01244c3d44462aaa0ab3f22b48693650da8a1ffddde979533709f4dfb2b1a7c6fa98646deeb4b97f29d8c79f74f3f537845b99f8564ff046d35fbe108e13cf17c3f1b9390512fc57cd2f66d6ff94a455ba646a3ebc7464376b63126c869e2b722510243ee579882540e3d02e796c997fe1d43e2364314ba3190bc8ff0ba09855df3ef9cd3277b4f4ffeba6aeafc9513d89c012507cc8a471ea2ab91b24898afd6575e572aeb290', "verylarge square is ok");
    });

    test( "asmCrypto.BigNumber.divide", function () {
        var small = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('95705fac129de210')),
            small2 = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('fffffffe00000002')),
            small3 = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('ffffffff')),
            large = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('9d616b569f3248a3e8b0bdcbed25f33122fd4e63f46cdacf664809417b3af1210cfd498deef48381295f067280f14d9ec85fe251e545f5013048853daab3b89')),
            large2 = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('322e393f76a1c22b147e7d193c00c023afb7c1500b006ff1bc1cc8d391fc38bd')),
            result = null;

        result = small.divide(0xabcd);
        equal( result.remainder.toString(16), 'aaaa', "small % 0xabcd" );
        equal( result.quotient.toString(16), 'deadbeefcafe', "floor( small / 0xabcd )" );

        result = small2.divide(small3);
        equal( result.remainder.toString(16), '1', "small2 % small3" );
        equal( result.quotient.toString(16), 'ffffffff', "floor( small2 / small3 )" );

        result = large.divide(large2);
        equal( result.remainder, asmCrypto.BigNumber.ZERO, "large % large2" );
        equal( result.quotient.toString(16), '322e393f76a1c22b147e7d193c00c023afb7c1500b006ff1bc1cc8d391fc38bd', "floor( large / large2 )" );

        result = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'))
                .divide(asmCrypto.hex_to_bytes('c7f1bc1dfb1be82d244aef01228c1409c198894eca9e21430f1669b4aa3864c9f37f3d51b2b4ba1ab9e80f59d267fda1521e88b05117993175e004543c6e3611242f24432ce8efa3b81f0ff660b4f91c5d52f2511a6f38181a7bf9abeef72db056508bbb4eeb5f65f161dd2d5b439655d2ae7081fcc62fdcb281520911d96700c85cdaf12e7d1f15b55ade867240722425198d4ce39019550c4c8a921fc231d3e94297688c2d77cd68ee8fdeda38b7f9a274701fef23b4eaa6c1a9c15b2d77f37634930386fc20ec291be95aed9956801e1c76601b09c413ad915ff03bfdc0b6b233686ae59e8caf11750b509ab4e57ee09202239baee3d6e392d1640185e1cd'));
        equal( result.quotient.toString(16), '1', "q is ok" );
        equal( result.remainder.toString(16), '380e43e204e417d2dbb510fedd73ebf63e6776b13561debcf0e9964b55c79b360c80c2ae4d4b45e54617f0a62d98025eade1774faee866ce8a1ffbabc391c9eedbd0dbbcd317105c47e0f0099f4b06e3a2ad0daee590c7e7e58406541108d24fa9af7444b114a09a0e9e22d2a4bc69aa2d518f7e0339d0234d7eadf6ee2698ff37a3250ed182e0ea4aa521798dbf8ddbdae672b31c6fe6aaf3b3756de03dce2c16bd689773d288329711702125c748065d8b8fe010dc4b15593e563ea4d2880c89cb6cfc7903df13d6e416a51266a97fe1e3899fe4f63bec526ea00fc4023f494dcc97951a617350ee8af4af654b1a811f6dfddc64511c291c6d2e9bfe7a1e33', "r is ok" );

        result = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('ad399e5f74531e554ab7e7130b8ae864c7ea09621f5fff87e07160b080e89cca0bb74448c9e792b53806bce62a0cedfed2184ea47014988c92fdbafe60771d02d5b5dcf7d4f5ac1dc0a1dd010d7ae5672efdb92b38f56b78ac54797d18a6dd363fdac5e58b68321305983c81cf4d627ed2a59c150458999e23d1d2569beb083c67fab925ae495a97acb4465aa6960d1df08a73d3f5362a53c3db3813f006d7bb7a29028d0547e918f2bb407acf60f6391b7862a1db39f26727771c61747a7766619a42864faa21d8d23317e12abbb13e0ba2ad6f7f0e3d08'))
                .divide(asmCrypto.hex_to_bytes('a736146b621310f6cd645cb2fefeda223aa7ae33a53ac22e019b6ffb7167d9b29be1aebb3e1a7129ee3a5b4fb1a11660932b9be2b36a6dd3226451d7c4dd79619bdb9aa5596cef4e7b6d91f0e227bba2547b004ded1ed0e06182141dc55e183374fe1d93e23c38fcc81cd8eae82647528dde963cf1ef86f470e69436a2ac0d7fa7161d6fbfd32141217df992002320cb575e8de44c446d73bdf116719d61451c474701e153a01771cb8f070f8241d465d3d0124aed70ec459669bfc4927f941ddac97f4772f8d4d55165d1d06eec147749d0b9fee868ddf3'));
        equal( result.quotient.toString(16), '1', "q is ok" );
        equal( result.remainder.toString(16), '60389f412400d5e7d538a600c8c0e428d425b2e7a253d59ded5f0b50f80c3176fd5958d8bcd218b49cc6196786bd79e3eecb2c1bcaa2ab9709969269b99a3a139da42527b88bccf45344b102b5329c4da82b8dd4bd69a984ad2655f5348c502cadca851a92bf9163d7b6396e7271b2c44c705d8126912a9b2eb3e1ff93efabcc0e49bb5ee7639568b364cc8a672ec52992be5efa8f1bce005ea21a252a5929f32e200abb1a7d1a7272c396b4d1f21d347a85056edc90621910d5c9ce1fae34886d0c33edcb14d0380cd4610bbcf9cc6c1d1f37096a55f15', "r is ok" );

        result = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('ad399e5f74531e554ab7e7130b8ae864c7ea09621f5fff87e07160b080e89cca0bb74448c9e792b53806bce62a0cedfed2184ea47014988c92fdbafe60771d02d5b5dcf7d4f5ac1dc0a1dd010d7ae5672efdb92b38f56b78ac54797d18a6dd363fdac5e58b68321305983c81cf4d627ed2a59c150458999e23d1d2569beb083c67fab925ae495a97acb4465aa6960d1df08a73d3f5362a53c3db3813f006d7bb7a29028d0547e918f2bb407acf60f6391b7862a1db39f26727771c61747a7766619a42864faa21d8d23317e12abbb13e0ba2ad6f7f0e3d08'))
                .divide(asmCrypto.hex_to_bytes('a736146b621310f6cd645cb2fefeda223aa7ae33a53ac22e019b6ffb7167d9b29be1aebb3e1a7129ee3a5b4fb1a11660932b9be2b36a6dd3226451d7c4dd79619bdb9aa5596cef4e7b6d91f0e227bba2547b004ded1ed0e06182141dc55e183374fe1d93e23c38fcc81cd8eae82647528dde963cf1ef86f470e69436a2ac0d7fa7161d6fbfd32141217df992002320cb575e8de44c446d73bdf116719d61451c474701e153a01771cb8f070f8241d465d3d0124aed70ec459669bfc4927f941ddac97f4772f8d4d55165d1d06eec147749d0b9fee868ddf3'));
        equal( result.quotient.toString(16), '1', "q is ok" );
        equal( result.remainder.toString(16), '60389f412400d5e7d538a600c8c0e428d425b2e7a253d59ded5f0b50f80c3176fd5958d8bcd218b49cc6196786bd79e3eecb2c1bcaa2ab9709969269b99a3a139da42527b88bccf45344b102b5329c4da82b8dd4bd69a984ad2655f5348c502cadca851a92bf9163d7b6396e7271b2c44c705d8126912a9b2eb3e1ff93efabcc0e49bb5ee7639568b364cc8a672ec52992be5efa8f1bce005ea21a252a5929f32e200abb1a7d1a7272c396b4d1f21d347a85056edc90621910d5c9ce1fae34886d0c33edcb14d0380cd4610bbcf9cc6c1d1f37096a55f15', "r is ok" );

        result = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('8251a22c009e3e37af0a516bbd73662a462531e4886005cec939265e99f177d7812fd7d5df184c5ea8ced1cace7e6724a4c31b1dbdedcd9636acff51936801df9bdf255850896b4da0aebfbc8944da8385a58f47e335ce94fd53ab1b299335c9e242fd89fc87126c11df2e65efa31fc37ce90e454b72afff5db16c271d476054022227c76c039c30feba1a1bd8d62c11b5c8a9e666b7726c4306c1e84f51c6fbe4485a2826cfacaea58d4a522a48a0164aa45df489944822953f860084d34b3ac537e27af0ed95613ffcb7f775832bf3acc7beff1469ed7a28abbff4dbf08859cafc8b8a7b3a2dc02cdff66095f53897ae74d2ce47e5644ea7ac59398a99b55'))
                .divide(asmCrypto.hex_to_bytes('4128d116004f1f1bd78528b5deb9b315231298f2443002e7649c932f4cf8bbebc097ebeaef8c262f546768e5673f339252618d8edef6e6cb1b567fa8c9b400efcdef92ac2844b5a6d0575fde44a26d41c2d2c7a3f19ae74a7ea9d58d94c99ae4f1217ec4fe43893608ef9732f7d18fe1be748722a5b957ffaed8b6138ea3b02a011113e3b601ce187f5d0d0dec6b1608dae454f3335bb936218360f427a8e37df2242d141367d65752c6a5291524500b25522efa44ca24114a9fc3004269a59d629bf13d7876cab09ffe5bfbbac195f9d663df7f8a34f6bd1455dffa6df8442ce57e45c53d9d16e0166ffb304afa9c4bd73a696723f2b22753d62c9cc54cdab'));
        equal( result.quotient.toString(16), '1', "q is ok" );
        equal( result.remainder.toString(16), '4128d116004f1f1bd78528b5deb9b315231298f2443002e7649c932f4cf8bbebc097ebeaef8c262f546768e5673f339252618d8edef6e6cb1b567fa8c9b400efcdef92ac2844b5a6d0575fde44a26d41c2d2c7a3f19ae74a7ea9d58d94c99ae4f1217ec4fe43893608ef9732f7d18fe1be748722a5b957ffaed8b6138ea3b02a011113e3b601ce187f5d0d0dec6b1608dae454f3335bb936218360f427a8e37df2242d141367d65752c6a5291524500b25522efa44ca24114a9fc3004269a59d629bf13d7876cab09ffe5bfbbac195f9d663df7f8a34f6bd1455dffa6df8442ce57e45c53d9d16e0166ffb304afa9c4bd73a696723f2b22753d62c9cc54cdaa', "r is ok" );
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

        z = asmCrypto.BigNumber.extGCD( asmCrypto.hex_to_bytes('abcdabcdabcd'), asmCrypto.hex_to_bytes('20000000000000') );
        equal( z.gcd.valueOf(), 1, "gcd ok" );
        equal( z.x.toString(16), '9b51de3a73905', "x ok" );
        equal( z.y.toString(16), '-341e3c1e3c1e', "y ok" );

        z = asmCrypto.BigNumber.extGCD(
            asmCrypto.hex_to_bytes('00fcbd95956bea867fe1250b179fb2d4e0c59c4a2fe469a01cd90509d7d7c25cdf84f77eea1fbe509269819a828959b39b8f54a38a6f0290e48c0f3c9c45b78123'),
            asmCrypto.hex_to_bytes('00d5176443bebb2a31a44df711ff7c982395c5477365f3618398fd7d37fad4d2394f9458c39dec561dab0bc6c7ced1c76b29cfd2e14ec793d5d300c70d49ada9f1')
        );
        equal( z.gcd.valueOf(), 1, "gcd ok" );

        z = asmCrypto.BigNumber.extGCD(
            asmCrypto.hex_to_bytes('100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'),
            asmCrypto.hex_to_bytes('c7f1bc1dfb1be82d244aef01228c1409c198894eca9e21430f1669b4aa3864c9f37f3d51b2b4ba1ab9e80f59d267fda1521e88b05117993175e004543c6e3611242f24432ce8efa3b81f0ff660b4f91c5d52f2511a6f38181a7bf9abeef72db056508bbb4eeb5f65f161dd2d5b439655d2ae7081fcc62fdcb281520911d96700c85cdaf12e7d1f15b55ade867240722425198d4ce39019550c4c8a921fc231d3e94297688c2d77cd68ee8fdeda38b7f9a274701fef23b4eaa6c1a9c15b2d77f37634930386fc20ec291be95aed9956801e1c76601b09c413ad915ff03bfdc0b6b233686ae59e8caf11750b509ab4e57ee09202239baee3d6e392d1640185e1cd')
            );
        equal( z.gcd.valueOf(), 1, "gcd ok" );
        equal( z.x.toString(16), '-210fc146c2f2919c3e9a4372a7221069fa359d7feba4ecaf765c47f29819a82ebb92c5944f921e090c8f0eee5218d243b35eb488fdef6a2f9712ba887625af9599b2a547595528054f079124831d94872243009cec4e3154199893d700c2a64c3fae1e259bd37b4f88e34a6ff0fcb7c221a9b222df4a74f4d381259c641cef4d05bbbc737ac29f06e050139aa823d00c2af2b484720a58eadc39ea10d53c8664289e5495fcb188abecb167c8b81a267a24fa304b447d484c37af38525f5c1c3c7bc9e614b779e21d582c0222fa8bc13bc37673cefbb60a84a70423dcec8850d6c3c80c244e09cee87e7f6dadaf24a2b9410bc31e1afc588f9d20d769a5c3df71', "x ok" );
        equal( z.y.toString(16), '2a54a02a4b2182e2ea06578065a9608f53c45bd34ab2d3c47c18bca20e2bf9d93f6ac1aecc7a4bf18cfbc073db8cd0829b656bcb1f7a52b10bdc463ac246f11a30c0cc4ea00f093fcb0b4809a2b83bfb627789c6daac33d467a2b7bcda403018b344ca065fecccd2922afd53268ea599b17b96f29fe9fa4487cd0df93db31f3197a1973fafdd5f37a9f80f2554947ed63ffa4f12f0c5eefec24e9192ddcbc19ad179f76d95e361250300f18de3f7c9a067b84ccba3b31e1d1cf4379a492aa916882e09fa6836e3524b9bf750cf8f8dddbb48dd2ac0a9cfdfe6409330c0d62f08d13ec220436482bb39db9b1c595c5e0e0b743344620ac8eb0e18b0d3c641f305', "y ok" );
    });

    test( "asmCrypto.Modulus", function () {
        var M = new asmCrypto.Modulus(123456789);

        ok( M, "new Modulus" );
        ok( M instanceof Number, "instanceof Number" );
        equal( M.reduce(987654321).valueOf(), 9, "Modulus.reduce(small)" );

        var M2 = new asmCrypto.Modulus(0xabcdabcdabcd);
        equal( M2.comodulus.toString(16), '10000000000000000', "M2 comodulus ok" );
        equal( M2.comodulusRemainder.toString(16), '624f6250624f', "M2 comodulus remainder ok" );
        equal( M2.comodulusRemainderSquare.toString(16), '399f399e399e', "M2 comodulus remainder square ok" );
        equal( M2.coefficient.toString(16), '1c58c6fb', "M2 coefficent ok" );

        var M3 = new asmCrypto.Modulus(asmCrypto.hex_to_bytes('c7f1bc1dfb1be82d244aef01228c1409c198894eca9e21430f1669b4aa3864c9f37f3d51b2b4ba1ab9e80f59d267fda1521e88b05117993175e004543c6e3611242f24432ce8efa3b81f0ff660b4f91c5d52f2511a6f38181a7bf9abeef72db056508bbb4eeb5f65f161dd2d5b439655d2ae7081fcc62fdcb281520911d96700c85cdaf12e7d1f15b55ade867240722425198d4ce39019550c4c8a921fc231d3e94297688c2d77cd68ee8fdeda38b7f9a274701fef23b4eaa6c1a9c15b2d77f37634930386fc20ec291be95aed9956801e1c76601b09c413ad915ff03bfdc0b6b233686ae59e8caf11750b509ab4e57ee09202239baee3d6e392d1640185e1cd'));
        equal( M3.comodulus.toString(16), '100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', "M3 comodulus ok" );
        equal( M3.comodulusRemainder.toString(16), '380e43e204e417d2dbb510fedd73ebf63e6776b13561debcf0e9964b55c79b360c80c2ae4d4b45e54617f0a62d98025eade1774faee866ce8a1ffbabc391c9eedbd0dbbcd317105c47e0f0099f4b06e3a2ad0daee590c7e7e58406541108d24fa9af7444b114a09a0e9e22d2a4bc69aa2d518f7e0339d0234d7eadf6ee2698ff37a3250ed182e0ea4aa521798dbf8ddbdae672b31c6fe6aaf3b3756de03dce2c16bd689773d288329711702125c748065d8b8fe010dc4b15593e563ea4d2880c89cb6cfc7903df13d6e416a51266a97fe1e3899fe4f63bec526ea00fc4023f494dcc97951a617350ee8af4af654b1a811f6dfddc64511c291c6d2e9bfe7a1e33', "M3 comodulus remainder ok" );
        equal( M3.comodulusRemainderSquare.toString(16), 'a8d0cc3c0069b1fe694294247f367071deb9b3fdc80824536f04fae0c3df7fccc9f856aeee2033803b371a3c455522fb288c60f326db2fdcaf7452b48b0f0a29cce2dabe844a63f8077be24d2a0db5051e8a1481c16f0b880819cf8d193adaa79c92f11f1e4a2e89f24bc0ef0e2285ff218a5c058908f6feef024b0c8bfe11d37cba38103339f19ba7466f3070588152f1a008dc454cebcc4f70879e94ac1eb26179833049da7b450fbe93d7d802edc5900b3a973d05ff76c6bbb7914c59b27265222501b14497fe0ef99b7fa67777bf9ab89a8b346aacb6dbf606e68da0ba2a5c4ce3b0f85225292cd1acafebae5f553c03e9c3857730c715017550e4e77a53', "M3 comodulus remainder square ok" );
        equal( M3.coefficient.toString(16), "39be0cfb", "M3 coefficent ok" );

        var M4 = new asmCrypto.Modulus( asmCrypto.hex_to_bytes('453b5e276054110d94fd7b413ca54e467543c28168730315dae65c6241c847aa7ca16aa99e84e89249addf73bdb326cb7787a667cce65537cd0be7a3564f40fecace8bd6eac901013d5cd5dc28ec9415defff41e30b495bf269472e66e163493403396b14e27c1c9697e90a6274ea8dfda5bcf94d014ed7fa9c64174c78deb2ca1222521f161eafa0752dddecb31c76968929a42669174c9839b97036a2371b5d1466fe5549e53bcc7f30f7ba676950bd7a751e9e916c6525f49bf3046903ff738c5b0514ffe375ba9fe41bb766daf5973ca1d7782d84628e59b3dfa14d7c86fb3d62a219176e84e17d6fae34faa461094ae0ffd9631dd49c9138f6691a1a854') );
        equal( M4.inverse( asmCrypto.hex_to_bytes('145cc156e018b9b8b3599cb8d59a07f69af5cfcbb54f00e84f70edfec80dbab9ac2f79b96adbcbeeca6050c7b043c01db9be7c3ca5ad281f788b07e4bf08404af05addd5cc9578c4211b4df57572c2248ce1de633b806847479512bc3e7f00678b5a779d8f751ae0e2cadf3fed717cf68b846a3ad3c9eb7fe6a3b8e61c93270d2055563728e09067a7cd141459e176e2c4675a8c000ca9e0ea790e4c4c64c7175bab4e16461072fb49de139cd69b59037ba9aeae357f2b456751ecf014c103c12ed0bb6335a51f5731ff7cbeaa5c7ede12ff35d7db308d1b165ad5fe425d954e07b775cda34117260702fe7f176e50d7b34240f03b3bd7ac4a32edf0fda80455') ).toString(16), '11', "M4 inverse OK" );
    });

    test( "asmCrypto.Modulus.power", function () {
        var base = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('3f70f29d3f3ae354a6d2536ceafba83cfc787cd91e7acd2b6bde05e62beb8295ae18e3f786726f8d034bbc15bf8331df959f59d431736d5f306aaba63dacec279484e39d76db9b527738072af15730e8b9956a64e8e4dbe868f77d1414a8a8b8bf65380a1f008d39c5fabe1a9f8343929342ab7b4f635bdc52532d764701ff3d8072c475c012ff0c59373e8bc423928d99f58c3a6d9f6ab21ee20bc8e8818fc147db09f60c81906f2c6f73dc69725f075853a89f0cd02a30a8dd86b660ccdeffc292f398efb54088c822774445a6afde471f7dd327ef9996296898a5747726ccaeeceeb2e459df98b4128cb5ab8c7cd20c563f960a1aa770f3c81f13f967b6cc')),
            modulus = new asmCrypto.Modulus(asmCrypto.hex_to_bytes('c7f1bc1dfb1be82d244aef01228c1409c198894eca9e21430f1669b4aa3864c9f37f3d51b2b4ba1ab9e80f59d267fda1521e88b05117993175e004543c6e3611242f24432ce8efa3b81f0ff660b4f91c5d52f2511a6f38181a7bf9abeef72db056508bbb4eeb5f65f161dd2d5b439655d2ae7081fcc62fdcb281520911d96700c85cdaf12e7d1f15b55ade867240722425198d4ce39019550c4c8a921fc231d3e94297688c2d77cd68ee8fdeda38b7f9a274701fef23b4eaa6c1a9c15b2d77f37634930386fc20ec291be95aed9956801e1c76601b09c413ad915ff03bfdc0b6b233686ae59e8caf11750b509ab4e57ee09202239baee3d6e392d1640185e1cd')),
            exponent = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('322e393f76a1c22b147e7d193c00c023afb7c1500b006ff1bc1cc8d391fc38bd'));

        equal( modulus.power( base, exponent ).toString(16), '5b3823974b3eda87286d3f38499de290bd575d8b02f06720acacf3d50950f9ca0ff6b749f3be03913ddca0b291e0b263bdab6c9cb97e4ab47ee9c235ff20931a8ca358726fab93614e2c549594f5c50b1c979b34f840b6d4fc51d6feb2dd072995421d17862cb405e040fc1ed662a3245a1f97bbafa6d1f7f76c7db6a802e3037acdf01ab5053f5da518d6753477193b9c25e1720519dcb9e2f6e70d5786656d356151845a49861dfc40187eff0e85cd18b1f3f3b97c476472edfa090b868b2388edfffecc521c20df8cebb8aacfb3669b020330dd6ea64b2a3067a972b8f249bccc19347eff43893e916f0949bd5789a5cce0f8b7cd87cece909d679345c0d4', "Modulus.power ok" );
    });

    test( "asmCrypto.isProbablePrime", function () {
        var p = new asmCrypto.BigNumber(asmCrypto.hex_to_bytes('8844ae66464b4b7db53644be87617124f314a1d8243d347867c8cfd6afb595bdb88ce63538fbd6c3f8461133d77ed4f5ef403f48c65b7340c683839c00bc7874bff3e9ffe7916a3ca085c7096f31871f2d628198f9c1deaeaefa581ebaef834a89afdf663b9570287a257bd6e4f507cede3b31eda6bd7fd4f8ae3c5b8791d89f'));
        ok( p.isProbablePrime(), "p is probable prime" );
    });
}
else
{
    skip( "asmCrypto.BigNumber" );
}
