module("AES");

///////////////////////////////////////////////////////////////////////////////

var cbc_aes_vectors = [
    [   // key
        [ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c ],
        // iv
        [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f ],
        // clear text
        [ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
          0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 ],
        // cipher text
        [ 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
          0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
          0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
          0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 ]
    ],
];

test( "asmCrypto.AES_CBC.encrypt / asmCrypto.AES_CBC.decrypt", function () {
    for ( var i = 0; i < cbc_aes_vectors.length; ++i ) {
        var key = new Uint8Array( cbc_aes_vectors[i][0] ),
            iv = new Uint8Array( cbc_aes_vectors[i][1] ),
            clear = new Uint8Array( cbc_aes_vectors[i][2] ),
            cipher = new Uint8Array( cbc_aes_vectors[i][3] );

        equal(
            asmCrypto.bytes_to_hex( asmCrypto.AES_CBC.encrypt( clear, key, false, iv ) ),
            asmCrypto.bytes_to_hex(cipher),
            "encrypt vector " + i
        );

        equal(
            asmCrypto.bytes_to_hex( asmCrypto.AES_CBC.decrypt( cipher, key, false, iv ) ),
            asmCrypto.bytes_to_hex(clear),
            "encrypt vector " + i
        );
    }
});

var ccm_aes_vectors = [
    [
        // key
        [ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf ],
        // nonce
        [ 0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 ],
        // adata
        [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 ],
        // tagSize
        8,
        // input message
        [ 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
          0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e ],
        // encrypted message
        [ 0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2, 0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
          0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84, 0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0 ]
    ],
    [
        // key
        [ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf ],
        // nonce
        [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
        // adata
        [ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x61, 0x75, 0x74, 0x68, 0x69, 0x6e, 0x66, 0x6f, 0x6f ],
        // tagSize
        16,
        // input message
        asmCrypto.hex_to_bytes('44696420796f75206b6e6f772e2e2e0d0a46726f6d2057696b6970656469612773206e657720616e6420726563656e746c7920696d70726f76656420636f6e74656e743a0d0a5361696e74204c656f6e61726420436174686f6c69632043687572636820284d616469736f6e2c204e65627261736b61290d0a2e2e2e207468617420746865204a61636f62204d2e204e616368746967616c6c2d64657369676e65642053742e204c656f6e61726420436174686f6c696320436875726368202870696374757265642920696e204d616469736f6e2c204e65627261736b612c20636f6e7461696e73206120626f6e652072656c6963206f6620697473206e616d6573616b653f0d0a2e2e2e2074686174207468652043616e61646196536f757468204b6f72656120467265652054726164652041677265656d656e742077696c6c20656c696d696e61746520393825206f6620616c6c20696d706f72742074617269666673206265747765656e207468652074776f20636f756e74726965733f0d0a2e2e2e207468617420526f7373204d634577616e2c2043454f206f66205242532047726f75702c206f6e63652074686520776f726c642773206c6172676573742062616e6b2c207477696365206661696c656420616e206163636f756e74616e6379206578616d3f0d0a2e2e2e2074686174205475726b69736820776f6d656e2773206e6174696f6e616c2069636520686f636b657920706c617965722047697a656d20d67a74617364656c656e2069732061206d656d626572206f662068657220666174686572277320636c7562204d696c656e79756d20506174656e20534b3f0d0a2e2e2e207468617420566572697a6f6e20762e204643432028323031342920776173207265706f7274656420746f20626520746865206465617468206f66206e6574776f726b206e65757472616c6974792c20686176696e6720766163617465642074776f206f662074686520464343204f70656e20496e7465726e6574204f726465722032303130277320746872656520726567756c6174696f6e733f0d0a2e2e2e207468617420746865206d6f737320737065636965732043686f7269736f646f6e7469756d206163697068796c6c756d2063616e207375727669766520666f72206d6f7265207468616e20312c3530302079656172732066726f7a656e3f'),
        // encrypted message
        asmCrypto.hex_to_bytes('09e3c1f3ba2f40eeca4dd7c27453085c71727d4b452a388dbdafc48a7f1406184b5516ea59d9ece55f347237b440792a4e71d26ee6df2dfcd39aea379080082a67be4d7c1af810181379d3f3a444512468e43494a41e9f968c6fe13f45027a297cc24ba3113a5e1b575fa3e1246004d75264e0960052d4e14b4e1a46b24f644428ef4ad4c50455e7029fa53b4eadbe5934c234043f23296b1c235bc8ffadd28deea7415b4bfd996071179cb361822894ab54078b5ad139a7dea6889a36d1417cbbbb1eb9afa0de88d736bf81e5140df06988f2901c275f63fed880fb6a00e7ebd0d5394360ca67b0680d64cc4ba5f7c69298a265916dc4ef03bb54b5e59c0cc48f83b20cf6ec1180b2423966e78ffd94ad1b74dc6b314802ddea17036d507f44c289effd820cb43d0daac09d3ee20ee41cff1e3f2858dc2643e13fcc481d4b1d36ada547e05f789f0d1067c73949c522fd54dc0240c942cc250af3304173dcbab38f1c8292ce0036c8f0c20ceb3d5cc70cc02e5b07329640dc971a410959e89e24edf15d96a6d2cf81abcb994355051371983533f788c9bd01a8e640b1b733c2b34b7ddf7229cf81d3664d85e0cf14dcfb73f0701939f6929e725de6ea590dc0a4caf5fa6fdacc96590e43b94c6f221a703c1c5073509e6b0700eeafde7ee99e149bdbf34a5acd948a513401ba78c4db7128e1f0aac26767f8a4754ae06a41287a12a7f3059c7a405aceb105b3748264c081240c3aa3f298a0ef5f2ea93151a25a3f746082d352eb3a52fb6f860cdf0f4d2186af5e4aa744893e8a59037daa6c23d8d31d2666c528a4ce4e249a27f7aab2bf14eeb7bf8c617380a34db5b7fade8eca02f1f030a62a2ffc7f2d2b14ec366b2a4269be4c763276195ce4c95b4c77c2cc001aac54dd6496099d7ecfe1f1e316d846ab41c4ef461ae0687588ea45532fe8bf9c91cf0840200a232adaa0b8036eaf3f29e4b2d898e8fb2315c22f4915b5746c7920a0bbc98548076e8f68a2fbf3b84df590d0a3154a66d17a80a115027c066f4d5f6c69769e52268f3cea1ee86150144bc05ba63d526e611a1ef723b0b573b37eb5949dd27875208219a77d5a8f170fcecf452ea1b4c78bc135a6345c853a2621154a664806d9fbb88a61ec7935c3511aa3ede4736ee37027e5f2ef2079447886ed5a30839eee442ff8feb17acfa832a8dedb28cbb52b07a950c5dcb853a32ed2f8c0ff83adea7b060aaf2466d148ad43d8e657')
    ]
];

test( "asmCrypto.AES_CCM.encrypt / asmCrypto.AES_CCM.decrypt", function () {
    for ( var i = 0; i < ccm_aes_vectors.length; ++i ) {
        var key = new Uint8Array( ccm_aes_vectors[i][0] ),
            nonce = new Uint8Array( ccm_aes_vectors[i][1] ),
            adata = new Uint8Array( ccm_aes_vectors[i][2] ),
            tagsize = ccm_aes_vectors[i][3],
            clear = new Uint8Array( ccm_aes_vectors[i][4] ),
            cipher = new Uint8Array( ccm_aes_vectors[i][5] );

        equal(
            asmCrypto.bytes_to_hex( asmCrypto.AES_CCM.encrypt( clear, key, nonce, adata, tagsize ) ),
            asmCrypto.bytes_to_hex(cipher),
            "encrypt vector " + i
        );

        equal(
            asmCrypto.bytes_to_hex( asmCrypto.AES_CCM.decrypt( cipher, key, nonce, adata, tagsize ) ),
            asmCrypto.bytes_to_hex(clear),
            "encrypt vector " + i
        );
    }
});
