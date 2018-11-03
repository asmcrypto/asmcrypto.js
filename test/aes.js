import * as asmCrypto from '../asmcrypto.all.es8';
import chai from 'chai';
const expect = chai.expect;

describe('AES', () => {
  describe('ECB', () => {
    const ecb_aes_vectors = [
      // AES-ECB-128
      [
        '2b7e151628aed2a6abf7158809cf4f3c', // key
        '6bc1bee22e409f96e93d7e117393172a', // clear text
        '3ad77bb40d7a3660a89ecaf32466ef97', // cipher text
      ],
      [
        '2b7e151628aed2a6abf7158809cf4f3c', // key
        'ae2d8a571e03ac9c9eb76fac45af8e51', // clear text
        'f5d3d58503b9699de785895a96fdbaaf', // cipher text
      ],
      [
        '2b7e151628aed2a6abf7158809cf4f3c', // key
        '30c81c46a35ce411e5fbc1191a0a52ef', // clear text
        '43b1cd7f598ece23881b00e3ed030688', // cipher text
      ],
      [
        '2b7e151628aed2a6abf7158809cf4f3c', // key
        'f69f2445df4f9b17ad2b417be66c3710', // clear text
        '7b0c785e27e8ad3f8223207104725dd4', // cipher text
      ],
      [
        // Two blocks
        '2b7e151628aed2a6abf7158809cf4f3c', // key
        'f69f2445df4f9b17ad2b417be66c3710f69f2445df4f9b17ad2b417be66c3710', // clear text
        '7b0c785e27e8ad3f8223207104725dd47b0c785e27e8ad3f8223207104725dd4', // cipher text
      ],
      // AES-ECB-256
      [
        '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', // key
        '6bc1bee22e409f96e93d7e117393172a', // clear text
        'f3eed1bdb5d2a03c064b5a7e3db181f8', // cipher text
      ],
      [
        '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', // key
        'ae2d8a571e03ac9c9eb76fac45af8e51', // clear text
        '591ccb10d410ed26dc5ba74a31362870', // cipher text
      ],
      [
        '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', // key
        '30c81c46a35ce411e5fbc1191a0a52ef', // clear text
        'b6ed21b99ca6f4f9f153e7b1beafed1d', // cipher text
      ],
      [
        // Two blocks
        '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', // key
        '30c81c46a35ce411e5fbc1191a0a52ef30c81c46a35ce411e5fbc1191a0a52ef', // clear text
        'b6ed21b99ca6f4f9f153e7b1beafed1db6ed21b99ca6f4f9f153e7b1beafed1d', // cipher text
      ],
      [
        '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', // key
        'f69f2445df4f9b17ad2b417be66c3710', // clear text
        '23304b7a39f9f3ff067d8d8f9e24ecc7', // cipher text
      ],
    ];

    it('asmCrypto.AES_ECB.encrypt / asmCrypto.AES_ECB.decrypt', function () {
      for (let i = 0; i < ecb_aes_vectors.length; ++i) {
        const key = new Uint8Array(asmCrypto.hex_to_bytes(ecb_aes_vectors[i][0]));
        const clear = new Uint8Array(asmCrypto.hex_to_bytes(ecb_aes_vectors[i][1]));
        const cipher = new Uint8Array(asmCrypto.hex_to_bytes(ecb_aes_vectors[i][2]));

        expect(asmCrypto.AES_ECB.encrypt(clear, key), `encrypt vector ${i}`).to.deep.equal(cipher);

        expect(asmCrypto.AES_ECB.decrypt(cipher, key), `decrypt vector ${i}`).to.deep.equal(clear);
      }
    });
  });

  describe('CBC', () => {
    const cbc_aes_vectors = [
      [   // key
        [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
        // iv
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        // clear text
        [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
          0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        // cipher text
        [0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
          0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
          0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
          0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7]
      ],
      [   // key
        [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
          0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
        // iv
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        // clear text
        [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
          0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        // cipher text
        [0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
          0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
          0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
          0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b]
      ]
    ];

    it('asmCrypto.AES_CBC.encrypt / asmCrypto.AES_CBC.decrypt', function () {
      for (let i = 0; i < cbc_aes_vectors.length; ++i) {
        const key = new Uint8Array(cbc_aes_vectors[i][0]);
        const iv = new Uint8Array(cbc_aes_vectors[i][1]);
        const clear = new Uint8Array(cbc_aes_vectors[i][2]);
        const cipher = new Uint8Array(cbc_aes_vectors[i][3]);

        expect(asmCrypto.bytes_to_hex(asmCrypto.AES_CBC.encrypt(clear, key, false, iv)), `encrypt vector ${i}`).to.be.equal(asmCrypto.bytes_to_hex(cipher));

        expect(asmCrypto.bytes_to_hex(asmCrypto.AES_CBC.decrypt(cipher, key, false, iv)), `decrypt vector ${i}`).to.be.equal(asmCrypto.bytes_to_hex(clear));
      }
    });
  });

  const ctr_aes_vectors = [
    [
      // key
      asmCrypto.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
      // nonce
      asmCrypto.hex_to_bytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
      // input message
      asmCrypto.hex_to_bytes('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'),
      // encrypted message
      asmCrypto.hex_to_bytes('874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee')
    ],
    [
      // key
      asmCrypto.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
      // nonce
      asmCrypto.hex_to_bytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
      // input message
      asmCrypto.hex_to_bytes('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c'),
      // encrypted message
      asmCrypto.hex_to_bytes('874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f300')
    ],
    [
      // key
      asmCrypto.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
      // nonce
      asmCrypto.hex_to_bytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
      // input message
      asmCrypto.hex_to_bytes('6bc1bee22e409f96e93d7e11739317'),
      // encrypted message
      asmCrypto.hex_to_bytes('874d6191b620e3261bef6864990db6')
    ],
    [
      // key
      asmCrypto.hex_to_bytes('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'),
      // nonce
      asmCrypto.hex_to_bytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
      // input message
      asmCrypto.hex_to_bytes('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'),
      // encrypted message
      asmCrypto.hex_to_bytes('601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6')
    ]
  ];
  describe('CTR', () => {
    it('asmCrypto.AES_CTR.encrypt / asmCrypto.AES_CTR.decrypt', function () {
      for (let i = 0; i < ctr_aes_vectors.length; ++i) {
        const key = new Uint8Array(ctr_aes_vectors[i][0]);
        const nonce = new Uint8Array(ctr_aes_vectors[i][1]);
        const clear = new Uint8Array(ctr_aes_vectors[i][2]);
        const cipher = new Uint8Array(ctr_aes_vectors[i][3]);

        expect(asmCrypto.bytes_to_hex(asmCrypto.AES_CTR.encrypt(clear, key, nonce)), `encrypt vector ${i}`).to.be.equal(asmCrypto.bytes_to_hex(cipher));

        expect(asmCrypto.bytes_to_hex(asmCrypto.AES_CTR.decrypt(cipher, key, nonce)), `decrypt vector ${i}`).to.be.equal(asmCrypto.bytes_to_hex(clear));
      }
    });
  });
  const gcm_aes_vectors = [
    [
      // key
      asmCrypto.hex_to_bytes('00000000000000000000000000000000'),
      // nonce
      asmCrypto.hex_to_bytes('000000000000000000000000'),
      // adata
      undefined,
      // tagSize
      16,
      // input message
      asmCrypto.string_to_bytes(''),
      // encrypted message
      asmCrypto.hex_to_bytes('58e2fccefa7e3061367f1d57a4e7455a')
    ],
    [
      // key
      asmCrypto.hex_to_bytes('00000000000000000000000000000000'),
      // nonce
      asmCrypto.hex_to_bytes('000000000000000000000000'),
      // adata
      asmCrypto.string_to_bytes(''),
      // tagSize
      16,
      // input message
      asmCrypto.hex_to_bytes('00000000000000000000000000000000'),
      // encrypted message
      asmCrypto.hex_to_bytes('0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf')
    ],
    [
      // key
      asmCrypto.hex_to_bytes('feffe9928665731c6d6a8f9467308308'),
      // nonce
      asmCrypto.hex_to_bytes('cafebabefacedbaddecaf888'),
      // adata
      asmCrypto.string_to_bytes(''),
      // tagSize
      16,
      // input message
      asmCrypto.hex_to_bytes('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'),
      // encrypted message
      asmCrypto.hex_to_bytes('42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4')
    ],
    [
      // key
      asmCrypto.hex_to_bytes('feffe9928665731c6d6a8f9467308308'),
      // nonce
      asmCrypto.hex_to_bytes('cafebabefacedbaddecaf888'),
      // adata
      asmCrypto.hex_to_bytes('feedfacedeadbeeffeedfacedeadbeefabaddad2'),
      // tagSize
      16,
      // input message
      asmCrypto.hex_to_bytes('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'),
      // encrypted message
      asmCrypto.hex_to_bytes('42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47')
    ],
    [
      // key
      asmCrypto.hex_to_bytes('feffe9928665731c6d6a8f9467308308'),
      // nonce
      asmCrypto.hex_to_bytes('cafebabefacedbad'),
      // adata
      asmCrypto.hex_to_bytes('feedfacedeadbeeffeedfacedeadbeefabaddad2'),
      // tagSize
      16,
      // input message
      asmCrypto.hex_to_bytes('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'),
      // encrypted message
      asmCrypto.hex_to_bytes('61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f45983612d2e79e3b0785561be14aaca2fccb')
    ],
    [
      // key
      asmCrypto.hex_to_bytes('feffe9928665731c6d6a8f9467308308'),
      // nonce
      asmCrypto.hex_to_bytes('9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b'),
      // adata
      asmCrypto.hex_to_bytes('feedfacedeadbeeffeedfacedeadbeefabaddad2'),
      // tagSize
      16,
      // input message
      asmCrypto.hex_to_bytes('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'),
      // encrypted message
      asmCrypto.hex_to_bytes('8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5619cc5aefffe0bfa462af43c1699d050')
    ],
    [
      // key
      asmCrypto.hex_to_bytes('0000000000000000000000000000000000000000000000000000000000000000'),
      // nonce
      asmCrypto.hex_to_bytes('000000000000000000000000'),
      // adata
      asmCrypto.string_to_bytes(''),
      // tagSize
      16,
      // input message
      asmCrypto.hex_to_bytes('00000000000000000000000000000000'),
      // encrypted message
      asmCrypto.hex_to_bytes('cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919')
    ],
    [
      // key
      asmCrypto.hex_to_bytes('0000000000000000000000000000000000000000000000000000000000000000'),
      // nonce
      asmCrypto.hex_to_bytes('000000000000000000000000'),
      // adata
      asmCrypto.string_to_bytes(''),
      // tagSize
      16,
      // input message
      asmCrypto.hex_to_bytes(''),
      // encrypted message
      asmCrypto.hex_to_bytes('530f8afbc74536b9a963b4f1c4cb738b')
    ],
    [
      // key
      asmCrypto.hex_to_bytes('0000000000000000000000000000000000000000000000000000000000000000'),
      // nonce
      asmCrypto.hex_to_bytes('000000000000000000000000'),
      // adata
      asmCrypto.string_to_bytes(''),
      // tagSize
      16,
      // input message
      asmCrypto.string_to_bytes(''),
      // encrypted message
      asmCrypto.hex_to_bytes('530f8afbc74536b9a963b4f1c4cb738b')
    ],
    [
      // key
      asmCrypto.hex_to_bytes('0000000000000000000000000000000000000000000000000000000000000000'),
      // nonce
      asmCrypto.hex_to_bytes('000000000000000000000000'),
      // adata
      asmCrypto.string_to_bytes(''),
      // tagSize
      16,
      // input message
      asmCrypto.hex_to_bytes('00000000000000000000000000000000'),
      // encrypted message
      asmCrypto.hex_to_bytes('cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919')
    ],
    [
      // key
      asmCrypto.hex_to_bytes('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308'),
      // nonce
      asmCrypto.hex_to_bytes('9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b'),
      // adata
      asmCrypto.hex_to_bytes('feedfacedeadbeeffeedfacedeadbeefabaddad2'),
      // tagSize
      16,
      // input message
      asmCrypto.hex_to_bytes('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'),
      // encrypted message
      asmCrypto.hex_to_bytes('5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3fa44a8266ee1c8eb0c8b5d4cf5ae9f19a')
    ],
    [ // Test case for issue #70 (https://github.com/vibornoff/asmcrypto.js/issues/70)
      // key
      asmCrypto.hex_to_bytes('00000000000000000000000000000000'),
      // nonce
      asmCrypto.hex_to_bytes('00'),
      // adata
      asmCrypto.string_to_bytes(''),
      // tagSize
      16,
      // input message
      asmCrypto.hex_to_bytes('00'),
      // encrypted message
      asmCrypto.hex_to_bytes('e9d60634580263ebab909efa6623dafc61')
    ],
    [ // Test case for issue #70 (https://github.com/vibornoff/asmcrypto.js/issues/92)
      // key
      asmCrypto.base64_to_bytes('dGQhii+B7+eLLHRiOA690w=='),
      // nonce
      asmCrypto.base64_to_bytes('R8q1njARXS7urWv3'),
      // adata
      undefined,
      // tagSize
      16,
      // input message
      asmCrypto.base64_to_bytes('dGQhwoovwoHDr8OnwossdGI4DsK9w5M='),
      // encrypted message
      asmCrypto.base64_to_bytes('L3zqVYAOsRk7zMg2KsNTVShcad8TjIQ7umfsvia21QO0XTj8vaeR')
    ],
  ];
  describe('GCM', () => {
    it("asmCrypto.AES_GCM.encrypt", function () {
      for (let i = 0; i < gcm_aes_vectors.length; ++i) {
        const key = gcm_aes_vectors[i][0];
        const nonce = gcm_aes_vectors[i][1];
        const adata = gcm_aes_vectors[i][2];
        const tagsize = gcm_aes_vectors[i][3];
        const cleartext = gcm_aes_vectors[i][4];
        const ciphertext = gcm_aes_vectors[i][5];

        expect(asmCrypto.bytes_to_hex(asmCrypto.AES_GCM.encrypt(cleartext, key, nonce, adata, tagsize)), 'encrypt vector ' + i).to.be.equal(asmCrypto.bytes_to_hex(ciphertext));

        expect(asmCrypto.bytes_to_hex(asmCrypto.AES_GCM.decrypt(ciphertext, key, nonce, adata, tagsize)), 'decrypt vector ' + i).to.be.equal(asmCrypto.bytes_to_hex(cleartext));
      }
    });
  });

  describe('CFB', () => {
    const cfb_aes_vectors = [
      [   // key
        [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
        // iv
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        // clear text
        [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
          0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        // cipher text
        [0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
          0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f, 0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b,
          0x26, 0x75, 0x1f, 0x67, 0xa3, 0xcb, 0xb1, 0x40, 0xb1, 0x80, 0x8c, 0xf1, 0x87, 0xa4, 0xf4, 0xdf,
          0xc0, 0x4b, 0x05, 0x35, 0x7c, 0x5d, 0x1c, 0x0e, 0xea, 0xc4, 0xc6, 0x6f, 0x9f, 0xf7, 0xf2, 0xe6]
      ],
      [   // key
        [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
        // iv
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        // clear text
        [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
          0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41],
        // cipher text
        [0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
          0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f, 0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b,
          0x26, 0x75, 0x1f, 0x67, 0xa3, 0xcb, 0xb1, 0x40, 0xb1, 0x80, 0x8c, 0xf1, 0x87, 0xa4, 0xf4, 0xdf,
          0xc0, 0x4b, 0x05, 0x35, 0x7c, 0x5d, 0x1c, 0x0e, 0xea, 0xc4, 0xc6]
      ],
      [   // key
        [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
          0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
        // iv
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        // clear text
        [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
          0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
        // cipher text
        [0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b, 0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
          0x39, 0xff, 0xed, 0x14, 0x3b, 0x28, 0xb1, 0xc8, 0x32, 0x11, 0x3c, 0x63, 0x31, 0xe5, 0x40, 0x7b,
          0xdf, 0x10, 0x13, 0x24, 0x15, 0xe5, 0x4b, 0x92, 0xa1, 0x3e, 0xd0, 0xa8, 0x26, 0x7a, 0xe2, 0xf9,
          0x75, 0xa3, 0x85, 0x74, 0x1a, 0xb9, 0xce, 0xf8, 0x20, 0x31, 0x62, 0x3d, 0x55, 0xb1, 0xe4, 0x71]
      ],
      [   // key
        [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
          0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
        // iv
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
        // clear text
        [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
          0xf6, 0x9f, 0x24],
        // cipher text
        [0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b, 0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
          0x39, 0xff, 0xed, 0x14, 0x3b, 0x28, 0xb1, 0xc8, 0x32, 0x11, 0x3c, 0x63, 0x31, 0xe5, 0x40, 0x7b,
          0xdf, 0x10, 0x13, 0x24, 0x15, 0xe5, 0x4b, 0x92, 0xa1, 0x3e, 0xd0, 0xa8, 0x26, 0x7a, 0xe2, 0xf9,
          0x75, 0xa3, 0x85]
      ]
    ];

    it('asmCrypto.AES_CFB.encrypt / asmCrypto.AES_CFB.decrypt', function () {
      for (let i = 0; i < cfb_aes_vectors.length; ++i) {
        const key = new Uint8Array(cfb_aes_vectors[i][0]);
        const iv = new Uint8Array(cfb_aes_vectors[i][1]);
        const clear = new Uint8Array(cfb_aes_vectors[i][2]);
        const cipher = new Uint8Array(cfb_aes_vectors[i][3]);

        expect(asmCrypto.bytes_to_hex(asmCrypto.AES_CFB.encrypt(clear, key, iv)), `encrypt vector ${i}`).to.be.equal(asmCrypto.bytes_to_hex(cipher));

        expect(asmCrypto.bytes_to_hex(asmCrypto.AES_CFB.decrypt(cipher, key, iv)), `decrypt vector ${i}`).to.be.equal(asmCrypto.bytes_to_hex(clear));
      }
    });
  });
  describe('OFB', () => {
    // key, iv, cleartext, ciphertext
    const ofb_vectors = [
      [
        asmCrypto.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
        asmCrypto.hex_to_bytes('000102030405060708090A0B0C0D0E0F'),
        asmCrypto.hex_to_bytes('6bc1bee22e409f96e93d7e117393172a'),
        asmCrypto.hex_to_bytes('3b3fd92eb72dad20333449f8e83cfb4a'),
      ],
      [
        asmCrypto.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
        asmCrypto.hex_to_bytes('50FE67CC996D32B6DA0937E99BAFEC60'),
        asmCrypto.hex_to_bytes('ae2d8a571e03ac9c9eb76fac45af8e51'),
        asmCrypto.hex_to_bytes('7789508d16918f03f53c52dac54ed825'),
      ],
      [
        asmCrypto.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
        asmCrypto.hex_to_bytes('D9A4DADA0892239F6B8B3D7680E15674'),
        asmCrypto.hex_to_bytes('30c81c46a35ce411e5fbc1191a0a52ef'),
        asmCrypto.hex_to_bytes('9740051e9c5fecf64344f7a82260edcc'),
      ],
      [
        asmCrypto.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
        asmCrypto.hex_to_bytes('A78819583F0308E7A6BF36B1386ABF23'),
        asmCrypto.hex_to_bytes('f69f2445df4f9b17ad2b417be66c3710'),
        asmCrypto.hex_to_bytes('304c6528f659c77866a510d9c1d6ae5e'),
      ],
      [
        asmCrypto.hex_to_bytes('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'),
        asmCrypto.hex_to_bytes('000102030405060708090A0B0C0D0E0F'),
        asmCrypto.hex_to_bytes('6bc1bee22e409f96e93d7e117393172a'),
        asmCrypto.hex_to_bytes('cdc80d6fddf18cab34c25909c99a4174'),
      ],
      [
        asmCrypto.hex_to_bytes('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'),
        asmCrypto.hex_to_bytes('A609B38DF3B1133DDDFF2718BA09565E'),
        asmCrypto.hex_to_bytes('ae2d8a571e03ac9c9eb76fac45af8e51'),
        asmCrypto.hex_to_bytes('fcc28b8d4c63837c09e81700c1100401'),
      ],
      [
        asmCrypto.hex_to_bytes('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'),
        asmCrypto.hex_to_bytes('52EF01DA52602FE0975F78AC84BF8A50'),
        asmCrypto.hex_to_bytes('30c81c46a35ce411e5fbc1191a0a52ef'),
        asmCrypto.hex_to_bytes('8d9a9aeac0f6596f559c6d4daf59a5f2'),
      ],
      [
        asmCrypto.hex_to_bytes('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'),
        asmCrypto.hex_to_bytes('BD5286AC63AABD7EB067AC54B553F71D'),
        asmCrypto.hex_to_bytes('f69f2445df4f9b17ad2b417be66c3710'),
        asmCrypto.hex_to_bytes('6d9f200857ca6c3e9cac524bd9acc92a'),
      ],
      [
        asmCrypto.hex_to_bytes('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'),
        asmCrypto.hex_to_bytes('000102030405060708090A0B0C0D0E0F'),
        asmCrypto.hex_to_bytes('6bc1bee22e409f96e93d7e117393172a'),
        asmCrypto.hex_to_bytes('dc7e84bfda79164b7ecd8486985d3860'),
      ],
      [
        asmCrypto.hex_to_bytes('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'),
        asmCrypto.hex_to_bytes('B7BF3A5DF43989DD97F0FA97EBCE2F4A'),
        asmCrypto.hex_to_bytes('ae2d8a571e03ac9c9eb76fac45af8e51'),
        asmCrypto.hex_to_bytes('4febdc6740d20b3ac88f6ad82a4fb08d'),
      ],
      [
        asmCrypto.hex_to_bytes('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'),
        asmCrypto.hex_to_bytes('E1C656305ED1A7A6563805746FE03EDC'),
        asmCrypto.hex_to_bytes('30c81c46a35ce411e5fbc1191a0a52ef'),
        asmCrypto.hex_to_bytes('71ab47a086e86eedf39d1c5bba97c408'),
      ],
      [
        asmCrypto.hex_to_bytes('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'),
        asmCrypto.hex_to_bytes('41635BE625B48AFC1666DD42A09D96E7'),
        asmCrypto.hex_to_bytes('f69f2445df4f9b17ad2b417be66c3710'),
        asmCrypto.hex_to_bytes('0126141d67f37be8538f5a8be740e484'),
      ],
    ];
    
    it('asmCrypto.AES_OFB.encrypt / asmCrypto.AES_OFB.decrypt', () => {
      for (let i = 0; i < ofb_vectors.length; ++i) {
        const key = new Uint8Array(ofb_vectors[i][0]);
        const iv = new Uint8Array(ofb_vectors[i][1]);
        const clear = new Uint8Array(ofb_vectors[i][2]);
        const cipher = new Uint8Array(ofb_vectors[i][3]);

        expect(asmCrypto.bytes_to_hex(asmCrypto.AES_OFB.encrypt(clear, key, iv)), 'encrypt vector ' + i).to.be.equal(asmCrypto.bytes_to_hex(cipher));

        expect(asmCrypto.bytes_to_hex(asmCrypto.AES_OFB.decrypt(cipher, key, iv)), 'decrypt vector ' + i).to.be.equal(asmCrypto.bytes_to_hex(clear));
      }
    });
  });
  describe('CMAC', () => {
    // key, data, result
    const cmac_vectors = [
      [
        asmCrypto.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
        asmCrypto.hex_to_bytes(''),
        asmCrypto.hex_to_bytes('bb1d6929e95937287fa37d129b756746'),
      ],
      [
        asmCrypto.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
        asmCrypto.hex_to_bytes('6bc1bee22e409f96e93d7e117393172a'),
        asmCrypto.hex_to_bytes('070a16b46b4d4144f79bdd9dd04a287c'),
      ],
      [
        asmCrypto.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
        asmCrypto.hex_to_bytes('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411'),
        asmCrypto.hex_to_bytes('dfa66747de9ae63030ca32611497c827'),
      ],
      [
        asmCrypto.hex_to_bytes('2b7e151628aed2a6abf7158809cf4f3c'),
        asmCrypto.hex_to_bytes('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'),
        asmCrypto.hex_to_bytes('51f0bebf7e3b9d92fc49741779363cfe'),
      ],
    ];
    
    it('asmCrypto.AES_CMAC', function() {
      for (let i = 0; i < cmac_vectors.length; ++i) {
        const key = new Uint8Array(cmac_vectors[i][0]);
        const data = new Uint8Array(cmac_vectors[i][1]);
        const result = new Uint8Array(cmac_vectors[i][2]);

        expect(asmCrypto.bytes_to_hex(asmCrypto.AES_CMAC.bytes(data, key)), 'cmac vector ' + i).to.be.equal(asmCrypto.bytes_to_hex(result));
      }
    });
  });
  describe('CCM', () => {
    const ccm_aes_vectors = [
      [
        // key
        new Uint8Array([ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf ]),
        // nonce
        new Uint8Array([ 0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 ]),
        // adata
        new Uint8Array([ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 ]),
        // tagSize
        8,
        // input message
        new Uint8Array([ 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
          0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e ]),
        // encrypted message
        new Uint8Array([ 0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2, 0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
          0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84, 0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0 ]),
      ],
      [
        // key
        new Uint8Array([ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf ]),
        // nonce
        new Uint8Array([ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]),
        // adata
        new Uint8Array([ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x61, 0x75, 0x74, 0x68, 0x69, 0x6e, 0x66, 0x6f, 0x6f ]),
        // tagSize
        16,
        // input message
        asmCrypto.hex_to_bytes('44696420796f75206b6e6f772e2e2e0d0a46726f6d2057696b6970656469612773206e657720616e6420726563656e746c7920696d70726f76656420636f6e74656e743a0d0a5361696e74204c656f6e61726420436174686f6c69632043687572636820284d616469736f6e2c204e65627261736b61290d0a2e2e2e207468617420746865204a61636f62204d2e204e616368746967616c6c2d64657369676e65642053742e204c656f6e61726420436174686f6c696320436875726368202870696374757265642920696e204d616469736f6e2c204e65627261736b612c20636f6e7461696e73206120626f6e652072656c6963206f6620697473206e616d6573616b653f0d0a2e2e2e2074686174207468652043616e61646196536f757468204b6f72656120467265652054726164652041677265656d656e742077696c6c20656c696d696e61746520393825206f6620616c6c20696d706f72742074617269666673206265747765656e207468652074776f20636f756e74726965733f0d0a2e2e2e207468617420526f7373204d634577616e2c2043454f206f66205242532047726f75702c206f6e63652074686520776f726c642773206c6172676573742062616e6b2c207477696365206661696c656420616e206163636f756e74616e6379206578616d3f0d0a2e2e2e2074686174205475726b69736820776f6d656e2773206e6174696f6e616c2069636520686f636b657920706c617965722047697a656d20d67a74617364656c656e2069732061206d656d626572206f662068657220666174686572277320636c7562204d696c656e79756d20506174656e20534b3f0d0a2e2e2e207468617420566572697a6f6e20762e204643432028323031342920776173207265706f7274656420746f20626520746865206465617468206f66206e6574776f726b206e65757472616c6974792c20686176696e6720766163617465642074776f206f662074686520464343204f70656e20496e7465726e6574204f726465722032303130277320746872656520726567756c6174696f6e733f0d0a2e2e2e207468617420746865206d6f737320737065636965732043686f7269736f646f6e7469756d206163697068796c6c756d2063616e207375727669766520666f72206d6f7265207468616e20312c3530302079656172732066726f7a656e3f'),
        // encrypted message
        asmCrypto.hex_to_bytes('09e3c1f3ba2f40eeca4dd7c27453085c71727d4b452a388dbdafc48a7f1406184b5516ea59d9ece55f347237b440792a4e71d26ee6df2dfcd39aea379080082a67be4d7c1af810181379d3f3a444512468e43494a41e9f968c6fe13f45027a297cc24ba3113a5e1b575fa3e1246004d75264e0960052d4e14b4e1a46b24f644428ef4ad4c50455e7029fa53b4eadbe5934c234043f23296b1c235bc8ffadd28deea7415b4bfd996071179cb361822894ab54078b5ad139a7dea6889a36d1417cbbbb1eb9afa0de88d736bf81e5140df06988f2901c275f63fed880fb6a00e7ebd0d5394360ca67b0680d64cc4ba5f7c69298a265916dc4ef03bb54b5e59c0cc48f83b20cf6ec1180b2423966e78ffd94ad1b74dc6b314802ddea17036d507f44c289effd820cb43d0daac09d3ee20ee41cff1e3f2858dc2643e13fcc481d4b1d36ada547e05f789f0d1067c73949c522fd54dc0240c942cc250af3304173dcbab38f1c8292ce0036c8f0c20ceb3d5cc70cc02e5b07329640dc971a410959e89e24edf15d96a6d2cf81abcb994355051371983533f788c9bd01a8e640b1b733c2b34b7ddf7229cf81d3664d85e0cf14dcfb73f0701939f6929e725de6ea590dc0a4caf5fa6fdacc96590e43b94c6f221a703c1c5073509e6b0700eeafde7ee99e149bdbf34a5acd948a513401ba78c4db7128e1f0aac26767f8a4754ae06a41287a12a7f3059c7a405aceb105b3748264c081240c3aa3f298a0ef5f2ea93151a25a3f746082d352eb3a52fb6f860cdf0f4d2186af5e4aa744893e8a59037daa6c23d8d31d2666c528a4ce4e249a27f7aab2bf14eeb7bf8c617380a34db5b7fade8eca02f1f030a62a2ffc7f2d2b14ec366b2a4269be4c763276195ce4c95b4c77c2cc001aac54dd6496099d7ecfe1f1e316d846ab41c4ef461ae0687588ea45532fe8bf9c91cf0840200a232adaa0b8036eaf3f29e4b2d898e8fb2315c22f4915b5746c7920a0bbc98548076e8f68a2fbf3b84df590d0a3154a66d17a80a115027c066f4d5f6c69769e52268f3cea1ee86150144bc05ba63d526e611a1ef723b0b573b37eb5949dd27875208219a77d5a8f170fcecf452ea1b4c78bc135a6345c853a2621154a664806d9fbb88a61ec7935c3511aa3ede4736ee37027e5f2ef2079447886ed5a30839eee442ff8feb17acfa832a8dedb28cbb52b07a950c5dcb853a32ed2f8c0ff83adea7b060aaf2466d148ad43d8e657')
      ],
      [ // Test case for issue #92 (https://github.com/vibornoff/asmcrypto.js/issues/92#issuecomment-158269407)
        // key
        asmCrypto.base64_to_bytes('dGQhii+B7+eLLHRiOA690w=='),
        // nonce
        asmCrypto.base64_to_bytes('R8q1njARXS7urWv3'),
        // adata
        undefined,
        // tagSize
        16,
        // plaintext
        asmCrypto.base64_to_bytes('dGQhwoovwoHDr8OnwossdGI4DsK9w5M='),
        // ciphertext
        asmCrypto.base64_to_bytes('kMrwkAdqy9VuEdkUA75K2hxjjy4kyRfDXMGzg+l4CoHga1/Rh49R'),
      ],
      [ // Test case for issue #92 (https://github.com/vibornoff/asmcrypto.js/issues/92#issuecomment-158269407)
        // key
        asmCrypto.base64_to_bytes('dGQhii+B7+eLLHRiOA690w=='),
        // nonce
        asmCrypto.base64_to_bytes('R8q1njARXS7urWv3'),
        // adata
        undefined,
        // tagSize
        16,
        // plaintext
        asmCrypto.base64_to_bytes('dGQhwoovwoHDr8OnwossdGI4DsK9w5M='),
        // ciphertext
        asmCrypto.base64_to_bytes('kMrwkAdqy9VuEdkUA75K2hxjjy4kyRfDXMGzg+l4CoHga1/Rh49R'),
      ],
      [ // Test case for issue #92 (https://github.com/vibornoff/asmcrypto.js/issues/92#issuecomment-158269407)
        // key
        asmCrypto.base64_to_bytes('dGQhii+B7+eLLHRiOA690w=='),
        // nonce
        asmCrypto.base64_to_bytes('R8q1njARXS7urWv3'),
        // adata
        asmCrypto.string_to_bytes(''),
        // tagSize
        16,
        // plaintext
        asmCrypto.base64_to_bytes('dGQhwoovwoHDr8OnwossdGI4DsK9w5M='),
        // ciphertext
        asmCrypto.base64_to_bytes('kMrwkAdqy9VuEdkUA75K2hxjjy4kyRfDXMGzg+l4CoHga1/Rh49R'),
      ],
      [ // Test case for issue #92 (https://github.com/vibornoff/asmcrypto.js/issues/92#issuecomment-158269407)
        // key
        asmCrypto.base64_to_bytes('dGQhii+B7+eLLHRiOA690w=='),
        // nonce
        asmCrypto.base64_to_bytes('R8q1njARXS7urWv3'),
        // adata
        new Uint8Array(0),
        // tagSize
        16,
        // plaintext
        asmCrypto.base64_to_bytes('dGQhwoovwoHDr8OnwossdGI4DsK9w5M='),
        // ciphertext
        asmCrypto.base64_to_bytes('kMrwkAdqy9VuEdkUA75K2hxjjy4kyRfDXMGzg+l4CoHga1/Rh49R'),
      ],
      [ // Test case for issue #92 (https://github.com/vibornoff/asmcrypto.js/issues/92#issuecomment-158797782)
        // key
        asmCrypto.hex_to_bytes('0f0e0d0c0b0a09080706050403020100'),
        // nonce
        asmCrypto.hex_to_bytes('000102030405060708090a0b'),
        // adata
        undefined,
        // tagSize
        16,
        // plaintext
        asmCrypto.string_to_bytes('42'),
        // ciphertext
        asmCrypto.hex_to_bytes('28be1ac7b43d8868869b9a45d3de436cd0cc'),
      ],
    ];

    it('asmCrypto.AES_CCM.encrypt / asmCrypto.AES_CCM.decrypt', function() {
      for (let i = 0; i < ccm_aes_vectors.length; ++i) {
        const key = ccm_aes_vectors[i][0];
        const nonce = ccm_aes_vectors[i][1];
        const adata = ccm_aes_vectors[i][2];
        const tagsize = ccm_aes_vectors[i][3];
        const clear = ccm_aes_vectors[i][4];
        const cipher = ccm_aes_vectors[i][5];

        expect(asmCrypto.bytes_to_hex(asmCrypto.AES_CCM.encrypt(clear, key, nonce, adata, tagsize)), 'encrypt vector ' + i).to.be.equal(asmCrypto.bytes_to_hex(cipher));

        expect(asmCrypto.bytes_to_hex(asmCrypto.AES_CCM.decrypt(cipher, key, nonce, adata, tagsize)), 'decrypt vector ' + i).to.be.equal(asmCrypto.bytes_to_hex(clear));
      }
    });
  });
  describe('Pooling', () => {
    it('asmCrypto.AES_CTR / asmCrypto.AES_ECB', () => {
      const key = new Uint8Array(ctr_aes_vectors[2][0]);
      const nonce = new Uint8Array(ctr_aes_vectors[2][1]);
      const clear = new Uint8Array(ctr_aes_vectors[2][2]);
      const cipher = new Uint8Array(ctr_aes_vectors[2][3]);

      const ctr = new asmCrypto.AES_CTR(key, nonce);
      expect(asmCrypto.bytes_to_hex(ctr.encrypt(asmCrypto.hex_to_bytes('6bc1bee22e409f96e93d7e117393172a'))), 'first call to encrypt').to.be.equal('874d6191b620e3261bef6864990db6ce');
      const ecb = new asmCrypto.AES_ECB(key, nonce);
      const ecb2 = new asmCrypto.AES_ECB(key, nonce);
      ecb2.encrypt(clear);
      expect(asmCrypto.bytes_to_hex(ctr.encrypt(asmCrypto.hex_to_bytes('ae2d8a571e03ac9c9eb76fac45af8e51'))), 'second call to encrypt').to.be.equal('c401492f668a9bd32003a7b75215e215');
    });
    it('asmCrypto.AES_GCM / asmCrypto.AES_CCM', () => {
      // Note: GCM and CCM are currently not pooled.

      const key = gcm_aes_vectors[0][0];
      const nonce = gcm_aes_vectors[0][1];
      const adata = gcm_aes_vectors[0][2];
      const tagsize = gcm_aes_vectors[0][3];
      const cleartext = gcm_aes_vectors[0][4];
      const ciphertext = gcm_aes_vectors[0][5];

      const gcm = new asmCrypto.AES_GCM(key, nonce, adata, tagsize);
      expect(asmCrypto.bytes_to_hex(gcm.encrypt(cleartext)), 'first call to encrypt').to.be.equal(asmCrypto.bytes_to_hex(ciphertext));
      const ccm = new asmCrypto.AES_CCM(key, nonce, adata, tagsize);
      const ccm2 = new asmCrypto.AES_CCM(key, nonce, adata, tagsize);
      ccm2.encrypt(cleartext);
      expect(asmCrypto.bytes_to_hex(gcm.encrypt(cleartext)), 'second call to encrypt').to.be.equal(asmCrypto.bytes_to_hex(ciphertext));
    });
  });
});
