import * as asmCrypto from '../asmcrypto.all.es8';
import chai from 'chai';
const expect = chai.expect;

describe('SHA256', () => {
  const sha256_vectors = [
    ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', asmCrypto.string_to_bytes('')],
    ['ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', asmCrypto.string_to_bytes('abc')],
    ['f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650', asmCrypto.string_to_bytes('message digest')],
    [
      'f30ceb2bb2829e79e4ca9753d35a8ecc00262d164cc077080295381cbd643f0d',
      asmCrypto.string_to_bytes('secure hash algorithm'),
    ],
    [
      '6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630',
      asmCrypto.string_to_bytes('SHA256 is considered to be safe'),
    ],
    [
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
      asmCrypto.string_to_bytes('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
    ],
    [
      'f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342',
      asmCrypto.string_to_bytes('For this sample, this 63-byte string will be used as input data'),
    ],
    [
      'ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8',
      asmCrypto.string_to_bytes('This is exactly 64 bytes long, not counting the terminating byte'),
    ],
  ];

  it('asmCrypto.SHA256.hex', function() {
    for (let i = 0; i < sha256_vectors.length; ++i) {
      const sha256 = new asmCrypto.Sha256();
      expect(asmCrypto.bytes_to_hex(sha256.process(sha256_vectors[i][1]).finish().result), 'vector ' + i).to.equal(
        sha256_vectors[i][0],
      );
    }
  });
});
describe('HMAC-SHA256', () => {
  const hmac_sha256_vectors = [
    [
      'b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad',
      asmCrypto.string_to_bytes(''),
      asmCrypto.string_to_bytes(''),
    ],
    [
      'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8',
      asmCrypto.string_to_bytes('key'),
      asmCrypto.string_to_bytes('The quick brown fox jumps over the lazy dog'),
    ],
    [
      'b54d57e9b21940b6496b58d5ac120eda9f1637788b5df058928637f2eca40cd9',
      asmCrypto.string_to_bytes('MyVeeeeeeeeeeeeeryVeeeeeeeeeeeeeryVeeeeeeeeeeeeeryLoooooooooongPassword'),
      asmCrypto.string_to_bytes('Lorem ipsum dolor sit amet, consectetur adipiscing elit.'),
    ],
  ];

  it('asmCrypto.HMAC_SHA256.hex', function() {
    for (let i = 0; i < hmac_sha256_vectors.length; ++i) {
      const hmacSha256 = new asmCrypto.HmacSha256(hmac_sha256_vectors[i][1]);
      expect(
        asmCrypto.bytes_to_hex(hmacSha256.process(hmac_sha256_vectors[i][2]).finish().result),
        'vector ' + i,
      ).to.equal(hmac_sha256_vectors[i][0]);
    }
  });
});
describe('PBKDF2-HMAC-SHA256', () => {
  const pbkdf2_hmac_sha256_vectors = [
    [
      '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b',
      asmCrypto.string_to_bytes('password'),
      asmCrypto.string_to_bytes('salt'),
      1,
      32,
    ],
    [
      'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43',
      asmCrypto.string_to_bytes('password'),
      asmCrypto.string_to_bytes('salt'),
      2,
      32,
    ],
    [
      'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a',
      asmCrypto.string_to_bytes('password'),
      asmCrypto.string_to_bytes('salt'),
      4096,
      32,
    ],
    [
      '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9',
      asmCrypto.string_to_bytes('passwordPASSWORDpassword'),
      asmCrypto.string_to_bytes('saltSALTsaltSALTsaltSALTsaltSALTsalt'),
      4096,
      40,
    ],
    [
      '89b69d0516f829893c696226650a8687',
      asmCrypto.string_to_bytes('pass\0word'),
      asmCrypto.string_to_bytes('sa\0lt'),
      4096,
      16,
    ],
    [
      'cdc8b1780ca68aba97f1f729c9d281719702eb4b308d7d87409817e60188be0d',
      asmCrypto.string_to_bytes('MyVeeeeeeeeeeeeeryVeeeeeeeeeeeeeryVeeeeeeeeeeeeeryLoooooooooongPassword'),
      asmCrypto.string_to_bytes('MyVeeeeeeeeeeeeeryVeeeeeeeeeeeeeryVeeeeeeeeeeeeeryLoooooooooongPassword'),
      4096,
      32,
    ],
  ];

  it('asmCrypto.PBKDF2_HMAC_SHA256.hex', function() {
    for (let i = 0; i < pbkdf2_hmac_sha256_vectors.length; ++i) {
      expect(
        // got
        asmCrypto.bytes_to_hex(asmCrypto.Pbkdf2HmacSha256(
          pbkdf2_hmac_sha256_vectors[i][1], // password
          pbkdf2_hmac_sha256_vectors[i][2], // salt
          pbkdf2_hmac_sha256_vectors[i][3], // count
          pbkdf2_hmac_sha256_vectors[i][4], // dklen
        )),
        "asmCrypto.PBKDF2_HMAC_SHA256.hex('" +
          pbkdf2_hmac_sha256_vectors[i][1] +
          "', '" +
          pbkdf2_hmac_sha256_vectors[i][2] +
          "', '" +
          pbkdf2_hmac_sha256_vectors[i][3] +
          "', '" +
          pbkdf2_hmac_sha256_vectors[i][4] +
          "') is equal to '" +
          pbkdf2_hmac_sha256_vectors[i][0] +
          "'",
      ).to.equal(pbkdf2_hmac_sha256_vectors[i][0]);
    }
  });
});
