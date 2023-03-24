import * as asmCrypto from '../asmcrypto.all.es8';
import chai from 'chai';
const expect = chai.expect;
/**
 * -----BEGIN PUBLIC KEY-----
 * MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBP4lIGcE2OBqUwZPmGYUd383l
 * 7KdwAD7DVPMULg9h8GdtfUIVzHoTsG4HRKqDFsnDdmy++jCyNG+6jxI21+ZUjPh9
 * lXjmkE/EKR4Jaic3/NlmJPcudieTUF+d/F+he0RhGt1U9cAL9UNz1yDLb05cq642
 * xEQrOdv0kVhBRUf0UwIDAQAB
 * -----END PUBLIC KEY-----
 */
const pubKey = [
  asmCrypto.hex_to_bytes(
    'c13f894819c136381a94c193e619851ddfcde5eca770003ec354f3142e0f61f0676d7d4215cc7a13b06e0744aa8316c9c3766cbefa30b2346fba8f1236d7e6548cf87d9578e6904fc4291e096a2737fcd96624f72e762793505f9dfc5fa17b44611add54f5c00bf54373d720cb6f4e5cabae36c4442b39dbf49158414547f453',
    ),
    asmCrypto.hex_to_bytes('10001'),
  ];
  
  /**
   * -----BEGIN PRIVATE KEY-----
   * MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAME/iUgZwTY4GpTB
   * k+YZhR3fzeXsp3AAPsNU8xQuD2HwZ219QhXMehOwbgdEqoMWycN2bL76MLI0b7qP
   * EjbX5lSM+H2VeOaQT8QpHglqJzf82WYk9y52J5NQX538X6F7RGEa3VT1wAv1Q3PX
   * IMtvTlyrrjbERCs52/SRWEFFR/RTAgMBAAECgYAHVJeqin+PxPUNK4KmudUY2wJ+
   * dEmtr/SxiCloXI7s0ie6OYQmO4lt8cVatToamuSwa2+Ylvj96YtLcl3ogqwT/BG2
   * FMssyBvMabmtFn3aCTxcZjd1Ss0OyemEWxsiRNWXyfY9fqB2vaGf6tzbO9G6kBiR
   * X+yYFlf7ekMBy4ej4QJBAO8vjZHXzZZxDWs7XqG2ditCFO/jKefQYJq4QZdE74Yg
   * OR5CPViQyGSuuzbA2vUDXSfzQn5qhP3jZGahS1atHPsCQQDO1Ud+Csucg2w8VOMy
   * aOBkzozf1ARSyLh6uDiza0mK4i/b2zMfWfYd08oVEhQ+d6aPjyQA2+nldqAACE5v
   * y7aJAkAieIL5otVROifJ7Xt86NPs9hAYZm+ypfhWM/nX+Cpg9SHmN3up2OvYfsoi
   * YPbtWrfBOzC5EVbrVCszE0nNSxOjAkBN6io0YPyyyQ9M6u1rX/aoAucuqj+2r8ZO
   * 9Hbnn9LkbrB4sepgNRNxyQanSVg27/veuJ1ndXB28Gj1mityEduBAkAmGpNhOpPk
   * OPpihYdY0ds7Pbg2YxlRfAOaz8wM4EzQ1zSdfo2MsOigWslm0EwYyBxJAl3itQu4
   * f3j6zM0ZzYYC
   * -----END PRIVATE KEY-----
   */
  const privkey = [
  asmCrypto.hex_to_bytes(
    'c13f894819c136381a94c193e619851ddfcde5eca770003ec354f3142e0f61f0676d7d4215cc7a13b06e0744aa8316c9c3766cbefa30b2346fba8f1236d7e6548cf87d9578e6904fc4291e096a2737fcd96624f72e762793505f9dfc5fa17b44611add54f5c00bf54373d720cb6f4e5cabae36c4442b39dbf49158414547f453',
  ),
  asmCrypto.hex_to_bytes('10001'),
  asmCrypto.hex_to_bytes(
    '75497aa8a7f8fc4f50d2b82a6b9d518db027e7449adaff4b18829685c8eecd227ba3984263b896df1c55ab53a1a9ae4b06b6f9896f8fde98b4b725de882ac13fc11b614cb2cc81bcc69b9ad167dda093c5c6637754acd0ec9e9845b1b2244d597c9f63d7ea076bda19feadcdb3bd1ba9018915fec981657fb7a4301cb87a3e1',
  ),
  asmCrypto.hex_to_bytes(
    'ef2f8d91d7cd96710d6b3b5ea1b6762b4214efe329e7d0609ab8419744ef8620391e423d5890c864aebb36c0daf5035d27f3427e6a84fde36466a14b56ad1cfb',
  ),
  asmCrypto.hex_to_bytes(
    'ced5477e0acb9c836c3c54e33268e064ce8cdfd40452c8b87ab838b36b498ae22fdbdb331f59f61dd3ca1512143e77a68f8f2400dbe9e576a000084e6fcbb689',
  ),
  asmCrypto.hex_to_bytes(
    '227882f9a2d5513a27c9ed7b7ce8d3ecf61018666fb2a5f85633f9d7f82a60f521e6377ba9d8ebd87eca2260f6ed5ab7c13b30b91156eb542b331349cd4b13a3',
  ),
  asmCrypto.hex_to_bytes(
    '4dea2a3460fcb2c90f4ceaed6b5ff6a802e72eaa3fb6afc64ef476e79fd2e46eb078b1ea60351371c906a7495836effbdeb89d67757076f068f59a2b7211db81',
  ),
  asmCrypto.hex_to_bytes(
    '261a93613a93e438fa62858758d1db3b3db8366319517c039acfcc0ce04cd0d7349d7e8d8cb0e8a05ac966d04c18c81c49025de2b50bb87f78facccd19cd8602',
  ),
];

describe('RSA', () => {
  it('asmCrypto.RSA.privateKey', function() {
    const m = new asmCrypto.Modulus(new asmCrypto.BigNumber(privkey[0]));
    const e = new asmCrypto.BigNumber(privkey[1]);
    const d = new asmCrypto.BigNumber(privkey[2]);
    const p = new asmCrypto.BigNumber(privkey[3]);
    const q = new asmCrypto.BigNumber(privkey[4]);
    const dp = new asmCrypto.BigNumber(privkey[5]);
    const dq = new asmCrypto.BigNumber(privkey[6]);
    const qi = new asmCrypto.BigNumber(privkey[7]);

    expect(p.multiply(q).toString(16), 'm == p*q').to.equal(m.toString(16));
    expect(
      e
        .multiply(d)
        .divide(p.subtract(asmCrypto.BigNumber.fromNumber(1)).multiply(q.subtract(asmCrypto.BigNumber.fromNumber(1))))
        .remainder.toString(16),
      'e*d == 1 mod (p-1)(q-1)',
    ).to.equal('1');
    expect(
      d.divide(p.subtract(asmCrypto.BigNumber.fromNumber(1))).remainder.toString(16),
      'dp == d mod (p-1)',
    ).to.equal(dp.toString(16));
    expect(
      d.divide(q.subtract(asmCrypto.BigNumber.fromNumber(1))).remainder.toString(16),
      'dq == d mod (q-1)',
    ).to.equal(dq.toString(16));
    expect(
      qi
        .multiply(q)
        .divide(p)
        .remainder.toString(16),
      'qi*q == 1 mod p',
    ).to.equal('1');
    expect(m.slice(m.bitLength - 1).valueOf(), 'm highest bit is 1').to.equal(1);
  });
});

describe('RSA-OAEP', () => {
  it('asmCrypto.RSA_OAEP_SHA256 encrypt/decrypt', function() {
    const cleartext = asmCrypto.string_to_bytes('HelloWorld!');
    const rsaOaepEnc = new asmCrypto.RSA_OAEP(pubKey, new asmCrypto.Sha256(), asmCrypto.string_to_bytes('test'));
    const rsaOaepDec = new asmCrypto.RSA_OAEP(privkey, new asmCrypto.Sha256(), asmCrypto.string_to_bytes('test'));

    const ciphertext = rsaOaepEnc.encrypt(cleartext);

    const result = rsaOaepDec.decrypt(ciphertext);
    expect(asmCrypto.bytes_to_string(result), 'decrypt').to.equal('HelloWorld!');
  });
});

describe('RSA-PSS-SHA256', () => {
  it('asmCrypto.RSA_PSS_SHA256 sign/verify', function() {
    const text = 'HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!';
    const rsaPssSign = new asmCrypto.RSA_PSS(privkey, new asmCrypto.Sha256());
    const rsaPssVerify = new asmCrypto.RSA_PSS(pubKey, new asmCrypto.Sha256());

    const signature = rsaPssSign.sign(asmCrypto.string_to_bytes(text));
    rsaPssVerify.verify(signature, asmCrypto.string_to_bytes(text));
  });

  it('asmCrypto.RSA_PSS_SHA256 sign/verify with non-default salt length', function() {
    const text = 'HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!';
    const rsaPssSign = new asmCrypto.RSA_PSS(privkey, new asmCrypto.Sha256(), 32);
    const rsaPssVerify = new asmCrypto.RSA_PSS(pubKey, new asmCrypto.Sha256(), 32);

    const signature = rsaPssSign.sign(asmCrypto.string_to_bytes(text));
    rsaPssVerify.verify(signature, asmCrypto.string_to_bytes(text));
  });

  it('asmCrypto.RSA_PSS_SHA256 sign/verify with salt length mismatch', function() {
    const text = 'HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!';
    const rsaPssSign = new asmCrypto.RSA_PSS(privkey, new asmCrypto.Sha256(), 4);
    const rsaPssVerify = new asmCrypto.RSA_PSS(pubKey, new asmCrypto.Sha256(), 32);

    const signature = rsaPssSign.sign(asmCrypto.string_to_bytes(text));
    expect(() => rsaPssVerify.verify(signature, asmCrypto.string_to_bytes(text))).to.throw;
  });

  it('asmCrypto.RSA_PSS_SHA256 sign/verify with default salt length mismatch', function() {
    const text = 'HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!';
    const rsaPssSign = new asmCrypto.RSA_PSS(privkey, new asmCrypto.Sha256(), 32);
    const rsaPssVerify = new asmCrypto.RSA_PSS(pubKey, new asmCrypto.Sha256());

    const signature = rsaPssSign.sign(asmCrypto.string_to_bytes(text));
    expect(() => rsaPssVerify.verify(signature, asmCrypto.string_to_bytes(text))).to.throw;
  });

  it('asmCrypto.RSA_PSS_SHA512 sign/verify', function() {
    const text = 'HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!';
    const rsaPssSign = new asmCrypto.RSA_PSS(privkey, new asmCrypto.Sha512());
    const rsaPssVerify = new asmCrypto.RSA_PSS(pubKey, new asmCrypto.Sha512());

    const signature = rsaPssSign.sign(asmCrypto.string_to_bytes(text));
    rsaPssVerify.verify(signature, asmCrypto.string_to_bytes(text));
  });

  // This requires a RSA2048 key instead of RSA1024
  it.skip('asmCrypto.RSA_PSS_SHA512 sign/verify with non-default salt length', function() {
    const text = 'HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!HelloWorld!';
    const rsaPssSign = new asmCrypto.RSA_PSS(privkey, new asmCrypto.Sha512(), 64);
    const rsaPssVerify = new asmCrypto.RSA_PSS(pubKey, new asmCrypto.Sha512(), 64);

    const signature = rsaPssSign.sign(asmCrypto.string_to_bytes(text));
    rsaPssVerify.verify(signature, asmCrypto.string_to_bytes(text));
  });

  it('asmCrypto.RSA_PSS_SHA256 verify OpenSSL-signed-data', function() {
    const key = [
      asmCrypto.hex_to_bytes(
        'f30be5ce8941c8e6e764c78d12f3ce6e02a0dea03577bc0c16029de258321b74ceb43ea94f768aec900011c78eb247ab0e94b4477ea8f086ba7b5ce4b03c0ad7e0bf2f54ed509a536a0f179e27db539f729b38a279873f7b3a360690c8390e289dedca6da1ba232d8edc3c1eb229e1072716ddf3ef88caf4a824c152d6ad38f1',
      ),
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

    const text = 'Hello There!';

    const signature = asmCrypto.hex_to_bytes(
      'A68BE713861409B4E536C12066B3D30650C7578F9B7AB61C1A302B42ECA14D58AE11899BC55FCB838F0AE06B99381DE26CE8D6318BD59BBFC4FFF56A995E9EFB0306FF105766F508297D1E74F22648B6BD66C18E06F4748BD258358ECB5BB722AC4AFFA146C04EE7BE84AD77ED2A84B5458D6CA4A7DA4D86DAB3F2B39FD647F4',
    );

    const saltlen = 32;

    const rsaPss = new asmCrypto.RSA_PSS(key, new asmCrypto.Sha256(), saltlen);
    rsaPss.verify(signature, asmCrypto.string_to_bytes(text));
  });  
});

describe('RSA-PKCS1-v1_5', () => {
  it('asmCrypto.RSA_PKCS1-PKCS-v1_5 sign/verify SHA-1', function() {
    const message = asmCrypto.string_to_bytes('Test message for signing');
    const rsaVerify = new asmCrypto.RSA_PKCS1_v1_5(pubKey, new asmCrypto.Sha1());
    const rsaSign = new asmCrypto.RSA_PKCS1_v1_5(privkey, new asmCrypto.Sha1());

    const signature = rsaSign.sign(message);
    expect(asmCrypto.bytes_to_hex(signature), 'sign').to.equal('ab391599335aeceec710c1b397eab695607b6eca37a243467c5179cd8187577c49606f621cc8d668cd939a384260192f1763ceef1c7399a07444cdeef636b99e3107d027d9b8f5fd7bdc72b6bbcc801e8e10143afa911b074e005e4e6e2f2d18d88d24957d85312e74d69b75fe33e21d2d845b8a8bbc4ace3832169398253d9e');

    rsaVerify.verify(signature, message);
  });

  it('asmCrypto.RSA_PKCS1-PKCS-v1_5 sign/verify SHA-256', function() {
    const message = asmCrypto.string_to_bytes('Test message for signing');
    const rsaVerify = new asmCrypto.RSA_PKCS1_v1_5(pubKey, new asmCrypto.Sha256());
    const rsaSign = new asmCrypto.RSA_PKCS1_v1_5(privkey, new asmCrypto.Sha256());

    const signature = rsaSign.sign(message);
    expect(asmCrypto.bytes_to_hex(signature), 'sign').to.equal('9b7a8eed5d871d948b8c231a724cd7e1db7ed99f4ede25147026e23e9b272126d011b54956249de512bf46012c6c29aee7cb9e497e39f7ab3761daeddcc180062eb88561815e69e9db419b4e542c7920eacef275cdfe7e6cd87ef66f28f815f03d1b348ecf282f127193d048892e55e0f9ac3eff4abad72916f3c2f483bf8f4f');

    rsaVerify.verify(signature, message);
  });

  it('asmCrypto.RSA_PKCS1-PKCS-v1_5 sign/verify default SHA-256', function() {
    const message = asmCrypto.string_to_bytes('Test message for signing');
    const rsaVerify = new asmCrypto.RSA_PKCS1_v1_5(pubKey);
    const rsaSign = new asmCrypto.RSA_PKCS1_v1_5(privkey);

    const signature = rsaSign.sign(message);
    expect(asmCrypto.bytes_to_hex(signature), 'sign').to.equal('9b7a8eed5d871d948b8c231a724cd7e1db7ed99f4ede25147026e23e9b272126d011b54956249de512bf46012c6c29aee7cb9e497e39f7ab3761daeddcc180062eb88561815e69e9db419b4e542c7920eacef275cdfe7e6cd87ef66f28f815f03d1b348ecf282f127193d048892e55e0f9ac3eff4abad72916f3c2f483bf8f4f');

    rsaVerify.verify(signature, message);
  });

  it('asmCrypto.RSA_PKCS1-PKCS-v1_5 sign/verify SHA-512', function() {
    const message = asmCrypto.string_to_bytes('Test message for signing');
    const rsaVerify = new asmCrypto.RSA_PKCS1_v1_5(pubKey, new asmCrypto.Sha512());
    const rsaSign = new asmCrypto.RSA_PKCS1_v1_5(privkey, new asmCrypto.Sha512());

    const signature = rsaSign.sign(message);
    expect(asmCrypto.bytes_to_hex(signature), 'sign').to.equal('1d153a6251a28a89bb3be6451e42190dd16decce0808f01345f19d24140cec8307f0e47ce10f2b77ecb2d44ac7389e635587c007fd37f9bc4c506d3fbac4b09efc79cca273533f5e641472f4dee811cb5314cea1f51bc2a1601fb2e351a514e39bf6e16a0281b280605d25550f2c9852ae5395d4dcaa53a85678e8ad1582bb03');

    rsaVerify.verify(signature, message);
  });

  it('asmCrypto.RSA_PKCS1-PKCS-v1_5 encrypt/decrypt', function() {
    const cleartext = asmCrypto.hex_to_bytes('01435e62ad3ec4850720e34f8cab620e203749f2315b203d');
    const rsaEnc = new asmCrypto.RSA_PKCS1_v1_5(pubKey);
    const rsaDec = new asmCrypto.RSA_PKCS1_v1_5(privkey);

    const ciphertext = rsaEnc.encrypt(cleartext);

    const result = rsaDec.decrypt(ciphertext);
    expect(asmCrypto.bytes_to_hex(result), 'decrypt').to.equal('01435e62ad3ec4850720e34f8cab620e203749f2315b203d');
  });

  it('asmCrypto.RSA_PKCS1-PKCS-v1_5 decrypt vector', function() {
    const rsaDec = new asmCrypto.RSA_PKCS1_v1_5(privkey);

    const result = rsaDec.decrypt(asmCrypto.hex_to_bytes("64c7dc7bc47d95081ae4cbb6c9ba9575c92190a3b29d56829dfd162f35fcc4e28658729e4d24e3205b77143034ca0552cb8dd50e391899e33ea6f63107d050c5562b7daed4f7ba2e3bce3090d171a0a20c4777248ad78adaa29259908bacd3271365361e544ddfd1e243dceffe676e815d7def064bbaf948d1da393f55a81a10"));
    expect(asmCrypto.bytes_to_hex(result), 'decrypt').to.equal('01435e62ad3ec4850720e34f8cab620e203749f2315b203d');
  });
});
