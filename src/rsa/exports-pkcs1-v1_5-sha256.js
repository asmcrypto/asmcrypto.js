/**
 * RSA-PKCS1-v1_5-SHA256 exports
 */

function rsa_pkcs1_v1_5_sha256_sign_bytes(data, key) {
  if (data === undefined) throw new SyntaxError('data required');
  if (key === undefined) throw new SyntaxError('key required');
  return new RSA_PKCS1_v1_5({ hash: get_sha256_instance(), key: key }).sign(data).result;
}

function rsa_pkcs1_v1_5_sha256_verify_bytes(signature, data, key) {
  if (signature === undefined) throw new SyntaxError('signature required');
  if (data === undefined) throw new SyntaxError('data required');
  if (key === undefined) throw new SyntaxError('key required');
  try {
    new RSA_PKCS1_v1_5({ hash: get_sha256_instance(), key: key }).verify(signature, data);
    return true;
  } catch (e) {
    if (!(e instanceof SecurityError)) throw e;
  }
  return false;
}

exports.RSA_PKCS1_v1_5 = RSA_PKCS1_v1_5;

exports.RSA_PKCS1_v1_5_SHA256 = {
  sign: rsa_pkcs1_v1_5_sha256_sign_bytes,
  verify: rsa_pkcs1_v1_5_sha256_verify_bytes,
};
