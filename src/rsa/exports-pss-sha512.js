/**
 * RSA-PSS-SHA512 exports
 */

import { RSA_PSS } from './pkcs1';
import { get_sha512_instance } from '../hash/sha512/sha512';
import { SecurityError } from '../errors';

function rsa_pss_sha512_sign_bytes(data, key, slen) {
  if (data === undefined) throw new SyntaxError('data required');
  if (key === undefined) throw new SyntaxError('key required');
  return new RSA_PSS({ hash: get_sha512_instance(), key: key, saltLength: slen }).sign(data).result;
}

function rsa_pss_sha512_verify_bytes(signature, data, key, slen) {
  if (signature === undefined) throw new SyntaxError('signature required');
  if (data === undefined) throw new SyntaxError('data required');
  if (key === undefined) throw new SyntaxError('key required');
  try {
    new RSA_PSS({ hash: get_sha512_instance(), key: key, saltLength: slen }).verify(signature, data);
    return true;
  } catch (e) {
    if (!(e instanceof SecurityError)) throw e;
  }
  return false;
}

export var RSA_PSS_SHA512 = {
  sign: rsa_pss_sha512_sign_bytes,
  verify: rsa_pss_sha512_verify_bytes,
};
