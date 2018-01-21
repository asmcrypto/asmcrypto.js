/**
 * HMAC-SHA512 exports
 */

import { get_hmac_sha512_instance, hmac_sha512_constructor } from './hmac-sha512';
import { bytes_to_base64, bytes_to_hex } from '../utils';

function hmac_sha512_bytes(data, password) {
  if (data === undefined) throw new SyntaxError('data required');
  if (password === undefined) throw new SyntaxError('password required');
  return get_hmac_sha512_instance()
    .reset({ password: password })
    .process(data)
    .finish().result;
}

function hmac_sha512_hex(data, password) {
  var result = hmac_sha512_bytes(data, password);
  return bytes_to_hex(result);
}

function hmac_sha512_base64(data, password) {
  var result = hmac_sha512_bytes(data, password);
  return bytes_to_base64(result);
}

export var HMAC_SHA512 = hmac_sha512_constructor;

HMAC_SHA512.bytes = hmac_sha512_bytes;
HMAC_SHA512.hex = hmac_sha512_hex;
HMAC_SHA512.base64 = hmac_sha512_base64;
