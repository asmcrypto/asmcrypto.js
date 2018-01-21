/**
 * HMAC-SHA1 exports
 */

import { get_hmac_sha1_instance, hmac_sha1_constructor } from './hmac-sha1';
import { bytes_to_base64, bytes_to_hex } from '../utils';

function hmac_sha1_bytes(data, password) {
  if (data === undefined) throw new SyntaxError('data required');
  if (password === undefined) throw new SyntaxError('password required');
  return get_hmac_sha1_instance()
    .reset({ password: password })
    .process(data)
    .finish().result;
}

function hmac_sha1_hex(data, password) {
  var result = hmac_sha1_bytes(data, password);
  return bytes_to_hex(result);
}

function hmac_sha1_base64(data, password) {
  var result = hmac_sha1_bytes(data, password);
  return bytes_to_base64(result);
}

export var HMAC_SHA1 = hmac_sha1_constructor;

HMAC_SHA1.bytes = hmac_sha1_bytes;
HMAC_SHA1.hex = hmac_sha1_hex;
HMAC_SHA1.base64 = hmac_sha1_base64;
