/**
 * HMAC-SHA256 exports
 */

import { get_hmac_sha256_instance, hmac_sha256_constructor } from './hmac-sha256';
import { bytes_to_base64, bytes_to_hex } from '../utils';

function hmac_sha256_bytes(data, password) {
  if (data === undefined) throw new SyntaxError('data required');
  if (password === undefined) throw new SyntaxError('password required');
  return get_hmac_sha256_instance()
    .reset({ password: password })
    .process(data)
    .finish().result;
}

function hmac_sha256_hex(data, password) {
  var result = hmac_sha256_bytes(data, password);
  return bytes_to_hex(result);
}

function hmac_sha256_base64(data, password) {
  var result = hmac_sha256_bytes(data, password);
  return bytes_to_base64(result);
}

export var HMAC_SHA256 = hmac_sha256_constructor;

HMAC_SHA256.bytes = hmac_sha256_bytes;
HMAC_SHA256.hex = hmac_sha256_hex;
HMAC_SHA256.base64 = hmac_sha256_base64;
