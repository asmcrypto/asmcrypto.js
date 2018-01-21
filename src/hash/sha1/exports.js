/**
 * SHA1 exports
 */

import { get_sha1_instance, sha1_constructor } from './sha1';
import { bytes_to_base64, bytes_to_hex } from '../../utils';

function sha1_bytes(data) {
  if (data === undefined) throw new SyntaxError('data required');
  return get_sha1_instance()
    .reset()
    .process(data)
    .finish().result;
}

function sha1_hex(data) {
  var result = sha1_bytes(data);
  return bytes_to_hex(result);
}

function sha1_base64(data) {
  var result = sha1_bytes(data);
  return bytes_to_base64(result);
}

export var SHA1 = sha1_constructor;

SHA1.bytes = sha1_bytes;
SHA1.hex = sha1_hex;
SHA1.base64 = sha1_base64;
