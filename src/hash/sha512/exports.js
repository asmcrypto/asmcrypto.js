/**
 * SHA512 exports
 */

import { get_sha512_instance, sha512_constructor } from './sha512';
import { bytes_to_base64, bytes_to_hex } from '../../utils';

function sha512_bytes(data) {
  if (data === undefined) throw new SyntaxError('data required');
  return get_sha512_instance()
    .reset()
    .process(data)
    .finish().result;
}

function sha512_hex(data) {
  var result = sha512_bytes(data);
  return bytes_to_hex(result);
}

function sha512_base64(data) {
  var result = sha512_bytes(data);
  return bytes_to_base64(result);
}

export var SHA512 = sha512_constructor;

SHA512.bytes = sha512_bytes;
SHA512.hex = sha512_hex;
SHA512.base64 = sha512_base64;
