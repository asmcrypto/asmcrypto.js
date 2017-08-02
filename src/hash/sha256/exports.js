/**
 * SHA256 exports
 */

import {get_sha256_instance, sha256_constructor} from './sha256';
import {bytes_to_base64, bytes_to_hex} from '../../utils';

function sha256_bytes (data ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    return get_sha256_instance().reset().process(data).finish().result;
}

function sha256_hex ( data ) {
    var result = sha256_bytes(data);
    return bytes_to_hex(result);
}

function sha256_base64 ( data ) {
    var result = sha256_bytes(data);
    return bytes_to_base64(result);
}

export var SHA256 = sha256_constructor;
SHA256.bytes = sha256_bytes;
SHA256.hex = sha256_hex;
SHA256.base64 = sha256_base64;
