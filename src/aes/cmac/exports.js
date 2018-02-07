import { AES_CMAC } from './cmac';

/**
 * @param {Uint8Array} data
 * @param {Uint8Array} key
 * @returns {Uint8Array}
 */
function AES_CMAC_bytes(data, key) {
  if (data === undefined) throw new SyntaxError('data required');
  if (key === undefined) throw new SyntaxError('key required');
  return new AES_CMAC(key).process(data).finish().result;
}

AES_CMAC.bytes = AES_CMAC_bytes;

export { AES_CMAC };
