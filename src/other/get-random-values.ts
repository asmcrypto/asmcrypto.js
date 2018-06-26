export function getRandomValues(buf: Uint32Array | Uint8Array): void {
  if (typeof process !== 'undefined') {
    const nodeCrypto = require('crypto');
    const bytes = nodeCrypto.randomBytes(buf.length);
    buf.set(bytes);
    return;
  }
  if (window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(buf);
    return;
  }
  if (self.crypto && self.crypto.getRandomValues) {
    self.crypto.getRandomValues(buf);
    return;
  }
  // @ts-ignore
  if (window.msCrypto && window.msCrypto.getRandomValues) {
    // @ts-ignore
    window.msCrypto.getRandomValues(buf);
    return;
  }
  throw new Error('No secure random number generator available.');
}
