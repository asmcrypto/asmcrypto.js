export function getRandomValues(buf: Uint32Array | Uint8Array): void {
  try {
    if (typeof window === 'undefined') {
      const nodeCrypto = require('crypto');
      const bytes = nodeCrypto.randomBytes(buf.length);
      buf.set(bytes);
      return;
    }
  } catch (e) {
    console.error(e);
    throw new Error('No secure random number generator available.');
  }
  if (window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(buf);
    return;
  }
  // @ts-ignore
  if (window.msCrypto && window.msCrypto.getRandomValues) {
    // @ts-ignore
    window.msCrypto.getRandomValues(buf);
    return;
  }
}
