var _global_console = typeof console !== 'undefined' ? console : undefined;

var _secure_origin =
  typeof location === 'undefined' || !location.protocol.search(/https:|file:|chrome:|chrome-extension:|moz-extension:/);

if (!_secure_origin && _global_console !== undefined) {
  _global_console.warn(
    'asmCrypto seems to be load from an insecure origin; this may cause to MitM-attack vulnerability. Consider using secure transport protocol.',
  );
}
