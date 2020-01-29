const local_atob = typeof atob === 'undefined' ? (str: string) => Buffer.from(str, 'base64').toString('binary') : atob;
const local_btoa = typeof btoa === 'undefined' ? (str: string) => Buffer.from(str, 'binary').toString('base64') : btoa;

export function string_to_bytes(str: string, utf8: boolean = false): Uint8Array {
  var len = str.length,
    bytes = new Uint8Array(utf8 ? 4 * len : len);

  for (var i = 0, j = 0; i < len; i++) {
    var c = str.charCodeAt(i);

    if (utf8 && 0xd800 <= c && c <= 0xdbff) {
      if (++i >= len) throw new Error('Malformed string, low surrogate expected at position ' + i);
      c = ((c ^ 0xd800) << 10) | 0x10000 | (str.charCodeAt(i) ^ 0xdc00);
    } else if (!utf8 && c >>> 8) {
      throw new Error('Wide characters are not allowed. At the position ' + i + ' this character was found: ' + str[i])
    }

    if (!utf8 || c <= 0x7f) {
      bytes[j++] = c;
    } else if (c <= 0x7ff) {
      bytes[j++] = 0xc0 | (c >> 6);
      bytes[j++] = 0x80 | (c & 0x3f);
    } else if (c <= 0xffff) {
      bytes[j++] = 0xe0 | (c >> 12);
      bytes[j++] = 0x80 | ((c >> 6) & 0x3f);
      bytes[j++] = 0x80 | (c & 0x3f);
    } else {
      bytes[j++] = 0xf0 | (c >> 18);
      bytes[j++] = 0x80 | ((c >> 12) & 0x3f);
      bytes[j++] = 0x80 | ((c >> 6) & 0x3f);
      bytes[j++] = 0x80 | (c & 0x3f);
    }
  }

  return bytes.subarray(0, j);
}

export function hex_to_bytes(str: string): Uint8Array {
  var len = str.length;
  if (len & 1) {
    str = '0' + str;
    len++;
  }
  var bytes = new Uint8Array(len >> 1);
  for (var i = 0; i < len; i += 2) {
    bytes[i >> 1] = parseInt(str.substr(i, 2), 16);
  }
  return bytes;
}

export function base64_to_bytes(str: string): Uint8Array {
  return string_to_bytes(local_atob(str));
}

export function bytes_to_string(bytes: Uint8Array, utf8: boolean = false): string {
  var len = bytes.length,
    chars = new Array(len);

  for (var i = 0, j = 0; i < len; i++) {
    var b = bytes[i];
    if (!utf8 || b < 128) {
      chars[j++] = b;
    } else if (b >= 192 && b < 224 && i + 1 < len) {
      chars[j++] = ((b & 0x1f) << 6) | (bytes[++i] & 0x3f);
    } else if (b >= 224 && b < 240 && i + 2 < len) {
      chars[j++] = ((b & 0xf) << 12) | ((bytes[++i] & 0x3f) << 6) | (bytes[++i] & 0x3f);
    } else if (b >= 240 && b < 248 && i + 3 < len) {
      var c = ((b & 7) << 18) | ((bytes[++i] & 0x3f) << 12) | ((bytes[++i] & 0x3f) << 6) | (bytes[++i] & 0x3f);
      if (c <= 0xffff) {
        chars[j++] = c;
      } else {
        c ^= 0x10000;
        chars[j++] = 0xd800 | (c >> 10);
        chars[j++] = 0xdc00 | (c & 0x3ff);
      }
    } else {
      throw new Error('Malformed UTF8 character at byte offset ' + i);
    }
  }

  var str = '',
    bs = 16384;
  for (var i = 0; i < j; i += bs) {
    str += String.fromCharCode.apply(String, chars.slice(i, i + bs <= j ? i + bs : j));
  }

  return str;
}

export function bytes_to_hex(arr: Uint8Array): string {
  var str = '';
  for (var i = 0; i < arr.length; i++) {
    var h = (arr[i] & 0xff).toString(16);
    if (h.length < 2) str += '0';
    str += h;
  }
  return str;
}

export function bytes_to_base64(arr: Uint8Array): string {
  return local_btoa(bytes_to_string(arr));
}

export function pow2_ceil(a: number): number {
  a -= 1;
  a |= a >>> 1;
  a |= a >>> 2;
  a |= a >>> 4;
  a |= a >>> 8;
  a |= a >>> 16;
  a += 1;
  return a;
}

export function is_number(a: number): boolean {
  return typeof a === 'number';
}

export function is_string(a: string): boolean {
  return typeof a === 'string';
}

export function is_buffer(a: ArrayBuffer): boolean {
  return a instanceof ArrayBuffer;
}

export function is_bytes(a: Uint8Array): boolean {
  return a instanceof Uint8Array;
}

export function is_typed_array(a: any): boolean {
  return (
    a instanceof Int8Array ||
    a instanceof Uint8Array ||
    a instanceof Int16Array ||
    a instanceof Uint16Array ||
    a instanceof Int32Array ||
    a instanceof Uint32Array ||
    a instanceof Float32Array ||
    a instanceof Float64Array
  );
}

export function _heap_init(heap?: Uint8Array, heapSize?: number): Uint8Array {
  const size = heap ? heap.byteLength : heapSize || 65536;

  if (size & 0xfff || size <= 0) throw new Error('heap size must be a positive integer and a multiple of 4096');

  heap = heap || new Uint8Array(new ArrayBuffer(size));

  return heap;
}

export function _heap_write(heap: Uint8Array, hpos: number, data: Uint8Array, dpos: number, dlen: number): number {
  const hlen = heap.length - hpos;
  const wlen = hlen < dlen ? hlen : dlen;

  heap.set(data.subarray(dpos, dpos + wlen), hpos);

  return wlen;
}

export function joinBytes(...arg: Uint8Array[]): Uint8Array {
  const totalLenght = arg.reduce((sum, curr) => sum + curr.length, 0);
  const ret = new Uint8Array(totalLenght);

  let cursor = 0;
  for (let i = 0; i < arg.length; i++) {
    ret.set(arg[i], cursor);
    cursor += arg[i].length;
  }
  return ret;
}
