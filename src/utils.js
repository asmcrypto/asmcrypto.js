"use strict";

var FloatArray = global.Float64Array || global.Float32Array; // make PhantomJS happy

function string_to_bytes ( str ) {
    var len = str.length,
        arr = new Uint8Array( len );
    for ( var i = 0; i < len; i++ ) {
        var c = str.charCodeAt(i);
        if ( c >>> 8 ) throw new Error("Wide characters are not allowed. Use string_to_utf8bytes.");
        arr[i] = c;
    }
    return arr;
}

function string_to_utf8bytes ( str ) {

	function fixedCharCodeAt(str, idx) {
	  idx = idx || 0;
	  var code = str.charCodeAt(idx);
	  var hi, low;
	  
	  // High surrogate (could change last hex to 0xDB7F to treat high
	  // private surrogates as single characters)
	  if (0xd800 <= code && code <= 0xdbff) {
		hi = code;
		low = str.charCodeAt(idx + 1);
		if (isNaN(low)) {
		  throw 'High surrogate not followed by low surrogate in fixedCharCodeAt()';
		}
		return ((hi - 0xd800) * 0x400) + (low - 0xdc00) + 0x10000;
	  }
	  if (0xdc00 <= code && code <= 0xdfff) { // Low surrogate
		// We return false to allow loops to skip this iteration since should have
		// already handled high surrogate above in the previous iteration
		return false;
	  }
	  return code;
	}

	var len = str.length,
        bytes = [];
    for ( var i = 0; i < len; i++ ) {
        var c = fixedCharCodeAt(str, i);
		if (c === false) continue;
		
        if (c <= 0x7f) {
            bytes.push(c);
        } else if (c <= 0x7ff) {
            bytes.push((c >> 6) | 0xc0);
            bytes.push((c & 0x3F) | 0x80);
        } else if (c <= 0xffff) {
            bytes.push((c >> 12) | 0xe0);
            bytes.push(((c >> 6) & 0x3f) | 0x80);
            bytes.push((c & 0x3f) | 0x80);
        } else {
            bytes.push((c >> 18) | 0xf0);
            bytes.push(((c >> 12) & 0x3f) | 0x80);
            bytes.push(((c >> 6) & 0x3f) | 0x80);
            bytes.push((c & 0x3f) | 0x80);
        }
    }
    return new Uint8Array(bytes);
}

function hex_to_bytes ( str ) {
    var arr = [],
        len = str.length,
        i;
    if ( len & 1 ) {
        str = '0'+str;
        len++;
    }
    for ( i=0; i<len; i+=2 ) {
        arr.push( parseInt( str.substr( i, 2), 16 ) );
    }
    return new Uint8Array(arr);
}

function base64_to_bytes ( str ) {
    return string_to_bytes( atob( str ) );
}

function bytes_to_string ( arr ) {
    var str = '';
    for ( var i = 0; i < arr.length; i++ ) str += String.fromCharCode( arr[i] );
    return str;
}

function utf8bytes_to_string ( arr ) {
	var len = arr.length,
        str = '';
    for ( var i = 0; i < len; i++ ) {
        if (arr[i] < 128) {
            str += String.fromCharCode( arr[i] );
        } else if (arr[i] >= 192 && arr[i] < 224 && (i + 1 < len)) {
			str += String.fromCharCode(((arr[i] & 0x1f) << 6) | (arr[++i] & 0x3f));
		} else if (arr[i] >= 224 && arr[i] < 240 && (i + 2 < len)) {
            str += String.fromCharCode(((arr[i] & 0xf) << 12) | ((arr[++i] & 0x3f) << 6) | (arr[++i] & 0x3f));
		} else if (arr[i] >= 240 && arr[i] < 248 && (i + 3 < len)) {
			var unicodePoint = ((arr[i] & 7) << 18) | ((arr[++i] & 0x3f) << 12) | ((arr[++i] & 0x3f) << 6) | (arr[++i] & 0x3f);
			if (unicodePoint <= 0xffff) {
				str += String.fromCharCode(unicodePoint);
			}
			else {
				unicodePoint -= 0x10000;
				highSurrogate = (unicodePoint >> 10) + 0xd800;
				lowSurrogate = (unicodePoint % 0x400) + 0xdc00;
				str += String.fromCharCode(highSurrogate, lowSurrogate);
			}
        } else {
			console.log(arr[i]);
			throw new Error("Not a UTF8 encoded byte array.");
		}
    }
    return str;
}

function bytes_to_hex ( arr ) {
    var sz = ( arr.byteLength || arr.length ) / arr.length,
        str = '';
    for ( var i = 0; i < arr.length; i++ ) {
        var h = arr[i].toString(16);
        if ( h.length < 2*sz ) str += '00000000000000'.substr( 0, 2*sz-h.length );
        str += h;
    }
    return str;
}

function bytes_to_base64 ( arr ) {
    return btoa( bytes_to_string(arr) );
}

function pow2_ceil ( a ) {
    a -= 1;
    a |= a >>> 1;
    a |= a >>> 2;
    a |= a >>> 4;
    a |= a >>> 8;
    a |= a >>> 16;
    a += 1;
    return a;
}

function is_number ( a ) {
    return ( typeof a === 'number' );
}

function is_string ( a ) {
    return ( typeof a === 'string' );
}

function is_buffer ( a ) {
    return ( a instanceof ArrayBuffer );
}

function is_bytes ( a ) {
    return ( a instanceof Uint8Array );
}

function is_typed_array ( a ) {
    return ( a instanceof Int8Array ) || ( a instanceof Uint8Array )
        || ( a instanceof Int16Array ) || ( a instanceof Uint16Array )
        || ( a instanceof Int32Array ) || ( a instanceof Uint32Array )
        || ( a instanceof Float32Array )
        || ( a instanceof Float64Array );
}
