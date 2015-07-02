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

	var len = str.length,
        bytes = new Uint8Array(4*len);
    for ( var i = 0, j = 0; i < len; i++ ) {
	
		var c = str.charCodeAt(i);
		if ( 0xd800 <= c && c <= 0xdbff ) {
            if ( ++i >= len ) throw new Error( "Malformed string, low surrogate expected at position " + i );
            c = ( (c ^ 0xd800) << 10 ) | 0x10000 | ( str.charCodeAt(i) ^ 0xdc00 );
        }
        
        if (c <= 0x7f) {
            bytes[j++] = c;
        } 
		else if (c <= 0x7ff) {
            bytes[j++] = 0xc0 | (c >> 6);
            bytes[j++] = 0x80 | (c & 0x3f);
        } 
		else if (c <= 0xffff) {
            bytes[j++] = 0xe0 | (c >> 12);
            bytes[j++] = 0x80 | ((c >> 6) & 0x3f);
            bytes[j++] = 0x80 | (c & 0x3f);
        } 
		else {
            bytes[j++] = 0xf0 | (c >> 18);
            bytes[j++] = 0x80 | ((c >> 12) & 0x3f);
            bytes[j++] = 0x80 | ((c >> 6) & 0x3f);
            bytes[j++] = 0x80 | (c & 0x3f);
        }
    }
	
    return bytes.subarray(0, j);
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
        strBuffer = new Uint16Array(len);
		
    for ( var i = 0, j = 0; i < len; i++ ) {
        if (arr[i] < 128) {
            strBuffer[j++] = arr[i] ;
        } 
		else if (arr[i] >= 192 && arr[i] < 224 && (i + 1 < len)) {
			strBuffer[j++] = ((arr[i] & 0x1f) << 6) | (arr[++i] & 0x3f);
		} 
		else if (arr[i] >= 224 && arr[i] < 240 && (i + 2 < len)) {
            strBuffer[j++] = ((arr[i] & 0xf) << 12) | ((arr[++i] & 0x3f) << 6) | (arr[++i] & 0x3f);
		} 
		else if (arr[i] >= 240 && arr[i] < 248 && (i + 3 < len)) {
			var unicodePoint = ((arr[i] & 7) << 18) | ((arr[++i] & 0x3f) << 12) | ((arr[++i] & 0x3f) << 6) | (arr[++i] & 0x3f);
			if (unicodePoint <= 0xffff) {
				strBuffer[j++] = unicodePoint;
			}
			else {
				unicodePoint -= 0x10000;
				strBuffer[j++] = (unicodePoint >> 10) + 0xd800;
				strBuffer[j++] = (unicodePoint % 0x400) + 0xdc00;
			}
        } 
		else {
			throw new Error("Not a UTF8 encoded byte array.");
		}
    }
	
	var batchSize = 16384;
	if (j < batchSize) {
		return String.fromCharCode.apply(null, strBuffer.subarray(0, j));
	}

	var str = '';
	for (var i = 0; i < j; i += batchSize) {
		var batch = strBuffer.subarray(i, i + batchSize > j ? j : i + batchSize);
		str += String.fromCharCode.apply(null, batch);
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
