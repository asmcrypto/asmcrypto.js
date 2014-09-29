"use strict";

var FloatArray = global.Float64Array || global.Float32Array; // make PhantomJS happy

function string_to_bytes ( str ) {
    var len = str.length,
        arr = new Uint8Array( len );
    for ( var i = 0; i < len; i++ ) {
        var c = str.charCodeAt(i);
        if ( c >>> 8 ) throw new Error("Wide characters are not allowed");
        arr[i] = c;
    }
    return arr;
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
