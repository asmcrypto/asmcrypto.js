"use strict";

/**
 * May be run as:
 * plain script (from <script> tag or whatever),
 * plain worker script (calling importScripts from worker),
 * multipart crypto-operation worker (calling new Worker and passing options via url-fragment).
 *
 * The last option is detected here.
 */
var _is_crypto_worker = ( global.document === undefined && global.location.hash.length > 0 );

function string_to_bytes ( str ) {
    var i,
        len=str.length,
        arr = new Uint8Array( len );
    for ( i=0; i<len; i+=1 ) {
        arr[i] = str.charCodeAt(i);
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
    return string_to_bytes( global.atob( str ) );
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
    return global.btoa( bytes_to_string(arr) );
}
