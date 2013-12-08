"use strict";

function IllegalStateError () { Error.apply( this, arguments ); }
IllegalStateError.prototype = new Error;

function IllegalArgumentError () { Error.apply( this, arguments ); }
IllegalArgumentError.prototype = new Error;

function SecurityError () { Error.apply( this, arguments ); }
IllegalArgumentError.prototype = new Error;

function resultAsArrayBuffer () {
    if ( this.result === null )
        throw new IllegalStateError("no result yet");

    return this.result.buffer;
}

function resultAsBinaryString () {
    if ( this.result === null )
        throw new IllegalStateError("no result yet");

    var s = '';
    for ( var i = 0; i < this.result.byteLength; i++ )
        s += String.fromCharCode( this.result[i] );

    return s;
}

function resultAsHex () {
    if ( this.result === null )
        throw new IllegalStateError("no result yet");

    var s = '', h;
    for ( var i = 0; i < this.result.byteLength; i++ ) {
        h = this.result[i].toString(16);
        if ( h.length < 2 ) s += '0';
        s += h;
    }

    return s;
}

function resultAsBase64 () {
    var s = resultAsBinaryString.call(this);
    return btoa(s);
}

exports.IllegalStateError = IllegalStateError;
exports.IllegalArgumentError = IllegalArgumentError;
exports.SecurityError = SecurityError;
