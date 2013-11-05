"use strict";

function resultAsArrayBuffer () {
    if ( this.result === null )
        throw new Error("Illegal state");

    return this.result.buffer;
}

function resultAsBinaryString () {
    if ( this.result === null )
        throw new Error("Illegal state");

    var s = '';
    for ( var i = 0; i < this.result.length; i++ )
        s += String.fromCharCode( this.result[i] );

    return s;
}

function resultAsHex () {
    if ( this.result === null )
        throw new Error("Illegal state");

    var s = '', h;
    for ( var i = 0; i < this.result.length; i++ ) {
        h = this.result[i].toString(16);
        if ( h.length < 2 ) s += '0';
        s += h;
    }

    return s;
}

function resultAsBase64 () {
    var s = resultAsBinaryString();
    return btoa(s);
}
