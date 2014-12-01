"use strict";

// Galois Field exponentiation and logarithm tables for 3 (generator)
var gexp3, glog3;

/**
 * Init Galois Field tables
 * @protected
 */
function ginit () {
    gexp3 = [],
    glog3 = [];

    var a = 1, c, d;
    for ( c = 0; c < 255; c++ ) {
        gexp3[c] = a;

        // Multiply by three
        d = a & 0x80, a <<= 1, a &= 255;
        if ( d === 0x80 ) a ^= 0x1b;
        a ^= gexp3[c];

        // Set the log table value
        glog3[gexp3[c]] = c;
    }
    gexp3[255] = gexp3[0];
    glog3[0] = 0;
}

/**
 * Galois Field multiplication
 * @protected
 * @param {Number} a
 * @param {Number} b
 * @return {Number}
 */
function gmul ( a, b ) {
    var c = gexp3[ ( glog3[a] + glog3[b] ) % 255 ];
    if ( a === 0 || b === 0 ) c = 0;
    return c;
}

/**
 * Galois Field reciprocal
 * @protected
 * @param {Number} a
 * @return {Number}
 */
function ginv ( a ) {
    var i = gexp3[ 255 - glog3[a] ];
    if ( a === 0 ) i = 0;
    return i;
}

/**
 * Encryption, Decryption, S-Box and KeyTransform
 * @protected
 */
var aes_sbox, aes_sinv, aes_enc, aes_dec;

/**
 * Init AES tables
 * @protected
 */
function aes_init () {
    // Calculates AES S-Box value
    function _s ( a ) {
        var c, s, x;
        s = x = ginv(a);
        for ( c = 0; c < 4; c++ ) {
            s = ( (s << 1) | (s >>> 7) ) & 255;
            x ^= s;
        }
        x ^= 99;
        return x;
    }

    // Tables
    aes_sbox = [],
    aes_sinv = [],
    aes_enc = [ [], [], [], [] ],
    aes_dec = [ [], [], [], [] ];

    for ( var i = 0; i < 256; i++ ) {
        var s = _s(i);

        // S-Box and its inverse
        aes_sbox[i]  = s;
        aes_sinv[s]  = i;

        // Ecryption and Decryption tables
        aes_enc[0][i] = ( gmul( 2, s ) << 24 )  | ( s << 16 )            | ( s << 8 )             | gmul( 3, s );
        aes_dec[0][s] = ( gmul( 14, i ) << 24 ) | ( gmul( 9, i ) << 16 ) | ( gmul( 13, i ) << 8 ) | gmul( 11, i );
        // Rotate tables
        for ( var t = 1; t < 4; t++ ) {
            aes_enc[t][i] = ( aes_enc[t-1][i] >>> 8 ) | ( aes_enc[t-1][i] << 24 );
            aes_dec[t][s] = ( aes_dec[t-1][s] >>> 8 ) | ( aes_dec[t-1][s] << 24 );
        }
    }
}

/**
 * Calculate AES key schedules
 * @protected
 * @param {Number} ks — key size, 4/6/8 (for 128/192/256-bit key correspondingly).
 * @param {Number} k0..k7 — key components.
 * @return {Array} array w/ encryption and decryption key schedules.
 */
function aes_keys ( ks, k0, k1, k2, k3, k4, k5, k6, k7 ) {
    var ekeys = [ k0, k1, k2, k3, k4, k5, k6, k7 ],
        dkeys = [];

    // Encryption key schedule
    for ( var i = ks, rcon = 1; i < 4*ks+28; i++ ) {
        var k = ekeys[i-1];
        if ( ( i % ks === 0 ) || ( ks === 8 && i % ks === 4 ) ) {
            k = aes_sbox[k>>>24]<<24 ^ aes_sbox[k>>>16&255]<<16 ^ aes_sbox[k>>>8&255]<<8 ^ aes_sbox[k&255];
        }
        if ( i % ks === 0 ) {
            k = (k << 8) ^ (k >>> 24) ^ (rcon << 24);
            rcon = (rcon << 1) ^ ( (rcon & 0x80) ? 0x1b : 0 );
        }
        ekeys[i] = ekeys[i-ks] ^ k;
    }

    // Decryption key schedule
    for ( var j = 0; j < i; j += 4 ) {
        for ( var jj = 0; jj < 4; jj++ ) {
            var k = ekeys[i+jj-(4+j)];
            if ( j < 4 || j >= i-4 ) {
                dkeys[j+jj] = k;
            } else {
                dkeys[j+jj] = aes_dec[0][aes_sbox[k>>>24]]
                            ^ aes_dec[1][aes_sbox[k>>>16&255]]
                            ^ aes_dec[2][aes_sbox[k>>>8&255]]
                            ^ aes_dec[3][aes_sbox[k&255]];
            }
        }
    }

    return [ ekeys, dkeys ];
}

// Init the stuff
ginit();
aes_init();

/**
 * Asm.js module w/ low-level core functions
 * Heap layout:
 * 0x0000 .. 0x0fff     key material
 * 0x1000 .. 0x1fff     encryption tables
 * 0x2000 .. 0x23ff     sbox
 * 0x3000 .. 0x3fff     decryption tables
 * 0x4000 .. 0x43ff     inv sbox
 * 0x5000 .. ??????     data
 * @protected
 */
function naes_asm ( stdlib, foreign, buffer ) {
    var heap = new Uint32Array(buffer);
    for ( var c = 0; c < 4; c++ ) {
        heap.set( aes_enc[c], (0x1000|c<<8)>>>2 );
        heap.set( aes_dec[c], (0x3000|c<<8)>>>2 );
    }
    heap.set( aes_sbox, 0x2000>>>2 );
    heap.set( aes_sinv, 0x4000>>>2 );

    return function ( stdlib, foreign, buffer ) {
        //"use asm";

        var S0 = 0, S1 = 0, S2 = 0, S3 = 0;

        var HEAP = new stdlib.Uint32Array(buffer);

        /**
         * AES core
         * @private
         * @param {int} t — precomputed encryption(decryption) table offset
         * @param {int} k — precomputed encryption(decryption) key schedule offset
         * @param {int} r — number of inner rounds to perform
         * @param {int} x0..x3 — 128-bit input block
         */
        function _core ( t, k, r, x0, x1, x2, x3 ) {
            t = t|0;
            k = k|0;
            r = r|0;
            x0 = x0|0;
            x1 = x1|0;
            x2 = x2|0;
            x3 = x3|0;

            var t1 = 0, t2 = 0, t3 = 0, t4 = 0,
                y0 = 0, y1 = 0, y2 = 0, y3 = 0,
                i = 0;

            t1 = t|0x400, t2 = t|0x800, t3 = t|0xc00, t4 = t|0x1000;

            // round 0
            x0 = x0 ^ HEAP[k>>2],
            x1 = x1 ^ HEAP[(k|4)>>2],
            x2 = x2 ^ HEAP[(k|8)>>2],
            x3 = x3 ^ HEAP[(k|12)>>2];

            // round 1..r
            for ( i = 1; (i|0) <= (r<<4); i = (i+16)|0 ) {
                y0 = HEAP[(t|x0>>22&1020)>>2] ^ HEAP[(t1|x1>>14&1020)>>2] ^ HEAP[(t2|x2>>6&1020)>>2] ^ HEAP[(t3|x3<<2&1020)>>2] ^ HEAP[(k|i|0)>>2],
                y1 = HEAP[(t|x1>>22&1020)>>2] ^ HEAP[(t1|x2>>14&1020)>>2] ^ HEAP[(t2|x3>>6&1020)>>2] ^ HEAP[(t3|x0<<2&1020)>>2] ^ HEAP[(k|i|4)>>2],
                y2 = HEAP[(t|x2>>22&1020)>>2] ^ HEAP[(t1|x3>>14&1020)>>2] ^ HEAP[(t2|x0>>6&1020)>>2] ^ HEAP[(t3|x1<<2&1020)>>2] ^ HEAP[(k|i|8)>>2],
                y3 = HEAP[(t|x3>>22&1020)>>2] ^ HEAP[(t1|x0>>14&1020)>>2] ^ HEAP[(t2|x1>>6&1020)>>2] ^ HEAP[(t3|x2<<2&1020)>>2] ^ HEAP[(k|i|12)>>2];
                x0 = y0, x1 = y1, x2 = y2, x3 = y3;
            }

            // final round
            S0 = HEAP[(t4|y0>>22&1020)>>2]<<24 ^ HEAP[(t4|y1>>14&1020)>>2]<<16 ^ HEAP[(t4|y2>>6&1020)>>2]<<8 ^ HEAP[(t4|y3<<2&1020)>>2] ^ HEAP[(k|r<<4|0)>>2],
            S1 = HEAP[(t4|y1>>22&1020)>>2]<<24 ^ HEAP[(t4|y2>>14&1020)>>2]<<16 ^ HEAP[(t4|y3>>6&1020)>>2]<<8 ^ HEAP[(t4|y0<<2&1020)>>2] ^ HEAP[(k|r<<4|4)>>2],
            S2 = HEAP[(t4|y2>>22&1020)>>2]<<24 ^ HEAP[(t4|y3>>14&1020)>>2]<<16 ^ HEAP[(t4|y0>>6&1020)>>2]<<8 ^ HEAP[(t4|y1<<2&1020)>>2] ^ HEAP[(k|r<<4|8)>>2],
            S3 = HEAP[(t4|y3>>22&1020)>>2]<<24 ^ HEAP[(t4|y0>>14&1020)>>2]<<16 ^ HEAP[(t4|y1>>6&1020)>>2]<<8 ^ HEAP[(t4|y2<<2&1020)>>2] ^ HEAP[(k|r<<4|12)>>2];
        }

        return {
            _core: _core
        };
    }( stdlib, foreign, buffer );
}
