/**
 * Asm.js module w/ low-level core functions
 *
 * Heap layout:
 * 0x0000   encryption key schedule
 * 0x0400   decryption key schedule
 * 0x0800   sbox
 * 0x0c00   inv sbox
 * 0x1000   encryption tables
 * 0x2000   decryption tables
 * 0x3000   reserved (GCM multiplication table)
 * 0x4000   data
 *
 * @protected
 */
var AES_asm = function () {
    "use strict";

    /**
     * Galois Field stuff init flag
     * @private
     */
    var ginit_done = false;

    /**
     * Galois Field exponentiation and logarithm tables for 3 (the generator)
     * @private
     */
    var gexp3, glog3;

    /**
     * Init Galois Field tables
     * @private
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

        ginit_done = true;
    }

    /**
     * Galois Field multiplication
     * @private
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
     * @private
     * @param {Number} a
     * @return {Number}
     */
    function ginv ( a ) {
        var i = gexp3[ 255 - glog3[a] ];
        if ( a === 0 ) i = 0;
        return i;
    }

    /**
     * AES stuff init flag
     */
    var aes_init_done = false;

    /**
     * Encryption, Decryption, S-Box and KeyTransform tables
     * @private
     */
    var aes_sbox, aes_sinv, aes_enc, aes_dec;

    /**
     * Init AES tables
     * @private
     */
    function aes_init () {
        if ( !ginit_done ) ginit();

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

    // Asm.js AES module wrapper
    var wrapper = function ( stdlib, foreign, buffer ) {
        // Init AES stuff for the first time
        if ( !aes_init_done ) aes_init();

        // Fill up AES tables
        var heap = new Uint32Array(buffer);
        heap.set( aes_sbox, 0x0800>>2 );
        heap.set( aes_sinv, 0x0c00>>2 );
        for ( var i = 0; i < 4; i++ ) {
            heap.set( aes_enc[i], ( 0x1000 + 0x400 * i )>>2 );
            heap.set( aes_dec[i], ( 0x2000 + 0x400 * i )>>2 );
        }

        /**
         * Calculate AES key schedules
         * @public
         * @param {Number} ks — key size, 4/6/8 (for 128/192/256-bit key correspondingly).
         * @param {Number} k0..k7 — key components.
         */
        function set_key ( ks, k0, k1, k2, k3, k4, k5, k6, k7 ) {
            var ekeys = heap.subarray( 0x000, 60 ),
                dkeys = heap.subarray( 0x100, 0x100+60 );

            // Encryption key schedule
            ekeys.set( [ k0, k1, k2, k3, k4, k5, k6, k7 ] );
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
                    var k = ekeys[i-(4+j)+(4-jj)%4];
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

            // Set rounds number
            asm.set_rounds( ks + 5 );
        }

        var asm = function ( stdlib, foreign, buffer ) {
            "use asm";

            var S0 = 0, S1 = 0, S2 = 0, S3 = 0,
                I0 = 0, I1 = 0, I2 = 0, I3 = 0,
                N0 = 0, N1 = 0, N2 = 0, N3 = 0,
                M0 = 0, M1 = 0, M2 = 0, M3 = 0,
                H0 = 0, H1 = 0, H2 = 0, H3 = 0,
                R = 0;

            var HEAP = new stdlib.Uint32Array(buffer),
                DATA = new stdlib.Uint8Array(buffer);

            /**
             * AES core
             * @private
             * @param {int} k — precomputed key schedule offset
             * @param {int} s — precomputed sbox table offset
             * @param {int} t — precomputed round table offset
             * @param {int} r — number of inner rounds to perform
             * @param {int} x0..x3 — 128-bit input block
             */
            function _core ( k, s, t, r, x0, x1, x2, x3 ) {
                k = k|0;
                s = s|0;
                t = t|0;
                r = r|0;
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                var t1 = 0, t2 = 0, t3 = 0,
                    y0 = 0, y1 = 0, y2 = 0, y3 = 0,
                    i = 0;

                t1 = t|0x400, t2 = t|0x800, t3 = t|0xc00;

                // round 0
                x0 = x0 ^ HEAP[(k|0)>>2],
                x1 = x1 ^ HEAP[(k|4)>>2],
                x2 = x2 ^ HEAP[(k|8)>>2],
                x3 = x3 ^ HEAP[(k|12)>>2];

                // round 1..r
                for ( i = 16; (i|0) <= (r<<4); i = (i+16)|0 ) {
                    y0 = HEAP[(t|x0>>22&1020)>>2] ^ HEAP[(t1|x1>>14&1020)>>2] ^ HEAP[(t2|x2>>6&1020)>>2] ^ HEAP[(t3|x3<<2&1020)>>2] ^ HEAP[(k|i|0)>>2],
                    y1 = HEAP[(t|x1>>22&1020)>>2] ^ HEAP[(t1|x2>>14&1020)>>2] ^ HEAP[(t2|x3>>6&1020)>>2] ^ HEAP[(t3|x0<<2&1020)>>2] ^ HEAP[(k|i|4)>>2],
                    y2 = HEAP[(t|x2>>22&1020)>>2] ^ HEAP[(t1|x3>>14&1020)>>2] ^ HEAP[(t2|x0>>6&1020)>>2] ^ HEAP[(t3|x1<<2&1020)>>2] ^ HEAP[(k|i|8)>>2],
                    y3 = HEAP[(t|x3>>22&1020)>>2] ^ HEAP[(t1|x0>>14&1020)>>2] ^ HEAP[(t2|x1>>6&1020)>>2] ^ HEAP[(t3|x2<<2&1020)>>2] ^ HEAP[(k|i|12)>>2];
                    x0 = y0, x1 = y1, x2 = y2, x3 = y3;
                }

                // final round
                S0 = HEAP[(s|x0>>22&1020)>>2]<<24 ^ HEAP[(s|x1>>14&1020)>>2]<<16 ^ HEAP[(s|x2>>6&1020)>>2]<<8 ^ HEAP[(s|x3<<2&1020)>>2] ^ HEAP[(k|i|0)>>2],
                S1 = HEAP[(s|x1>>22&1020)>>2]<<24 ^ HEAP[(s|x2>>14&1020)>>2]<<16 ^ HEAP[(s|x3>>6&1020)>>2]<<8 ^ HEAP[(s|x0<<2&1020)>>2] ^ HEAP[(k|i|4)>>2],
                S2 = HEAP[(s|x2>>22&1020)>>2]<<24 ^ HEAP[(s|x3>>14&1020)>>2]<<16 ^ HEAP[(s|x0>>6&1020)>>2]<<8 ^ HEAP[(s|x1<<2&1020)>>2] ^ HEAP[(k|i|8)>>2],
                S3 = HEAP[(s|x3>>22&1020)>>2]<<24 ^ HEAP[(s|x0>>14&1020)>>2]<<16 ^ HEAP[(s|x1>>6&1020)>>2]<<8 ^ HEAP[(s|x2<<2&1020)>>2] ^ HEAP[(k|i|12)>>2];
            }

            /**
             * ECB mode encryption
             * @private
             */
            function _ecb_enc ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    x0,
                    x1,
                    x2,
                    x3
                );
            }

            /**
             * ECB mode decryption
             * @private
             */
            function _ecb_dec ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                var t = 0;

                _core(
                    0x0400, 0x0c00, 0x2000,
                    R,
                    x0,
                    x3,
                    x2,
                    x1
                );

                t = S1, S1 = S3, S3 = t;
            }


            /**
             * CBC mode encryption
             * @private
             */
            function _cbc_enc ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    I0 ^ x0,
                    I1 ^ x1,
                    I2 ^ x2,
                    I3 ^ x3
                );

                I0 = S0,
                I1 = S1,
                I2 = S2,
                I3 = S3;
            }

            /**
             * CBC mode decryption
             * @private
             */
            function _cbc_dec ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                var t = 0;

                _core(
                    0x0400, 0x0c00, 0x2000,
                    R,
                    x0,
                    x3,
                    x2,
                    x1
                );

                t = S1, S1 = S3, S3 = t;

                S0 = S0 ^ I0,
                S1 = S1 ^ I1,
                S2 = S2 ^ I2,
                S3 = S3 ^ I3;

                I0 = x0,
                I1 = x1,
                I2 = x2,
                I3 = x3;
            }

            /**
             * CFB mode encryption
             * @private
             */
            function _cfb_enc ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    I0,
                    I1,
                    I2,
                    I3
                );

                I0 = S0 = S0 ^ x0,
                I1 = S1 = S1 ^ x1,
                I2 = S2 = S2 ^ x2,
                I3 = S3 = S3 ^ x3;
            }


            /**
             * CFB mode decryption
             * @private
             */
            function _cfb_dec ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    I0,
                    I1,
                    I2,
                    I3
                );

                S0 = S0 ^ x0,
                S1 = S1 ^ x1,
                S2 = S2 ^ x2,
                S3 = S3 ^ x3;

                I0 = x0,
                I1 = x1,
                I2 = x2,
                I3 = x3;
            }

            /**
             * OFB mode encryption / decryption
             * @private
             */
            function _ofb ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    I0,
                    I1,
                    I2,
                    I3
                );

                I0 = S0,
                I1 = S1,
                I2 = S2,
                I3 = S3;

                S0 = S0 ^ x0,
                S1 = S1 ^ x1,
                S2 = S2 ^ x2,
                S3 = S3 ^ x3;
            }

            /**
             * CTR mode encryption / decryption
             * @private
             */
            function _ctr ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    N0,
                    N1,
                    N2,
                    N3
                );

                N3 = ( ~M3 & N3 ) | M3 & ( N3 + 1 ),
                N2 = ( ~M2 & N2 ) | M2 & ( N2 + ( (N3|0) == 0 ) ),
                N1 = ( ~M1 & N1 ) | M1 & ( N1 + ( (N2|0) == 0 ) ),
                N0 = ( ~M0 & N0 ) | M0 & ( N0 + ( (N1|0) == 0 ) );

                S0 = S0 ^ x0,
                S1 = S1 ^ x1,
                S2 = S2 ^ x2,
                S3 = S3 ^ x3;
            }

            /**
             * GCM mode MAC calculation
             * @private
             */
            function _gcm_mac ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                var y0 = 0, y1 = 0, y2 = 0, y3 = 0,
                    z0 = 0, z1 = 0, z2 = 0, z3 = 0,
                    i = 0, c = 0;

                x0 = x0 ^ I0,
                x1 = x1 ^ I1,
                x2 = x2 ^ I2,
                x3 = x3 ^ I3;

                y0 = H0|0,
                y1 = H1|0,
                y2 = H2|0,
                y3 = H3|0;

                for ( ; (i|0) < 128; i = (i + 1)|0 ) {
                    if ( y0 >>> 31 ) {
                        z0 = z0 ^ x0,
                        z1 = z1 ^ x1,
                        z2 = z2 ^ x2,
                        z3 = z3 ^ x3;
                    }

                    y0 = (y0 << 1) | (y1 >>> 31),
                    y1 = (y1 << 1) | (y2 >>> 31),
                    y2 = (y2 << 1) | (y3 >>> 31),
                    y3 = (y3 << 1);

                    c = x3 & 1;

                    x3 = (x3 >>> 1) | (x2 << 31),
                    x2 = (x2 >>> 1) | (x1 << 31),
                    x1 = (x1 >>> 1) | (x0 << 31),
                    x0 = (x0 >>> 1);

                    if ( c ) x0 = x0 ^ 0xe1000000;
                }

                I0 = z0,
                I1 = z1,
                I2 = z2,
                I3 = z3;
            }

            /**
             * Set the internal rounds number
             * @public
             */
            function set_rounds ( r ) {
                r = r|0;
                R = r;
            }

            /**
             * Populate the internal state of the module
             * @public
             */
            function set_state ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                S0 = x0,
                S1 = x1,
                S2 = x2,
                S3 = x3;
            }

            /**
             * Populate the internal iv of the module
             * @public
             */
            function set_iv ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                I0 = x0,
                I1 = x1,
                I2 = x2,
                I3 = x3;
            }

            /**
             * Set nonce for CTR-family modes
             * @public
             */
            function set_nonce ( n0, n1, n2, n3 ) {
                n0 = n0|0;
                n1 = n1|0;
                n2 = n2|0;
                n3 = n3|0;

                N0 = n0,
                N1 = n1,
                N2 = n2,
                N3 = n3;
            }

            /**
             * Set counter mask for CTR-family modes
             * @public
             */
            function set_mask ( m0, m1, m2, m3 ) {
                m0 = m0|0;
                m1 = m1|0;
                m2 = m2|0;
                m3 = m3|0;

                M0 = m0,
                M1 = m1,
                M2 = m2,
                M3 = m3;
            }

            /**
             * Set counter for CTR-family modes
             * @public
             */
            function set_counter ( c0, c1, c2, c3 ) {
                c0 = c0|0;
                c1 = c1|0;
                c2 = c2|0;
                c3 = c3|0;

                N3 = ( ~M3 & N3 ) | M3 & c3,
                N2 = ( ~M2 & N2 ) | M2 & c2,
                N1 = ( ~M1 & N1 ) | M1 & c1,
                N0 = ( ~M0 & N0 ) | M0 & c0;
            }

            /**
             * Store the internal state into the heap
             * @public
             * @param {int} pos — offset where to put the data
             */
            function get_state ( pos ) {
                pos = pos|0;

                if ( pos & 15 ) return -1;

                DATA[pos|0] = S0>>>24,
                DATA[pos|1] = S0>>>16&255,
                DATA[pos|2] = S0>>>8&255,
                DATA[pos|3] = S0&255,
                DATA[pos|4] = S1>>>24,
                DATA[pos|5] = S1>>>16&255,
                DATA[pos|6] = S1>>>8&255,
                DATA[pos|7] = S1&255,
                DATA[pos|8] = S2>>>24,
                DATA[pos|9] = S2>>>16&255,
                DATA[pos|10] = S2>>>8&255,
                DATA[pos|11] = S2&255,
                DATA[pos|12] = S3>>>24,
                DATA[pos|13] = S3>>>16&255,
                DATA[pos|14] = S3>>>8&255,
                DATA[pos|15] = S3&255;

                return 16;
            }

            /**
             * Store the internal iv into the heap
             * @public
             * @param {int} pos — offset where to put the data
             */
            function get_iv ( pos ) {
                pos = pos|0;

                if ( pos & 15 ) return -1;

                DATA[pos|0] = I0>>>24,
                DATA[pos|1] = I0>>>16&255,
                DATA[pos|2] = I0>>>8&255,
                DATA[pos|3] = I0&255,
                DATA[pos|4] = I1>>>24,
                DATA[pos|5] = I1>>>16&255,
                DATA[pos|6] = I1>>>8&255,
                DATA[pos|7] = I1&255,
                DATA[pos|8] = I2>>>24,
                DATA[pos|9] = I2>>>16&255,
                DATA[pos|10] = I2>>>8&255,
                DATA[pos|11] = I2&255,
                DATA[pos|12] = I3>>>24,
                DATA[pos|13] = I3>>>16&255,
                DATA[pos|14] = I3>>>8&255,
                DATA[pos|15] = I3&255;

                return 16;
            }

            /**
             * GCM initialization
             * @public
             */
            function gcm_init ( ) {
                _ecb_enc( 0, 0, 0, 0 );
                H0 = S0,
                H1 = S1,
                H2 = S2,
                H3 = S3;
            }

            /**
             * Perform ciphering operation on the supplied data
             * @public
             * @param {int} mode — block cipher mode (see mode constants)
             * @param {int} pos — offset of the data being processed
             * @param {int} len — length of the data being processed
             * @return {int} actual amount of the data processed
             */
            function cipher ( mode, pos, len ) {
                mode = mode|0;
                pos = pos|0;
                len = len|0;

                var ret = 0;

                if ( pos & 15 ) return -1;

                while ( (len|0) >= 16 ) {
                    _cipher_modes[mode&7](
                        DATA[pos|0]<<24 | DATA[pos|1]<<16 | DATA[pos|2]<<8 | DATA[pos|3],
                        DATA[pos|4]<<24 | DATA[pos|5]<<16 | DATA[pos|6]<<8 | DATA[pos|7],
                        DATA[pos|8]<<24 | DATA[pos|9]<<16 | DATA[pos|10]<<8 | DATA[pos|11],
                        DATA[pos|12]<<24 | DATA[pos|13]<<16 | DATA[pos|14]<<8 | DATA[pos|15]
                    );

                    DATA[pos|0] = S0>>>24,
                    DATA[pos|1] = S0>>>16&255,
                    DATA[pos|2] = S0>>>8&255,
                    DATA[pos|3] = S0&255,
                    DATA[pos|4] = S1>>>24,
                    DATA[pos|5] = S1>>>16&255,
                    DATA[pos|6] = S1>>>8&255,
                    DATA[pos|7] = S1&255,
                    DATA[pos|8] = S2>>>24,
                    DATA[pos|9] = S2>>>16&255,
                    DATA[pos|10] = S2>>>8&255,
                    DATA[pos|11] = S2&255,
                    DATA[pos|12] = S3>>>24,
                    DATA[pos|13] = S3>>>16&255,
                    DATA[pos|14] = S3>>>8&255,
                    DATA[pos|15] = S3&255;

                    ret = (ret + 16)|0,
                    pos = (pos + 16)|0,
                    len = (len - 16)|0;
                }

                return ret|0;
            }

            /**
             * Calculates MAC of the supplied data
             * @public
             * @param {int} mode — block cipher mode (see mode constants)
             * @param {int} pos — offset of the data being processed
             * @param {int} len — length of the data being processed
             * @return {int} actual amount of the data processed
             */
            function mac ( mode, pos, len ) {
                mode = mode|0;
                pos = pos|0;
                len = len|0;

                var ret = 0;

                if ( pos & 15 ) return -1;

                while ( (len|0) >= 16 ) {
                    _mac_modes[mode&1](
                        DATA[pos|0]<<24 | DATA[pos|1]<<16 | DATA[pos|2]<<8 | DATA[pos|3],
                        DATA[pos|4]<<24 | DATA[pos|5]<<16 | DATA[pos|6]<<8 | DATA[pos|7],
                        DATA[pos|8]<<24 | DATA[pos|9]<<16 | DATA[pos|10]<<8 | DATA[pos|11],
                        DATA[pos|12]<<24 | DATA[pos|13]<<16 | DATA[pos|14]<<8 | DATA[pos|15]
                    );

                    ret = (ret + 16)|0,
                    pos = (pos + 16)|0,
                    len = (len - 16)|0;
                }

                return ret|0;
            }

            /**
             * AES cipher modes table (virual methods)
             * @private
             */
            var _cipher_modes = [ _ecb_enc, _ecb_dec, _cbc_enc, _cbc_dec, _cfb_enc, _cfb_dec, _ofb, _ctr ];

            /**
             * AES MAC modes table (virual methods)
             * @private
             */
            var _mac_modes = [ _cbc_enc, _gcm_mac ];

            /**
             * Asm.js module exports
             */
            return {
                set_rounds: set_rounds,
                set_state:  set_state,
                set_iv:     set_iv,
                set_nonce:  set_nonce,
                set_mask:   set_mask,
                set_counter:set_counter,
                get_state:  get_state,
                get_iv:     get_iv,
                gcm_init:   gcm_init,
                cipher:     cipher,
                mac:        mac
            };
        }( stdlib, foreign, buffer );

        asm.set_key = set_key;

        return asm;
    };

    /**
     * AES enciphering mode constants
     * @public
     */
    wrapper.ENC = {
        ECB: 0,
        CBC: 2,
        CFB: 4,
        OFB: 6,
        CTR: 7
    },

    /**
     * AES deciphering mode constants
     * @public
     */
    wrapper.DEC = {
        ECB: 1,
        CBC: 3,
        CFB: 5,
        OFB: 6,
        CTR: 7
    },

    /**
     * AES MAC mode constants
     * @public
     */
    wrapper.MAC = {
        CBC: 0,
        GCM: 1
    };

    /**
     * Heap data offset
     */
    wrapper.HEAP_DATA = 0x4000;

    // Prevent further modifications
    Object.freeze(wrapper);

    return wrapper;
}();
