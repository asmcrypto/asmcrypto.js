/* ----------------------------------------------------------------------
 * Copyright (c) 2014 Artem S Vybornov
 *
 * Copyright (c) 2012 Yves-Marie K. Rinquin
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ----------------------------------------------------------------------
 *
 * ISAAC is a cryptographically secure pseudo-random number generator
 * (or CSPRNG for short) designed by Robert J. Jenkins Jr. in 1996 and
 * based on RC4. It is designed for speed and security.
 *
 * ISAAC's informations & analysis:
 *   http://burtleburtle.net/bob/rand/isaac.html
 * ISAAC's implementation details:
 *   http://burtleburtle.net/bob/rand/isaacafa.html
 *
 * ISAAC succesfully passed TestU01
 */

var ISAAC = ( function () {
    var m = new Uint32Array(256), // internal memory
        r = new Uint32Array(256), // result array
        acc = 0,              // accumulator
        brs = 0,              // last result
        cnt = 0,              // counter
        gnt = 0;              // generation counter

    /* public: seeding function */
    function seed ( s ) {
        var a, b, c, d, e, f, g, h, i, j, k, n, l;

        /* private mixing function */
        function mix () {
            a ^= b <<  11; d = (d + a)|0; b = (b + c)|0;
            b ^= c >>>  2; e = (e + b)|0; c = (c + d)|0;
            c ^= d <<   8; f = (f + c)|0; d = (d + e)|0;
            d ^= e >>> 16; g = (g + d)|0; e = (e + f)|0;
            e ^= f <<  10; h = (h + e)|0; f = (f + g)|0;
            f ^= g >>>  4; a = (a + f)|0; g = (g + h)|0;
            g ^= h <<   8; b = (b + g)|0; h = (h + a)|0;
            h ^= a >>>  9; c = (c + h)|0; a = (a + b)|0;
        }

        if ( !is_typed_array(s) ) {
            if ( is_number(s) ) {
                n = new Float64Array(1), n[0] = s;
                s = new Uint8Array(n.buffer);
            }
            else if ( is_string(s) ) {
                s = string_to_bytes(s);
            }
            else if ( is_buffer(s) ) {
                s = new Uint8Array(s);
            }
            else {
                throw new TypeError("bad seed type");
            }
        }
        else {
            s = new Uint8Array(s.buffer);
        }

        // preprocess the seed
        l = s.length;
        for ( j = 0; j < l; j += 1024 )
        {
            // process seed chunk, pad with zeros up to 1024 octets
            for ( k = j, i = 0; ( i < 1024 ) && ( k < l ); k = j | (++i) ) {
                n = r[(k >> 2) & 255];
                n <<= 8, n |= s[k];
                r[(k >> 2) & 255] = n;
            }

            // the golden ratio
            a = b = c = d = e = f = g = h = 0x9e3779b9;

            // scramble it
            for ( i = 0; i < 4; i++ )
                mix();

            // mix it and combine with the internal state
            for ( i = 0; i < 256; i += 8 ) {
                a = (a + r[i|0])|0; b = (b + r[i|1])|0;
                c = (c + r[i|2])|0; d = (d + r[i|3])|0;
                e = (e + r[i|4])|0; f = (f + r[i|5])|0;
                g = (g + r[i|6])|0; h = (h + r[i|7])|0;

                mix();

                // chain with previously mixed chunk
                m[i|0] ^= a,
                m[i|1] ^= b,
                m[i|2] ^= c,
                m[i|3] ^= d,
                m[i|4] ^= e,
                m[i|5] ^= f,
                m[i|6] ^= g,
                m[i|7] ^= h;
            }

            // mix it again
            for ( i = 0; i < 256; i += 8 ) {
                a = (a + m[i|0])|0; b = (b + m[i|1])|0;
                c = (c + m[i|2])|0; d = (d + m[i|3])|0;
                e = (e + m[i|4])|0; f = (f + m[i|5])|0;
                g = (g + m[i|6])|0; h = (h + m[i|7])|0;

                mix();

                m[i|0] = a,
                m[i|1] = b,
                m[i|2] = c,
                m[i|3] = d,
                m[i|4] = e,
                m[i|5] = f,
                m[i|6] = g,
                m[i|7] = h;
            }
        }

        // fill in the first set of results
        prng(1), gnt = 256;
    }

    /* public: isaac generator, n = number of run */
    function prng ( n ) {
        n = n || 1;

        var i, x, y;

        while ( n-- ) {
            cnt = (cnt + 1)|0;
            brs = (brs + cnt)|0;

            for ( i = 0; i < 256; i += 4 ) {
                acc ^= acc << 13;
                acc = m[(i + 128) & 0xff] + acc | 0; x = m[i|0];
                m[i|0] = y = m[(x>>>2) & 0xff] + ( acc + brs | 0 ) | 0;
                r[i|0] = brs = m[(y>>>10) & 0xff] + x | 0;

                acc ^= acc >>> 6;
                acc = m[(i + 129) & 0xff] + acc | 0; x = m[i|1];
                m[i|1] = y = m[(x >>> 2) & 0xff] + ( acc + brs | 0 ) | 0;
                r[i|1] = brs = m[(y >>> 10) & 0xff] + x | 0;

                acc ^= acc << 2;
                acc = m[(i + 130) & 0xff] + acc | 0; x = m[i|2];
                m[i|2] = y = m[(x >>> 2) & 0xff] + ( acc + brs | 0 ) | 0;
                r[i|2] = brs = m[(y >>> 10) & 0xff] + x | 0;

                acc ^= acc >>> 16;
                acc = m[(i + 131) & 0xff] + acc | 0; x = m[i|3];
                m[i|3] = y = m[(x >>> 2) & 0xff] + (acc + brs | 0 ) | 0;
                r[i|3] = brs = m[(y >>> 10) & 0xff] + x | 0;
            }
        }
    }

    /* public: return a random number */
    function rand() {
        if ( !gnt-- )
            prng(1), gnt = 255;

        return r[gnt];
    }

    /* return class object */
    return {
        'seed':  seed,
        'prng':  prng,
        'rand':  rand
    };
})();
