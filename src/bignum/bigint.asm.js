// imul polyfill for IE
if ( global.Math.imul === undefined ) {
    global.Math.imul = function imul_polyfill ( a, b ) {
        return ( (a>>>0) * (b>>>0) )|0;
    }
}

/**
 * Integers are represented as little endian array of 32-bit limbs.
 * Limbs number is a power of 2 and a multiple of 8 (256 bits).
 * Negative values use two's complement representation.
 */
function bigint_asm ( stdlib, foreign, buffer ) {
    "use asm";

    var SP = 0;

    var HEAP32 = new stdlib.Uint32Array(buffer);

    var imul = stdlib.Math.imul;

    /**
     * Simple stack memory allocator
     *
     * Methods:
     *  sreset
     *  salloc
     *  sfree
     */

    function sreset ( p ) {
        p = p|0;
        SP = p = (p + 31) & -32;
        return p|0;
    }

    function salloc ( l ) {
        l = l|0;
        var p = 0; p = SP;
        SP = p + ((l + 31) & -32)|0;
        return p|0;
    }

    function sfree ( l ) {
        l = l|0;
        SP = SP - ((l + 31) & -32)|0;
    }

    /**
     * Utility functions:
     *  cp
     *  z
     */

    function cp ( l, A, B ) {
        l = l|0;
        A = A|0;
        B = B|0;

        var i = 0, Ai = 0, Bi = 0;

        if ( (A|0) > (B|0) ) {
            for ( ; (i|0) < (l|0); i = (i+4)|0 ) {
                HEAP32[(B+i)>>2] = HEAP32[(A+i)>>2];
            }
        }
        else {
            for ( i = (l-4)|0; (i|0) >= 0; i = (i-4)|0 ) {
                HEAP32[(B+i)>>2] = HEAP32[(A+i)>>2];
            }
        }
    }

    function z ( l, z, A ) {
        l = l|0;
        z = z|0;
        A = A|0;

        var i = 0, Ai = 0;

        for ( ; (i|0) < (l|0); i = (i+4)|0 ) {
            HEAP32[(A+i)>>2] = z;
        }
    }

    /**
     * Negate the argument
     *
     * Perform two's complement transformation:
     *
     *  -A = ~A + 1
     *
     * @param A offset of the argment being negated, 32-byte aligned
     * @param lA length of the argument, multiple of 32
     *
     * @param R offset where to place the result to, 32-byte aligned
     * @param lR length to truncate the result to, multiple of 32
     */
    function neg ( A, lA, R, lR ) {
        A  =  A|0;
        lA = lA|0;
        R  =  R|0;
        lR = lR|0;

        var a = 0, c = 0, t = 0, r = 0, i = 0;

        if ( (lR|0) <= 0 )
            lR = lA;

        if ( (lR|0) < (lA|0) )
            lA = lR;

        c = 1;
        for ( ; (i|0) < (lA|0); i = (i+4)|0 ) {
            a = ~HEAP32[(A+i)>>2];
            t = (a & 0xffff) + c|0;
            r = (a >>> 16) + (t >>> 16)|0;
            HEAP32[(R+i)>>2] = (r << 16) | (t & 0xffff);
            c = r >>> 16;
        }

        for ( ; (i|0) < (lR|0); i = (i+4)|0 ) {
            HEAP32[(R+i)>>2] = (c-1)|0;
        }

        return c|0;
    }

    function cmp ( A, lA, B, lB ) {
        A  =  A|0;
        lA = lA|0;
        B  =  B|0;
        lB = lB|0;

        var a = 0, b = 0, i = 0;

        if ( (lA|0) > (lB|0) ) {
            for ( i = (lA-4)|0; (i|0) >= (lB|0); i = (i-4)|0 ) {
                if ( HEAP32[(A+i)>>2]|0 ) return 1;
            }
        }
        else {
            for ( i = (lB-4)|0; (i|0) >= (lA|0); i = (i-4)|0 ) {
                if ( HEAP32[(B+i)>>2]|0 ) return -1;
            }
        }

        for ( ; (i|0) >= 0; i = (i-4)|0 ) {
            a = HEAP32[(A+i)>>2]>>>0, b = HEAP32[(B+i)>>2]>>>0;
            if ( (a>>>0) < (b>>>0) ) return -1;
            if ( (a>>>0) > (b>>>0) ) return 1;
        }

        return 0;
    }

    /**
     * Test the argument
     *
     * Same as `cmp` with zero.
     */
    function tst ( A, lA ) {
        A  =  A|0;
        lA = lA|0;

        var i = 0;

        for ( i = (lA-4)|0; (i|0) >= 0; i = (i-4)|0 ) {
            if ( HEAP32[(A+i)>>2]|0 ) return (i+4)|0;
        }

        return 0;
    }

    /**
     * Conventional addition
     *
     * @param A offset of the first argument, 32-byte aligned
     * @param lA length of the first argument, multiple of 32
     *
     * @param B offset of the second argument, 32-bit aligned
     * @param lB length of the second argument, multiple of 32
     *
     * @param R offset where to place the result to, 32-byte aligned
     * @param lR length to truncate the result to, multiple of 32
     */
    function add ( A, lA, B, lB, R, lR ) {
        A  =  A|0;
        lA = lA|0;
        B  =  B|0;
        lB = lB|0;
        R  =  R|0;
        lR = lR|0;

        var a = 0, b = 0, c = 0, t = 0, r = 0, i = 0;

        if ( (lA|0) < (lB|0) ) {
            t = A, A = B, B = t;
            t = lA, lA = lB, lB = t;
        }

        if ( (lR|0) <= 0 )
            lR = lA+4|0;

        if ( (lR|0) < (lB|0) )
            lA = lB = lR;

        for ( ; (i|0) < (lB|0); i = (i+4)|0 ) {
            a = HEAP32[(A+i)>>2]|0;
            b = HEAP32[(B+i)>>2]|0;
            t = ( (a & 0xffff) + (b & 0xffff)|0 ) + c|0;
            r = ( (a >>> 16) + (b >>> 16)|0 ) + (t >>> 16)|0;
            HEAP32[(R+i)>>2] = (t & 0xffff) | (r << 16);
            c = r >>> 16;
        }

        for ( ; (i|0) < (lA|0); i = (i+4)|0 ) {
            a = HEAP32[(A+i)>>2]|0;
            t = (a & 0xffff) + c|0;
            r = (a >>> 16) + (t >>> 16)|0;
            HEAP32[(R+i)>>2] = (t & 0xffff) | (r << 16);
            c = r >>> 16;
        }

        for ( ; (i|0) < (lR|0); i = (i+4)|0 ) {
            HEAP32[(R+i)>>2] = c|0;
            c = 0;
        }

        return c|0;
    }

   /**
     * Conventional subtraction
     *
     * @param A offset of the first argument, 32-byte aligned
     * @param lA length of the first argument, multiple of 32
     *
     * @param B offset of the second argument, 32-bit aligned
     * @param lB length of the second argument, multiple of 32
     *
     * @param R offset where to place the result to, 32-byte aligned
     * @param lR length to truncate the result to, multiple of 32
     */
    function sub ( A, lA, B, lB, R, lR ) {
        A  =  A|0;
        lA = lA|0;
        B  =  B|0;
        lB = lB|0;
        R  =  R|0;
        lR = lR|0;

        var a = 0, b = 0, c = 0, t = 0, r = 0, i = 0;

        if ( (lR|0) <= 0 )
            lR = (lA|0) > (lB|0) ? lA+4|0 : lB+4|0;

        if ( (lR|0) < (lA|0) )
            lA = lR;

        if ( (lR|0) < (lB|0) )
            lB = lR;

        if ( (lA|0) < (lB|0) ) {
            for ( ; (i|0) < (lA|0); i = (i+4)|0 ) {
                a = HEAP32[(A+i)>>2]|0;
                b = HEAP32[(B+i)>>2]|0;
                t = ( (a & 0xffff) - (b & 0xffff)|0 ) + c|0;
                r = ( (a >>> 16) - (b >>> 16)|0 ) + (t >> 16)|0;
                HEAP32[(R+i)>>2] = (t & 0xffff) | (r << 16);
                c = r >> 16;
            }

            for ( ; (i|0) < (lB|0); i = (i+4)|0 ) {
                b = HEAP32[(B+i)>>2]|0;
                t = c - (b & 0xffff)|0;
                r = (t >> 16) - (b >>> 16)|0;
                HEAP32[(R+i)>>2] = (t & 0xffff) | (r << 16);
                c = r >> 16;
            }
        }
        else {
            for ( ; (i|0) < (lB|0); i = (i+4)|0 ) {
                a = HEAP32[(A+i)>>2]|0;
                b = HEAP32[(B+i)>>2]|0;
                t = ( (a & 0xffff) - (b & 0xffff)|0 ) + c|0;
                r = ( (a >>> 16) - (b >>> 16)|0 ) + (t >> 16)|0;
                HEAP32[(R+i)>>2] = (t & 0xffff) | (r << 16);
                c = r >> 16;
            }

            for ( ; (i|0) < (lA|0); i = (i+4)|0 ) {
                a = HEAP32[(A+i)>>2]|0;
                t = (a & 0xffff) + c|0;
                r = (a >>> 16) + (t >> 16)|0;
                HEAP32[(R+i)>>2] = (t & 0xffff) | (r << 16);
                c = r >> 16;
            }
        }

        for ( ; (i|0) < (lR|0); i = (i+4)|0 ) {
            HEAP32[(R+i)>>2] = c|0;
        }

        return c|0;
    }

    /**
     * Conventional multiplication
     *
     * TODO implement Karatsuba algorithm for large multiplicands
     *
     * @param A offset of the first argument, 32-byte aligned
     * @param lA length of the first argument, multiple of 32
     *
     * @param B offset of the second argument, 32-byte aligned
     * @param lB length of the second argument, multiple of 32
     *
     * @param R offset where to place the result to, 32-byte aligned
     * @param lR length to truncate the result to, multiple of 32
     */
    function mul ( A, lA, B, lB, R, lR ) {
        A  =  A|0;
        lA = lA|0;
        B  =  B|0;
        lB = lB|0;
        R  =  R|0;
        lR = lR|0;

        var al0 = 0, al1 = 0, al2 = 0, al3 = 0, al4 = 0, al5 = 0, al6 = 0, al7 = 0, ah0 = 0, ah1 = 0, ah2 = 0, ah3 = 0, ah4 = 0, ah5 = 0, ah6 = 0, ah7 = 0,
            bl0 = 0, bl1 = 0, bl2 = 0, bl3 = 0, bl4 = 0, bl5 = 0, bl6 = 0, bl7 = 0, bh0 = 0, bh1 = 0, bh2 = 0, bh3 = 0, bh4 = 0, bh5 = 0, bh6 = 0, bh7 = 0,
            r0 = 0, r1 = 0, r2 = 0, r3 = 0, r4 = 0, r5 = 0, r6 = 0, r7 = 0, r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0,
            u = 0, v = 0, w = 0, m = 0,
            i = 0, Ai = 0, j = 0, Bj = 0, Rk = 0;

        if ( (lA|0) > (lB|0) ) {
            u = A, v = lA;
            A = B, lA = lB;
            B = u, lB = v;
        }

        m = (lA+lB)|0;
        if ( ( (lR|0) > (m|0) ) | ( (lR|0) <= 0 ) )
            lR = m;

        if ( (lR|0) < (lA|0) )
            lA = lR;

        if ( (lR|0) < (lB|0) )
            lB = lR;

        for ( ; (i|0) < (lA|0); i = (i+32)|0 ) {
            Ai = (A+i)|0;

            ah0 = HEAP32[(Ai|0)>>2]|0,
            ah1 = HEAP32[(Ai|4)>>2]|0,
            ah2 = HEAP32[(Ai|8)>>2]|0,
            ah3 = HEAP32[(Ai|12)>>2]|0,
            ah4 = HEAP32[(Ai|16)>>2]|0,
            ah5 = HEAP32[(Ai|20)>>2]|0,
            ah6 = HEAP32[(Ai|24)>>2]|0,
            ah7 = HEAP32[(Ai|28)>>2]|0,
            al0 = ah0 & 0xffff,
            al1 = ah1 & 0xffff,
            al2 = ah2 & 0xffff,
            al3 = ah3 & 0xffff,
            al4 = ah4 & 0xffff,
            al5 = ah5 & 0xffff,
            al6 = ah6 & 0xffff,
            al7 = ah7 & 0xffff,
            ah0 = ah0 >>> 16,
            ah1 = ah1 >>> 16,
            ah2 = ah2 >>> 16,
            ah3 = ah3 >>> 16,
            ah4 = ah4 >>> 16,
            ah5 = ah5 >>> 16,
            ah6 = ah6 >>> 16,
            ah7 = ah7 >>> 16;

            r8 = r9 = r10 = r11 = r12 = r13 = r14 = r15 = 0;

            for ( j = 0; (j|0) < (lB|0); j = (j+32)|0 ) {
                Bj = (B+j)|0;
                Rk = (R+(i+j|0))|0;

                bh0 = HEAP32[(Bj|0)>>2]|0,
                bh1 = HEAP32[(Bj|4)>>2]|0,
                bh2 = HEAP32[(Bj|8)>>2]|0,
                bh3 = HEAP32[(Bj|12)>>2]|0,
                bh4 = HEAP32[(Bj|16)>>2]|0,
                bh5 = HEAP32[(Bj|20)>>2]|0,
                bh6 = HEAP32[(Bj|24)>>2]|0,
                bh7 = HEAP32[(Bj|28)>>2]|0,
                bl0 = bh0 & 0xffff,
                bl1 = bh1 & 0xffff,
                bl2 = bh2 & 0xffff,
                bl3 = bh3 & 0xffff,
                bl4 = bh4 & 0xffff,
                bl5 = bh5 & 0xffff,
                bl6 = bh6 & 0xffff,
                bl7 = bh7 & 0xffff,
                bh0 = bh0 >>> 16,
                bh1 = bh1 >>> 16,
                bh2 = bh2 >>> 16,
                bh3 = bh3 >>> 16,
                bh4 = bh4 >>> 16,
                bh5 = bh5 >>> 16,
                bh6 = bh6 >>> 16,
                bh7 = bh7 >>> 16;

                r0 = HEAP32[(Rk|0)>>2]|0,
                r1 = HEAP32[(Rk|4)>>2]|0,
                r2 = HEAP32[(Rk|8)>>2]|0,
                r3 = HEAP32[(Rk|12)>>2]|0,
                r4 = HEAP32[(Rk|16)>>2]|0,
                r5 = HEAP32[(Rk|20)>>2]|0,
                r6 = HEAP32[(Rk|24)>>2]|0,
                r7 = HEAP32[(Rk|28)>>2]|0;

                u = ((imul(al0, bl0)|0) + (r8 & 0xffff)|0) + (r0 & 0xffff)|0;
                v = ((imul(ah0, bl0)|0) + (r8 >>> 16)|0) + (r0 >>> 16)|0;
                w = ((imul(al0, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r0 = (w << 16) | (u & 0xffff);

                u = ((imul(al0, bl1)|0) + (m & 0xffff)|0) + (r1 & 0xffff)|0;
                v = ((imul(ah0, bl1)|0) + (m >>> 16)|0) + (r1 >>> 16)|0;
                w = ((imul(al0, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r1 = (w << 16) | (u & 0xffff);

                u = ((imul(al0, bl2)|0) + (m & 0xffff)|0) + (r2 & 0xffff)|0;
                v = ((imul(ah0, bl2)|0) + (m >>> 16)|0) + (r2 >>> 16)|0;
                w = ((imul(al0, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r2 = (w << 16) | (u & 0xffff);

                u = ((imul(al0, bl3)|0) + (m & 0xffff)|0) + (r3 & 0xffff)|0;
                v = ((imul(ah0, bl3)|0) + (m >>> 16)|0) + (r3 >>> 16)|0;
                w = ((imul(al0, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r3 = (w << 16) | (u & 0xffff);

                u = ((imul(al0, bl4)|0) + (m & 0xffff)|0) + (r4 & 0xffff)|0;
                v = ((imul(ah0, bl4)|0) + (m >>> 16)|0) + (r4 >>> 16)|0;
                w = ((imul(al0, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r4 = (w << 16) | (u & 0xffff);

                u = ((imul(al0, bl5)|0) + (m & 0xffff)|0) + (r5 & 0xffff)|0;
                v = ((imul(ah0, bl5)|0) + (m >>> 16)|0) + (r5 >>> 16)|0;
                w = ((imul(al0, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r5 = (w << 16) | (u & 0xffff);

                u = ((imul(al0, bl6)|0) + (m & 0xffff)|0) + (r6 & 0xffff)|0;
                v = ((imul(ah0, bl6)|0) + (m >>> 16)|0) + (r6 >>> 16)|0;
                w = ((imul(al0, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r6 = (w << 16) | (u & 0xffff);

                u = ((imul(al0, bl7)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                v = ((imul(ah0, bl7)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                w = ((imul(al0, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r7 = (w << 16) | (u & 0xffff);

                r8 = m;

                u = ((imul(al1, bl0)|0) + (r9 & 0xffff)|0) + (r1 & 0xffff)|0;
                v = ((imul(ah1, bl0)|0) + (r9 >>> 16)|0) + (r1 >>> 16)|0;
                w = ((imul(al1, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r1 = (w << 16) | (u & 0xffff);

                u = ((imul(al1, bl1)|0) + (m & 0xffff)|0) + (r2 & 0xffff)|0;
                v = ((imul(ah1, bl1)|0) + (m >>> 16)|0) + (r2 >>> 16)|0;
                w = ((imul(al1, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r2 = (w << 16) | (u & 0xffff);

                u = ((imul(al1, bl2)|0) + (m & 0xffff)|0) + (r3 & 0xffff)|0;
                v = ((imul(ah1, bl2)|0) + (m >>> 16)|0) + (r3 >>> 16)|0;
                w = ((imul(al1, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r3 = (w << 16) | (u & 0xffff);

                u = ((imul(al1, bl3)|0) + (m & 0xffff)|0) + (r4 & 0xffff)|0;
                v = ((imul(ah1, bl3)|0) + (m >>> 16)|0) + (r4 >>> 16)|0;
                w = ((imul(al1, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r4 = (w << 16) | (u & 0xffff);

                u = ((imul(al1, bl4)|0) + (m & 0xffff)|0) + (r5 & 0xffff)|0;
                v = ((imul(ah1, bl4)|0) + (m >>> 16)|0) + (r5 >>> 16)|0;
                w = ((imul(al1, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r5 = (w << 16) | (u & 0xffff);

                u = ((imul(al1, bl5)|0) + (m & 0xffff)|0) + (r6 & 0xffff)|0;
                v = ((imul(ah1, bl5)|0) + (m >>> 16)|0) + (r6 >>> 16)|0;
                w = ((imul(al1, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r6 = (w << 16) | (u & 0xffff);

                u = ((imul(al1, bl6)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                v = ((imul(ah1, bl6)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                w = ((imul(al1, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r7 = (w << 16) | (u & 0xffff);

                u = ((imul(al1, bl7)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                v = ((imul(ah1, bl7)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                w = ((imul(al1, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r8 = (w << 16) | (u & 0xffff);

                r9 = m;

                u = ((imul(al2, bl0)|0) + (r10 & 0xffff)|0) + (r2 & 0xffff)|0;
                v = ((imul(ah2, bl0)|0) + (r10 >>> 16)|0) + (r2 >>> 16)|0;
                w = ((imul(al2, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah2, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r2 = (w << 16) | (u & 0xffff);

                u = ((imul(al2, bl1)|0) + (m & 0xffff)|0) + (r3 & 0xffff)|0;
                v = ((imul(ah2, bl1)|0) + (m >>> 16)|0) + (r3 >>> 16)|0;
                w = ((imul(al2, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah2, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r3 = (w << 16) | (u & 0xffff);

                u = ((imul(al2, bl2)|0) + (m & 0xffff)|0) + (r4 & 0xffff)|0;
                v = ((imul(ah2, bl2)|0) + (m >>> 16)|0) + (r4 >>> 16)|0;
                w = ((imul(al2, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah2, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r4 = (w << 16) | (u & 0xffff);

                u = ((imul(al2, bl3)|0) + (m & 0xffff)|0) + (r5 & 0xffff)|0;
                v = ((imul(ah2, bl3)|0) + (m >>> 16)|0) + (r5 >>> 16)|0;
                w = ((imul(al2, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah2, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r5 = (w << 16) | (u & 0xffff);

                u = ((imul(al2, bl4)|0) + (m & 0xffff)|0) + (r6 & 0xffff)|0;
                v = ((imul(ah2, bl4)|0) + (m >>> 16)|0) + (r6 >>> 16)|0;
                w = ((imul(al2, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah2, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r6 = (w << 16) | (u & 0xffff);

                u = ((imul(al2, bl5)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                v = ((imul(ah2, bl5)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                w = ((imul(al2, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah2, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r7 = (w << 16) | (u & 0xffff);

                u = ((imul(al2, bl6)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                v = ((imul(ah2, bl6)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                w = ((imul(al2, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah2, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r8 = (w << 16) | (u & 0xffff);

                u = ((imul(al2, bl7)|0) + (m & 0xffff)|0) + (r9 & 0xffff)|0;
                v = ((imul(ah2, bl7)|0) + (m >>> 16)|0) + (r9 >>> 16)|0;
                w = ((imul(al2, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah2, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r9 = (w << 16) | (u & 0xffff);

                r10 = m;

                u = ((imul(al3, bl0)|0) + (r11 & 0xffff)|0) + (r3 & 0xffff)|0;
                v = ((imul(ah3, bl0)|0) + (r11 >>> 16)|0) + (r3 >>> 16)|0;
                w = ((imul(al3, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah3, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r3 = (w << 16) | (u & 0xffff);

                u = ((imul(al3, bl1)|0) + (m & 0xffff)|0) + (r4 & 0xffff)|0;
                v = ((imul(ah3, bl1)|0) + (m >>> 16)|0) + (r4 >>> 16)|0;
                w = ((imul(al3, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah3, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r4 = (w << 16) | (u & 0xffff);

                u = ((imul(al3, bl2)|0) + (m & 0xffff)|0) + (r5 & 0xffff)|0;
                v = ((imul(ah3, bl2)|0) + (m >>> 16)|0) + (r5 >>> 16)|0;
                w = ((imul(al3, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah3, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r5 = (w << 16) | (u & 0xffff);

                u = ((imul(al3, bl3)|0) + (m & 0xffff)|0) + (r6 & 0xffff)|0;
                v = ((imul(ah3, bl3)|0) + (m >>> 16)|0) + (r6 >>> 16)|0;
                w = ((imul(al3, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah3, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r6 = (w << 16) | (u & 0xffff);

                u = ((imul(al3, bl4)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                v = ((imul(ah3, bl4)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                w = ((imul(al3, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah3, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r7 = (w << 16) | (u & 0xffff);

                u = ((imul(al3, bl5)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                v = ((imul(ah3, bl5)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                w = ((imul(al3, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah3, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r8 = (w << 16) | (u & 0xffff);

                u = ((imul(al3, bl6)|0) + (m & 0xffff)|0) + (r9 & 0xffff)|0;
                v = ((imul(ah3, bl6)|0) + (m >>> 16)|0) + (r9 >>> 16)|0;
                w = ((imul(al3, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah3, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r9 = (w << 16) | (u & 0xffff);

                u = ((imul(al3, bl7)|0) + (m & 0xffff)|0) + (r10 & 0xffff)|0;
                v = ((imul(ah3, bl7)|0) + (m >>> 16)|0) + (r10 >>> 16)|0;
                w = ((imul(al3, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah3, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r10 = (w << 16) | (u & 0xffff);

                r11 = m;

                u = ((imul(al4, bl0)|0) + (r12 & 0xffff)|0) + (r4 & 0xffff)|0;
                v = ((imul(ah4, bl0)|0) + (r12 >>> 16)|0) + (r4 >>> 16)|0;
                w = ((imul(al4, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah4, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r4 = (w << 16) | (u & 0xffff);

                u = ((imul(al4, bl1)|0) + (m & 0xffff)|0) + (r5 & 0xffff)|0;
                v = ((imul(ah4, bl1)|0) + (m >>> 16)|0) + (r5 >>> 16)|0;
                w = ((imul(al4, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah4, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r5 = (w << 16) | (u & 0xffff);

                u = ((imul(al4, bl2)|0) + (m & 0xffff)|0) + (r6 & 0xffff)|0;
                v = ((imul(ah4, bl2)|0) + (m >>> 16)|0) + (r6 >>> 16)|0;
                w = ((imul(al4, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah4, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r6 = (w << 16) | (u & 0xffff);

                u = ((imul(al4, bl3)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                v = ((imul(ah4, bl3)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                w = ((imul(al4, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah4, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r7 = (w << 16) | (u & 0xffff);

                u = ((imul(al4, bl4)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                v = ((imul(ah4, bl4)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                w = ((imul(al4, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah4, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r8 = (w << 16) | (u & 0xffff);

                u = ((imul(al4, bl5)|0) + (m & 0xffff)|0) + (r9 & 0xffff)|0;
                v = ((imul(ah4, bl5)|0) + (m >>> 16)|0) + (r9 >>> 16)|0;
                w = ((imul(al4, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah4, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r9 = (w << 16) | (u & 0xffff);

                u = ((imul(al4, bl6)|0) + (m & 0xffff)|0) + (r10 & 0xffff)|0;
                v = ((imul(ah4, bl6)|0) + (m >>> 16)|0) + (r10 >>> 16)|0;
                w = ((imul(al4, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah4, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r10 = (w << 16) | (u & 0xffff);

                u = ((imul(al4, bl7)|0) + (m & 0xffff)|0) + (r11 & 0xffff)|0;
                v = ((imul(ah4, bl7)|0) + (m >>> 16)|0) + (r11 >>> 16)|0;
                w = ((imul(al4, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah4, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r11 = (w << 16) | (u & 0xffff);

                r12 = m;

                u = ((imul(al5, bl0)|0) + (r13 & 0xffff)|0) + (r5 & 0xffff)|0;
                v = ((imul(ah5, bl0)|0) + (r13 >>> 16)|0) + (r5 >>> 16)|0;
                w = ((imul(al5, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah5, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r5 = (w << 16) | (u & 0xffff);

                u = ((imul(al5, bl1)|0) + (m & 0xffff)|0) + (r6 & 0xffff)|0;
                v = ((imul(ah5, bl1)|0) + (m >>> 16)|0) + (r6 >>> 16)|0;
                w = ((imul(al5, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah5, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r6 = (w << 16) | (u & 0xffff);

                u = ((imul(al5, bl2)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                v = ((imul(ah5, bl2)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                w = ((imul(al5, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah5, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r7 = (w << 16) | (u & 0xffff);

                u = ((imul(al5, bl3)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                v = ((imul(ah5, bl3)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                w = ((imul(al5, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah5, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r8 = (w << 16) | (u & 0xffff);

                u = ((imul(al5, bl4)|0) + (m & 0xffff)|0) + (r9 & 0xffff)|0;
                v = ((imul(ah5, bl4)|0) + (m >>> 16)|0) + (r9 >>> 16)|0;
                w = ((imul(al5, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah5, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r9 = (w << 16) | (u & 0xffff);

                u = ((imul(al5, bl5)|0) + (m & 0xffff)|0) + (r10 & 0xffff)|0;
                v = ((imul(ah5, bl5)|0) + (m >>> 16)|0) + (r10 >>> 16)|0;
                w = ((imul(al5, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah5, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r10 = (w << 16) | (u & 0xffff);

                u = ((imul(al5, bl6)|0) + (m & 0xffff)|0) + (r11 & 0xffff)|0;
                v = ((imul(ah5, bl6)|0) + (m >>> 16)|0) + (r11 >>> 16)|0;
                w = ((imul(al5, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah5, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r11 = (w << 16) | (u & 0xffff);

                u = ((imul(al5, bl7)|0) + (m & 0xffff)|0) + (r12 & 0xffff)|0;
                v = ((imul(ah5, bl7)|0) + (m >>> 16)|0) + (r12 >>> 16)|0;
                w = ((imul(al5, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah5, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r12 = (w << 16) | (u & 0xffff);

                r13 = m;

                u = ((imul(al6, bl0)|0) + (r14 & 0xffff)|0) + (r6 & 0xffff)|0;
                v = ((imul(ah6, bl0)|0) + (r14 >>> 16)|0) + (r6 >>> 16)|0;
                w = ((imul(al6, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah6, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r6 = (w << 16) | (u & 0xffff);

                u = ((imul(al6, bl1)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                v = ((imul(ah6, bl1)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                w = ((imul(al6, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah6, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r7 = (w << 16) | (u & 0xffff);

                u = ((imul(al6, bl2)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                v = ((imul(ah6, bl2)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                w = ((imul(al6, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah6, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r8 = (w << 16) | (u & 0xffff);

                u = ((imul(al6, bl3)|0) + (m & 0xffff)|0) + (r9 & 0xffff)|0;
                v = ((imul(ah6, bl3)|0) + (m >>> 16)|0) + (r9 >>> 16)|0;
                w = ((imul(al6, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah6, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r9 = (w << 16) | (u & 0xffff);

                u = ((imul(al6, bl4)|0) + (m & 0xffff)|0) + (r10 & 0xffff)|0;
                v = ((imul(ah6, bl4)|0) + (m >>> 16)|0) + (r10 >>> 16)|0;
                w = ((imul(al6, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah6, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r10 = (w << 16) | (u & 0xffff);

                u = ((imul(al6, bl5)|0) + (m & 0xffff)|0) + (r11 & 0xffff)|0;
                v = ((imul(ah6, bl5)|0) + (m >>> 16)|0) + (r11 >>> 16)|0;
                w = ((imul(al6, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah6, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r11 = (w << 16) | (u & 0xffff);

                u = ((imul(al6, bl6)|0) + (m & 0xffff)|0) + (r12 & 0xffff)|0;
                v = ((imul(ah6, bl6)|0) + (m >>> 16)|0) + (r12 >>> 16)|0;
                w = ((imul(al6, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah6, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r12 = (w << 16) | (u & 0xffff);

                u = ((imul(al6, bl7)|0) + (m & 0xffff)|0) + (r13 & 0xffff)|0;
                v = ((imul(ah6, bl7)|0) + (m >>> 16)|0) + (r13 >>> 16)|0;
                w = ((imul(al6, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah6, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r13 = (w << 16) | (u & 0xffff);

                r14 = m;

                u = ((imul(al7, bl0)|0) + (r15 & 0xffff)|0) + (r7 & 0xffff)|0;
                v = ((imul(ah7, bl0)|0) + (r15 >>> 16)|0) + (r7 >>> 16)|0;
                w = ((imul(al7, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah7, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r7 = (w << 16) | (u & 0xffff);

                u = ((imul(al7, bl1)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                v = ((imul(ah7, bl1)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                w = ((imul(al7, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah7, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r8 = (w << 16) | (u & 0xffff);

                u = ((imul(al7, bl2)|0) + (m & 0xffff)|0) + (r9 & 0xffff)|0;
                v = ((imul(ah7, bl2)|0) + (m >>> 16)|0) + (r9 >>> 16)|0;
                w = ((imul(al7, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah7, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r9 = (w << 16) | (u & 0xffff);

                u = ((imul(al7, bl3)|0) + (m & 0xffff)|0) + (r10 & 0xffff)|0;
                v = ((imul(ah7, bl3)|0) + (m >>> 16)|0) + (r10 >>> 16)|0;
                w = ((imul(al7, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah7, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r10 = (w << 16) | (u & 0xffff);

                u = ((imul(al7, bl4)|0) + (m & 0xffff)|0) + (r11 & 0xffff)|0;
                v = ((imul(ah7, bl4)|0) + (m >>> 16)|0) + (r11 >>> 16)|0;
                w = ((imul(al7, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah7, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r11 = (w << 16) | (u & 0xffff);

                u = ((imul(al7, bl5)|0) + (m & 0xffff)|0) + (r12 & 0xffff)|0;
                v = ((imul(ah7, bl5)|0) + (m >>> 16)|0) + (r12 >>> 16)|0;
                w = ((imul(al7, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah7, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r12 = (w << 16) | (u & 0xffff);

                u = ((imul(al7, bl6)|0) + (m & 0xffff)|0) + (r13 & 0xffff)|0;
                v = ((imul(ah7, bl6)|0) + (m >>> 16)|0) + (r13 >>> 16)|0;
                w = ((imul(al7, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah7, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r13 = (w << 16) | (u & 0xffff);

                u = ((imul(al7, bl7)|0) + (m & 0xffff)|0) + (r14 & 0xffff)|0;
                v = ((imul(ah7, bl7)|0) + (m >>> 16)|0) + (r14 >>> 16)|0;
                w = ((imul(al7, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah7, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r14 = (w << 16) | (u & 0xffff);

                r15 = m;

                HEAP32[(Rk|0)>>2] = r0,
                HEAP32[(Rk|4)>>2] = r1,
                HEAP32[(Rk|8)>>2] = r2,
                HEAP32[(Rk|12)>>2] = r3,
                HEAP32[(Rk|16)>>2] = r4,
                HEAP32[(Rk|20)>>2] = r5,
                HEAP32[(Rk|24)>>2] = r6,
                HEAP32[(Rk|28)>>2] = r7;
            }

            Rk = (R+(i+j|0))|0;
            HEAP32[(Rk|0)>>2] = r8,
            HEAP32[(Rk|4)>>2] = r9,
            HEAP32[(Rk|8)>>2] = r10,
            HEAP32[(Rk|12)>>2] = r11,
            HEAP32[(Rk|16)>>2] = r12,
            HEAP32[(Rk|20)>>2] = r13,
            HEAP32[(Rk|24)>>2] = r14,
            HEAP32[(Rk|28)>>2] = r15;
        }
/*
        for ( i = lA & -32; (i|0) < (lA|0); i = (i+4)|0 ) {
            Ai = (A+i)|0;

            ah0 = HEAP32[Ai>>2]|0,
            al0 = ah0 & 0xffff,
            ah0 = ah0 >>> 16;

            r1 = 0;

            for ( j = 0; (j|0) < (lB|0); j = (j+4)|0 ) {
                Bj = (B+j)|0;
                Rk = (R+(i+j|0))|0;

                bh0 = HEAP32[Bj>>2]|0,
                bl0 = bh0 & 0xffff,
                bh0 = bh0 >>> 16;

                r0 = HEAP32[Rk>>2]|0;

                u = ((imul(al0, bl0)|0) + (r1 & 0xffff)|0) + (r0 & 0xffff)|0;
                v = ((imul(ah0, bl0)|0) + (r1 >>> 16)|0) + (r0 >>> 16)|0;
                w = ((imul(al0, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r0 = (w << 16) | (u & 0xffff);

                r1 = m;

                HEAP32[Rk>>2] = r0;
            }

            Rk = (R+(i+j|0))|0;
            HEAP32[Rk>>2] = r1;
        }
*/
    }

    /**
     * Fast squaring
     *
     * Exploits the fact:
     *
     *  X² = ( X0 + X1*B )² = X0² + 2*X0*X1*B + X1²*B²,
     *
     * where B is a power of 2, so:
     *
     *  2*X0*X1*B = (X0*X1 << 1)*B
     *
     * @param A offset of the argument being squared, 32-byte aligned
     * @param lA length of the argument, multiple of 32
     *
     * @param R offset where to place the result to, 32-byte aligned
     */
    function sqr ( A, lA, R ) {
        A  =  A|0;
        lA = lA|0;
        R  =  R|0;

        var al0 = 0, al1 = 0, al2 = 0, al3 = 0, al4 = 0, al5 = 0, al6 = 0, al7 = 0, ah0 = 0, ah1 = 0, ah2 = 0, ah3 = 0, ah4 = 0, ah5 = 0, ah6 = 0, ah7 = 0,
            bl0 = 0, bl1 = 0, bl2 = 0, bl3 = 0, bl4 = 0, bl5 = 0, bl6 = 0, bl7 = 0, bh0 = 0, bh1 = 0, bh2 = 0, bh3 = 0, bh4 = 0, bh5 = 0, bh6 = 0, bh7 = 0,
            r0 = 0, r1 = 0, r2 = 0, r3 = 0, r4 = 0, r5 = 0, r6 = 0, r7 = 0, r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0,
            u = 0, v = 0, w = 0, c = 0, h = 0, m = 0, r = 0,
            d = 0, dd = 0, p = 0, i = 0, j = 0, k = 0, Ai = 0, Aj = 0, Rk = 0;

        // prepare for iterations
        for ( ; (i|0) < (lA|0); i = (i+4)|0 ) {
            Rk = R+(i<<1)|0;
            ah0 = HEAP32[(A+i)>>2]|0, al0 = ah0 & 0xffff, ah0 = ah0 >>> 16;
            u = imul(al0,al0)|0;
            v = (imul(al0,ah0)|0) + (u >>> 17)|0;
            w = (imul(ah0,ah0)|0) + (v >>> 15)|0;
            HEAP32[(Rk)>>2] = (v << 17) | (u & 0x1ffff);
            HEAP32[(Rk|4)>>2] = w;
        }

        // unrolled 1st iteration
        for ( p = 0; (p|0) < (lA|0); p = (p+8)|0 ) {
            Ai = A+p|0, Rk = R+(p<<1)|0;

            ah0 = HEAP32[(Ai)>>2]|0, al0 = ah0 & 0xffff, ah0 = ah0 >>> 16;

            bh0 = HEAP32[(Ai|4)>>2]|0, bl0 = bh0 & 0xffff, bh0 = bh0 >>> 16;

            u = imul(al0,bl0)|0;
            v = (imul(al0,bh0)|0) + (u >>> 16)|0;
            w = (imul(ah0,bl0)|0) + (v & 0xffff)|0;
            m = ((imul(ah0,bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;

            r = HEAP32[(Rk|4)>>2]|0;
            u = (r & 0xffff) + ((u & 0xffff) << 1)|0;
            w = ((r >>> 16) + ((w & 0xffff) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk|4)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            r = HEAP32[(Rk|8)>>2]|0;
            u = ((r & 0xffff) + ((m & 0xffff) << 1)|0) + c|0;
            w = ((r >>> 16) + ((m >>> 16) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk|8)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            if ( c ) {
                r = HEAP32[(Rk|12)>>2]|0;
                u = (r & 0xffff) + c|0;
                w = (r >>> 16) + (u >>> 16)|0;
                HEAP32[(Rk|12)>>2] = (w << 16) | (u & 0xffff);
            }
        }

        // unrolled 2nd iteration
        for ( p = 0; (p|0) < (lA|0); p = (p+16)|0 ) {
            Ai = A+p|0, Rk = R+(p<<1)|0;

            ah0 = HEAP32[(Ai)>>2]|0, al0 = ah0 & 0xffff, ah0 = ah0 >>> 16,
            ah1 = HEAP32[(Ai|4)>>2]|0, al1 = ah1 & 0xffff, ah1 = ah1 >>> 16;

            bh0 = HEAP32[(Ai|8)>>2]|0, bl0 = bh0 & 0xffff, bh0 = bh0 >>> 16,
            bh1 = HEAP32[(Ai|12)>>2]|0, bl1 = bh1 & 0xffff, bh1 = bh1 >>> 16;

            u = imul(al0, bl0)|0;
            v = imul(ah0, bl0)|0;
            w = ((imul(al0, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah0, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r0 = (w << 16) | (u & 0xffff);

            u = (imul(al0, bl1)|0) + (m & 0xffff)|0;
            v = (imul(ah0, bl1)|0) + (m >>> 16)|0;
            w = ((imul(al0, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah0, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r1 = (w << 16) | (u & 0xffff);

            r2 = m;

            u = (imul(al1, bl0)|0) + (r1 & 0xffff)|0;
            v = (imul(ah1, bl0)|0) + (r1 >>> 16)|0;
            w = ((imul(al1, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah1, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r1 = (w << 16) | (u & 0xffff);

            u = ((imul(al1, bl1)|0) + (r2 & 0xffff)|0) + (m & 0xffff)|0;
            v = ((imul(ah1, bl1)|0) + (r2 >>> 16)|0) + (m >>> 16)|0;
            w = ((imul(al1, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah1, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r2 = (w << 16) | (u & 0xffff);

            r3 = m;

            r = HEAP32[(Rk|8)>>2]|0;
            u = (r & 0xffff) + ((r0 & 0xffff) << 1)|0;
            w = ((r >>> 16) + ((r0 >>> 16) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk|8)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            r = HEAP32[(Rk|12)>>2]|0;
            u = ((r & 0xffff) + ((r1 & 0xffff) << 1)|0)  + c|0;
            w = ((r >>> 16) + ((r1 >>> 16) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk|12)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            r = HEAP32[(Rk|16)>>2]|0;
            u = ((r & 0xffff) + ((r2 & 0xffff) << 1)|0) + c|0;
            w = ((r >>> 16) + ((r2 >>> 16) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk|16)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            r = HEAP32[(Rk|20)>>2]|0;
            u = ((r & 0xffff) + ((r3 & 0xffff) << 1)|0) + c|0;
            w = ((r >>> 16) + ((r3 >>> 16) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk|20)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            for ( k = 24; !!c & ( (k|0) < 32 ); k = (k+4)|0 ) {
                r = HEAP32[(Rk|k)>>2]|0;
                u = (r & 0xffff) + c|0;
                w = (r >>> 16) + (u >>> 16)|0;
                HEAP32[(Rk|k)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;
            }
        }

        // unrolled 3rd iteration
        for ( p = 0; (p|0) < (lA|0); p = (p+32)|0 ) {
            Ai = A+p|0, Rk = R+(p<<1)|0;

            ah0 = HEAP32[(Ai)>>2]|0, al0 = ah0 & 0xffff, ah0 = ah0 >>> 16,
            ah1 = HEAP32[(Ai|4)>>2]|0, al1 = ah1 & 0xffff, ah1 = ah1 >>> 16,
            ah2 = HEAP32[(Ai|8)>>2]|0, al2 = ah2 & 0xffff, ah2 = ah2 >>> 16,
            ah3 = HEAP32[(Ai|12)>>2]|0, al3 = ah3 & 0xffff, ah3 = ah3 >>> 16;

            bh0 = HEAP32[(Ai|16)>>2]|0, bl0 = bh0 & 0xffff, bh0 = bh0 >>> 16,
            bh1 = HEAP32[(Ai|20)>>2]|0, bl1 = bh1 & 0xffff, bh1 = bh1 >>> 16,
            bh2 = HEAP32[(Ai|24)>>2]|0, bl2 = bh2 & 0xffff, bh2 = bh2 >>> 16,
            bh3 = HEAP32[(Ai|28)>>2]|0, bl3 = bh3 & 0xffff, bh3 = bh3 >>> 16;

            u = imul(al0, bl0)|0;
            v = imul(ah0, bl0)|0;
            w = ((imul(al0, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah0, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r0 = (w << 16) | (u & 0xffff);

            u = (imul(al0, bl1)|0) + (m & 0xffff)|0;
            v = (imul(ah0, bl1)|0) + (m >>> 16)|0;
            w = ((imul(al0, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah0, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r1 = (w << 16) | (u & 0xffff);

            u = (imul(al0, bl2)|0) + (m & 0xffff)|0;
            v = (imul(ah0, bl2)|0) + (m >>> 16)|0;
            w = ((imul(al0, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah0, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r2 = (w << 16) | (u & 0xffff);

            u = (imul(al0, bl3)|0) + (m & 0xffff)|0;
            v = (imul(ah0, bl3)|0) + (m >>> 16)|0;
            w = ((imul(al0, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah0, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r3 = (w << 16) | (u & 0xffff);

            r4 = m;

            u = (imul(al1, bl0)|0) + (r1 & 0xffff)|0;
            v = (imul(ah1, bl0)|0) + (r1 >>> 16)|0;
            w = ((imul(al1, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah1, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r1 = (w << 16) | (u & 0xffff);

            u = ((imul(al1, bl1)|0) + (r2 & 0xffff)|0) + (m & 0xffff)|0;
            v = ((imul(ah1, bl1)|0) + (r2 >>> 16)|0) + (m >>> 16)|0;
            w = ((imul(al1, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah1, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r2 = (w << 16) | (u & 0xffff);

            u = ((imul(al1, bl2)|0) + (r3 & 0xffff)|0) + (m & 0xffff)|0;
            v = ((imul(ah1, bl2)|0) + (r3 >>> 16)|0) + (m >>> 16)|0;
            w = ((imul(al1, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah1, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r3 = (w << 16) | (u & 0xffff);

            u = ((imul(al1, bl3)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
            v = ((imul(ah1, bl3)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
            w = ((imul(al1, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah1, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r4 = (w << 16) | (u & 0xffff);

            r5 = m;

            u = (imul(al2, bl0)|0) + (r2 & 0xffff)|0;
            v = (imul(ah2, bl0)|0) + (r2 >>> 16)|0;
            w = ((imul(al2, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah2, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r2 = (w << 16) | (u & 0xffff);

            u = ((imul(al2, bl1)|0) + (r3 & 0xffff)|0) + (m & 0xffff)|0;
            v = ((imul(ah2, bl1)|0) + (r3 >>> 16)|0) + (m >>> 16)|0;
            w = ((imul(al2, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah2, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r3 = (w << 16) | (u & 0xffff);

            u = ((imul(al2, bl2)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
            v = ((imul(ah2, bl2)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
            w = ((imul(al2, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah2, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r4 = (w << 16) | (u & 0xffff);

            u = ((imul(al2, bl3)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
            v = ((imul(ah2, bl3)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
            w = ((imul(al2, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah2, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r5 = (w << 16) | (u & 0xffff);

            r6 = m;

            u = (imul(al3, bl0)|0) + (r3 & 0xffff)|0;
            v = (imul(ah3, bl0)|0) + (r3 >>> 16)|0;
            w = ((imul(al3, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah3, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r3 = (w << 16) | (u & 0xffff);

            u = ((imul(al3, bl1)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
            v = ((imul(ah3, bl1)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
            w = ((imul(al3, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah3, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r4 = (w << 16) | (u & 0xffff);

            u = ((imul(al3, bl2)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
            v = ((imul(ah3, bl2)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
            w = ((imul(al3, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah3, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r5 = (w << 16) | (u & 0xffff);

            u = ((imul(al3, bl3)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
            v = ((imul(ah3, bl3)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
            w = ((imul(al3, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
            m = ((imul(ah3, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
            r6 = (w << 16) | (u & 0xffff);

            r7 = m;

            r = HEAP32[(Rk|16)>>2]|0;
            u = (r & 0xffff) + ((r0 & 0xffff) << 1)|0;
            w = ((r >>> 16) + ((r0 >>> 16) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk|16)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            r = HEAP32[(Rk|20)>>2]|0;
            u = ((r & 0xffff) + ((r1 & 0xffff) << 1)|0)  + c|0;
            w = ((r >>> 16) + ((r1 >>> 16) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk|20)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            r = HEAP32[(Rk|24)>>2]|0;
            u = ((r & 0xffff) + ((r2 & 0xffff) << 1)|0) + c|0;
            w = ((r >>> 16) + ((r2 >>> 16) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk|24)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            r = HEAP32[(Rk|28)>>2]|0;
            u = ((r & 0xffff) + ((r3 & 0xffff) << 1)|0) + c|0;
            w = ((r >>> 16) + ((r3 >>> 16) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk|28)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            r = HEAP32[(Rk+32)>>2]|0;
            u = ((r & 0xffff) + ((r4 & 0xffff) << 1)|0) + c|0;
            w = ((r >>> 16) + ((r4 >>> 16) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk+32)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            r = HEAP32[(Rk+36)>>2]|0;
            u = ((r & 0xffff) + ((r5 & 0xffff) << 1)|0) + c|0;
            w = ((r >>> 16) + ((r5 >>> 16) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk+36)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            r = HEAP32[(Rk+40)>>2]|0;
            u = ((r & 0xffff) + ((r6 & 0xffff) << 1)|0) + c|0;
            w = ((r >>> 16) + ((r6 >>> 16) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk+40)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            r = HEAP32[(Rk+44)>>2]|0;
            u = ((r & 0xffff) + ((r7 & 0xffff) << 1)|0) + c|0;
            w = ((r >>> 16) + ((r7 >>> 16) << 1)|0) + (u >>> 16)|0;
            HEAP32[(Rk+44)>>2] = (w << 16) | (u & 0xffff);
            c = w >>> 16;

            for ( k = 48; !!c & ( (k|0) < 64 ); k = (k+4)|0 ) {
                r = HEAP32[(Rk+k)>>2]|0;
                u = (r & 0xffff) + c|0;
                w = (r >>> 16) + (u >>> 16)|0;
                HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;
            }
        }

        // perform iterations
        for ( d = 32; (d|0) < (lA|0); d = d << 1 ) { // depth loop
            dd = d << 1;

            for ( p = 0; (p|0) < (lA|0); p = (p+dd)|0 ) { // part loop
                Rk = R+(p<<1)|0;

                h = 0;
                for ( i = 0; (i|0) < (d|0); i = (i+32)|0 ) { // multiply-and-add loop
                    Ai = (A+p|0)+i|0;

                    ah0 = HEAP32[(Ai)>>2]|0, al0 = ah0 & 0xffff, ah0 = ah0 >>> 16,
                    ah1 = HEAP32[(Ai|4)>>2]|0, al1 = ah1 & 0xffff, ah1 = ah1 >>> 16,
                    ah2 = HEAP32[(Ai|8)>>2]|0, al2 = ah2 & 0xffff, ah2 = ah2 >>> 16,
                    ah3 = HEAP32[(Ai|12)>>2]|0, al3 = ah3 & 0xffff, ah3 = ah3 >>> 16,
                    ah4 = HEAP32[(Ai|16)>>2]|0, al4 = ah4 & 0xffff, ah4 = ah4 >>> 16,
                    ah5 = HEAP32[(Ai|20)>>2]|0, al5 = ah5 & 0xffff, ah5 = ah5 >>> 16,
                    ah6 = HEAP32[(Ai|24)>>2]|0, al6 = ah6 & 0xffff, ah6 = ah6 >>> 16,
                    ah7 = HEAP32[(Ai|28)>>2]|0, al7 = ah7 & 0xffff, ah7 = ah7 >>> 16;

                    r8 = r9 = r10 = r11 = r12 = r13 = r14 = r15 = c = 0;

                    for ( j = 0; (j|0) < (d|0); j = (j+32)|0 ) {
                        Aj = ((A+p|0)+d|0)+j|0;

                        bh0 = HEAP32[(Aj)>>2]|0, bl0 = bh0 & 0xffff, bh0 = bh0 >>> 16,
                        bh1 = HEAP32[(Aj|4)>>2]|0, bl1 = bh1 & 0xffff, bh1 = bh1 >>> 16,
                        bh2 = HEAP32[(Aj|8)>>2]|0, bl2 = bh2 & 0xffff, bh2 = bh2 >>> 16,
                        bh3 = HEAP32[(Aj|12)>>2]|0, bl3 = bh3 & 0xffff, bh3 = bh3 >>> 16,
                        bh4 = HEAP32[(Aj|16)>>2]|0, bl4 = bh4 & 0xffff, bh4 = bh4 >>> 16,
                        bh5 = HEAP32[(Aj|20)>>2]|0, bl5 = bh5 & 0xffff, bh5 = bh5 >>> 16,
                        bh6 = HEAP32[(Aj|24)>>2]|0, bl6 = bh6 & 0xffff, bh6 = bh6 >>> 16,
                        bh7 = HEAP32[(Aj|28)>>2]|0, bl7 = bh7 & 0xffff, bh7 = bh7 >>> 16;

                        r0 = r1 = r2 = r3 = r4 = r5 = r6 = r7 = 0;

                        u = ((imul(al0, bl0)|0) + (r0 & 0xffff)|0) + (r8 & 0xffff)|0;
                        v = ((imul(ah0, bl0)|0) + (r0 >>> 16)|0) + (r8 >>> 16)|0;
                        w = ((imul(al0, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah0, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r0 = (w << 16) | (u & 0xffff);

                        u = ((imul(al0, bl1)|0) + (r1 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah0, bl1)|0) + (r1 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al0, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah0, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r1 = (w << 16) | (u & 0xffff);

                        u = ((imul(al0, bl2)|0) + (r2 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah0, bl2)|0) + (r2 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al0, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah0, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r2 = (w << 16) | (u & 0xffff);

                        u = ((imul(al0, bl3)|0) + (r3 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah0, bl3)|0) + (r3 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al0, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah0, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r3 = (w << 16) | (u & 0xffff);

                        u = ((imul(al0, bl4)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah0, bl4)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al0, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah0, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r4 = (w << 16) | (u & 0xffff);

                        u = ((imul(al0, bl5)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah0, bl5)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al0, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah0, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r5 = (w << 16) | (u & 0xffff);

                        u = ((imul(al0, bl6)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah0, bl6)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al0, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah0, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r6 = (w << 16) | (u & 0xffff);

                        u = ((imul(al0, bl7)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah0, bl7)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al0, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah0, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r7 = (w << 16) | (u & 0xffff);

                        r8 = m;

                        u = ((imul(al1, bl0)|0) + (r1 & 0xffff)|0) + (r9 & 0xffff)|0;
                        v = ((imul(ah1, bl0)|0) + (r1 >>> 16)|0) + (r9 >>> 16)|0;
                        w = ((imul(al1, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah1, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r1 = (w << 16) | (u & 0xffff);

                        u = ((imul(al1, bl1)|0) + (r2 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah1, bl1)|0) + (r2 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al1, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah1, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r2 = (w << 16) | (u & 0xffff);

                        u = ((imul(al1, bl2)|0) + (r3 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah1, bl2)|0) + (r3 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al1, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah1, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r3 = (w << 16) | (u & 0xffff);

                        u = ((imul(al1, bl3)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah1, bl3)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al1, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah1, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r4 = (w << 16) | (u & 0xffff);

                        u = ((imul(al1, bl4)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah1, bl4)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al1, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah1, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r5 = (w << 16) | (u & 0xffff);

                        u = ((imul(al1, bl5)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah1, bl5)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al1, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah1, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r6 = (w << 16) | (u & 0xffff);

                        u = ((imul(al1, bl6)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah1, bl6)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al1, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah1, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r7 = (w << 16) | (u & 0xffff);

                        u = ((imul(al1, bl7)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah1, bl7)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al1, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah1, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r8 = (w << 16) | (u & 0xffff);

                        r9 = m;

                        u = ((imul(al2, bl0)|0) + (r2 & 0xffff)|0) + (r10 & 0xffff)|0;
                        v = ((imul(ah2, bl0)|0) + (r2 >>> 16)|0) + (r10 >>> 16)|0;
                        w = ((imul(al2, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah2, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r2 = (w << 16) | (u & 0xffff);

                        u = ((imul(al2, bl1)|0) + (r3 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah2, bl1)|0) + (r3 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al2, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah2, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r3 = (w << 16) | (u & 0xffff);

                        u = ((imul(al2, bl2)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah2, bl2)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al2, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah2, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r4 = (w << 16) | (u & 0xffff);

                        u = ((imul(al2, bl3)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah2, bl3)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al2, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah2, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r5 = (w << 16) | (u & 0xffff);

                        u = ((imul(al2, bl4)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah2, bl4)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al2, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah2, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r6 = (w << 16) | (u & 0xffff);

                        u = ((imul(al2, bl5)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah2, bl5)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al2, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah2, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r7 = (w << 16) | (u & 0xffff);

                        u = ((imul(al2, bl6)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah2, bl6)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al2, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah2, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r8 = (w << 16) | (u & 0xffff);

                        u = ((imul(al2, bl7)|0) + (r9 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah2, bl7)|0) + (r9 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al2, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah2, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r9 = (w << 16) | (u & 0xffff);

                        r10 = m;

                        u = ((imul(al3, bl0)|0) + (r3 & 0xffff)|0) + (r11 & 0xffff)|0;
                        v = ((imul(ah3, bl0)|0) + (r3 >>> 16)|0) + (r11 >>> 16)|0;
                        w = ((imul(al3, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah3, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r3 = (w << 16) | (u & 0xffff);

                        u = ((imul(al3, bl1)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah3, bl1)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al3, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah3, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r4 = (w << 16) | (u & 0xffff);

                        u = ((imul(al3, bl2)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah3, bl2)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al3, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah3, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r5 = (w << 16) | (u & 0xffff);

                        u = ((imul(al3, bl3)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah3, bl3)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al3, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah3, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r6 = (w << 16) | (u & 0xffff);

                        u = ((imul(al3, bl4)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah3, bl4)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al3, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah3, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r7 = (w << 16) | (u & 0xffff);

                        u = ((imul(al3, bl5)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah3, bl5)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al3, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah3, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r8 = (w << 16) | (u & 0xffff);

                        u = ((imul(al3, bl6)|0) + (r9 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah3, bl6)|0) + (r9 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al3, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah3, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r9 = (w << 16) | (u & 0xffff);

                        u = ((imul(al3, bl7)|0) + (r10 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah3, bl7)|0) + (r10 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al3, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah3, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r10 = (w << 16) | (u & 0xffff);

                        r11 = m;

                        u = ((imul(al4, bl0)|0) + (r4 & 0xffff)|0) + (r12 & 0xffff)|0;
                        v = ((imul(ah4, bl0)|0) + (r4 >>> 16)|0) + (r12 >>> 16)|0;
                        w = ((imul(al4, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah4, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r4 = (w << 16) | (u & 0xffff);

                        u = ((imul(al4, bl1)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah4, bl1)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al4, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah4, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r5 = (w << 16) | (u & 0xffff);

                        u = ((imul(al4, bl2)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah4, bl2)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al4, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah4, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r6 = (w << 16) | (u & 0xffff);

                        u = ((imul(al4, bl3)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah4, bl3)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al4, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah4, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r7 = (w << 16) | (u & 0xffff);

                        u = ((imul(al4, bl4)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah4, bl4)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al4, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah4, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r8 = (w << 16) | (u & 0xffff);

                        u = ((imul(al4, bl5)|0) + (r9 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah4, bl5)|0) + (r9 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al4, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah4, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r9 = (w << 16) | (u & 0xffff);

                        u = ((imul(al4, bl6)|0) + (r10 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah4, bl6)|0) + (r10 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al4, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah4, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r10 = (w << 16) | (u & 0xffff);

                        u = ((imul(al4, bl7)|0) + (r11 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah4, bl7)|0) + (r11 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al4, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah4, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r11 = (w << 16) | (u & 0xffff);

                        r12 = m;

                        u = ((imul(al5, bl0)|0) + (r5 & 0xffff)|0) + (r13 & 0xffff)|0;
                        v = ((imul(ah5, bl0)|0) + (r5 >>> 16)|0) + (r13 >>> 16)|0;
                        w = ((imul(al5, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah5, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r5 = (w << 16) | (u & 0xffff);

                        u = ((imul(al5, bl1)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah5, bl1)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al5, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah5, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r6 = (w << 16) | (u & 0xffff);

                        u = ((imul(al5, bl2)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah5, bl2)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al5, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah5, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r7 = (w << 16) | (u & 0xffff);

                        u = ((imul(al5, bl3)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah5, bl3)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al5, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah5, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r8 = (w << 16) | (u & 0xffff);

                        u = ((imul(al5, bl4)|0) + (r9 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah5, bl4)|0) + (r9 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al5, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah5, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r9 = (w << 16) | (u & 0xffff);

                        u = ((imul(al5, bl5)|0) + (r10 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah5, bl5)|0) + (r10 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al5, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah5, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r10 = (w << 16) | (u & 0xffff);

                        u = ((imul(al5, bl6)|0) + (r11 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah5, bl6)|0) + (r11 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al5, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah5, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r11 = (w << 16) | (u & 0xffff);

                        u = ((imul(al5, bl7)|0) + (r12 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah5, bl7)|0) + (r12 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al5, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah5, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r12 = (w << 16) | (u & 0xffff);

                        r13 = m;

                        u = ((imul(al6, bl0)|0) + (r6 & 0xffff)|0) + (r14 & 0xffff)|0;
                        v = ((imul(ah6, bl0)|0) + (r6 >>> 16)|0) + (r14 >>> 16)|0;
                        w = ((imul(al6, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah6, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r6 = (w << 16) | (u & 0xffff);

                        u = ((imul(al6, bl1)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah6, bl1)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al6, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah6, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r7 = (w << 16) | (u & 0xffff);

                        u = ((imul(al6, bl2)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah6, bl2)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al6, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah6, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r8 = (w << 16) | (u & 0xffff);

                        u = ((imul(al6, bl3)|0) + (r9 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah6, bl3)|0) + (r9 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al6, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah6, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r9 = (w << 16) | (u & 0xffff);

                        u = ((imul(al6, bl4)|0) + (r10 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah6, bl4)|0) + (r10 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al6, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah6, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r10 = (w << 16) | (u & 0xffff);

                        u = ((imul(al6, bl5)|0) + (r11 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah6, bl5)|0) + (r11 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al6, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah6, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r11 = (w << 16) | (u & 0xffff);

                        u = ((imul(al6, bl6)|0) + (r12 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah6, bl6)|0) + (r12 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al6, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah6, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r12 = (w << 16) | (u & 0xffff);

                        u = ((imul(al6, bl7)|0) + (r13 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah6, bl7)|0) + (r13 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al6, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah6, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r13 = (w << 16) | (u & 0xffff);

                        r14 = m;

                        u = ((imul(al7, bl0)|0) + (r7 & 0xffff)|0) + (r15 & 0xffff)|0;
                        v = ((imul(ah7, bl0)|0) + (r7 >>> 16)|0) + (r15 >>> 16)|0;
                        w = ((imul(al7, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah7, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r7 = (w << 16) | (u & 0xffff);

                        u = ((imul(al7, bl1)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah7, bl1)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al7, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah7, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r8 = (w << 16) | (u & 0xffff);

                        u = ((imul(al7, bl2)|0) + (r9 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah7, bl2)|0) + (r9 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al7, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah7, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r9 = (w << 16) | (u & 0xffff);

                        u = ((imul(al7, bl3)|0) + (r10 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah7, bl3)|0) + (r10 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al7, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah7, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r10 = (w << 16) | (u & 0xffff);

                        u = ((imul(al7, bl4)|0) + (r11 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah7, bl4)|0) + (r11 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al7, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah7, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r11 = (w << 16) | (u & 0xffff);

                        u = ((imul(al7, bl5)|0) + (r12 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah7, bl5)|0) + (r12 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al7, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah7, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r12 = (w << 16) | (u & 0xffff);

                        u = ((imul(al7, bl6)|0) + (r13 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah7, bl6)|0) + (r13 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al7, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah7, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r13 = (w << 16) | (u & 0xffff);

                        u = ((imul(al7, bl7)|0) + (r14 & 0xffff)|0) + (m & 0xffff)|0;
                        v = ((imul(ah7, bl7)|0) + (r14 >>> 16)|0) + (m >>> 16)|0;
                        w = ((imul(al7, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                        m = ((imul(ah7, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                        r14 = (w << 16) | (u & 0xffff);

                        r15 = m;

                        k = d+(i+j|0)|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r0 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r0 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r1 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r1 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r2 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r2 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r3 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r3 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r4 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r4 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r5 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r5 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r6 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r6 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r7 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r7 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;
                    }

                    k = d+(i+j|0)|0;
                    r = HEAP32[(Rk+k)>>2]|0;
                    u = (((r & 0xffff) + ((r8 & 0xffff) << 1)|0) + c|0) + h|0;
                    w = ((r >>> 16) + ((r8 >>> 16) << 1)|0) + (u >>> 16)|0;
                    HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                    c = w >>> 16;

                    k = k+4|0;
                    r = HEAP32[(Rk+k)>>2]|0;
                    u = ((r & 0xffff) + ((r9 & 0xffff) << 1)|0) + c|0;
                    w = ((r >>> 16) + ((r9 >>> 16) << 1)|0) + (u >>> 16)|0;
                    HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                    c = w >>> 16;

                    k = k+4|0;
                    r = HEAP32[(Rk+k)>>2]|0;
                    u = ((r & 0xffff) + ((r10 & 0xffff) << 1)|0) + c|0;
                    w = ((r >>> 16) + ((r10 >>> 16) << 1)|0) + (u >>> 16)|0;
                    HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                    c = w >>> 16;

                    k = k+4|0;
                    r = HEAP32[(Rk+k)>>2]|0;
                    u = ((r & 0xffff) + ((r11 & 0xffff) << 1)|0) + c|0;
                    w = ((r >>> 16) + ((r11 >>> 16) << 1)|0) + (u >>> 16)|0;
                    HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                    c = w >>> 16;

                    k = k+4|0;
                    r = HEAP32[(Rk+k)>>2]|0;
                    u = ((r & 0xffff) + ((r12 & 0xffff) << 1)|0) + c|0;
                    w = ((r >>> 16) + ((r12 >>> 16) << 1)|0) + (u >>> 16)|0;
                    HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                    c = w >>> 16;

                    k = k+4|0;
                    r = HEAP32[(Rk+k)>>2]|0;
                    u = ((r & 0xffff) + ((r13 & 0xffff) << 1)|0) + c|0;
                    w = ((r >>> 16) + ((r13 >>> 16) << 1)|0) + (u >>> 16)|0;
                    HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                    c = w >>> 16;

                    k = k+4|0;
                    r = HEAP32[(Rk+k)>>2]|0;
                    u = ((r & 0xffff) + ((r14 & 0xffff) << 1)|0) + c|0;
                    w = ((r >>> 16) + ((r14 >>> 16) << 1)|0) + (u >>> 16)|0;
                    HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                    c = w >>> 16;

                    k = k+4|0;
                    r = HEAP32[(Rk+k)>>2]|0;
                    u = ((r & 0xffff) + ((r15 & 0xffff) << 1)|0) + c|0;
                    w = ((r >>> 16) + ((r15 >>> 16) << 1)|0) + (u >>> 16)|0;
                    HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                    h = w >>> 16;
                }

                for ( k = k+4|0; !!h & ( (k|0) < (dd<<1) ); k = (k+4)|0 ) { // carry propagation loop
                    r = HEAP32[(Rk+k)>>2]|0;
                    u = (r & 0xffff) + h|0;
                    w = (r >>> 16) + (u >>> 16)|0;
                    HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                    h = w >>> 16;
                }
            }
        }
    }

    /**
     * Conventional division
     *
     * @param A offset of the numerator, 32-byte aligned
     * @param lA length of the numerator, multiple of 32
     *
     * @param B offset of the divisor, 32-byte aligned
     * @param lB length of the divisor, multiple of 32
     *
     * @param R offset where to place the remainder to, 32-byte aligned
     *
     * @param Q offser where to place the quotient to, 32-byte aligned
     */

    function div ( N, lN, D, lD, R, Q ) {
        N  =  N|0;
        lN = lN|0
        D  =  D|0;
        lD = lD|0
        R  =  R|0;
        Q  =  Q|0;

        var n = 0, d = 0, e = 0,
            u1 = 0, u0 = 0, uh = 0, um = 0, ul = 0,
            v0 = 0, vh = 0, vl = 0,
            qh = 0, ql = 0, rh = 0, rl = 0,
            t1 = 0, t2 = 0, m = 0, c = 0,
            i = 0, j = 0, k = 0;

        // copy `N` to `R`
        cp( lN, N, R );

        // number of significant limbs in `N` (multiplied by 4)
        for ( i = (lN-1) & -4; (i|0) >= 0; i = (i-4)|0 ) {
            n = HEAP32[(N+i)>>2]|0;
            if ( n ) {
                lN = i;
                break;
            }
        }

        // number of significant limbs in `D` (multiplied by 4)
        for ( i = (lD-1) & -4; (i|0) >= 0; i = (i-4)|0 ) {
            d = HEAP32[(D+i)>>2]|0;
            if ( d ) {
                lD = i;
                break;
            }
        }

        // `D` is zero? WTF?!

        // calculate `e` — the power of 2 of the normalization factor
        while ( (d & 0x80000000) == 0 ) {
            d = d << 1;
            e = e + 1|0;
        }

        // shift `R` for `e` bits left
        u0 = HEAP32[(N+lN)>>2]|0;
        if ( e ) u1 = u0>>>(32-e|0);
        for ( i = (lN-4)|0; (i|0) >= 0; i = (i-4)|0 ) {
            n = HEAP32[(N+i)>>2]|0;
            HEAP32[(R+i+4)>>2] = (u0 << e) | ( e ? n >>> (32-e|0) : 0 );
            u0 = n;
        }
        HEAP32[R>>2] = u0 << e;

        // normalize `D` in place
        if ( e ) {
            v0 = HEAP32[(D+lD)>>2]|0;
            for ( i = (lD-4)|0; (i|0) >= 0; i = (i-4)|0 ) {
                d = HEAP32[(D+i)>>2]|0;
                HEAP32[(D+i+4)>>2] = (v0 << e) | ( d >>> (32-e|0) );
                v0 = d;
            }
            HEAP32[D>>2] = v0 << e;
        }

        // divisor parts won't change
        v0 = HEAP32[(D+lD)>>2]|0;
        vh = v0 >>> 16, vl = v0 & 0xffff;

        // perform division
        for ( i = lN; (i|0) >= (lD|0); i = (i-4)|0 ) {
            j = (i-lD)|0;

            // estimate high part of the quotient
            u0 = HEAP32[(R+i)>>2]|0;
            qh = ( (u1>>>0) / (vh>>>0) )|0, rh = ( (u1>>>0) % (vh>>>0) )|0, t1 = imul(qh, vl)|0;
            while ( ( (qh|0) == 0x10000 ) | ( (t1>>>0) > (((rh << 16)|(u0 >>> 16))>>>0) ) ) {
                qh = (qh-1)|0, rh = (rh+vh)|0, t1 = (t1-vl)|0;
                if ( (rh|0) >= 0x10000 ) break;
            }

            // bulk multiply-and-subtract
            // m - multiplication carry, c - subtraction carry
            m = 0, c = 0;
            for ( k = 0; (k|0) <= (lD|0); k = (k+4)|0 ) {
                d = HEAP32[(D+k)>>2]|0;
                t1 = (imul(qh, d & 0xffff)|0) + (m >>> 16)|0;
                t2 = (imul(qh, d >>> 16)|0) + (t1 >>> 16)|0;
                d = (m & 0xffff) | (t1 << 16);
                m = t2;
                n = HEAP32[(R+j+k)>>2]|0;
                t1 = ((n & 0xffff) - (d & 0xffff)|0) + c|0;
                t2 = ((n >>> 16) - (d >>> 16)|0) + (t1 >> 16)|0;
                HEAP32[(R+j+k)>>2] = (t2 << 16) | (t1 & 0xffff);
                c = t2 >> 16;
            }
            t1 = ((u1 & 0xffff) - (m & 0xffff)|0) + c|0;
            t2 = ((u1 >>> 16) - (m >>> 16)|0) + (t1 >> 16)|0;
            HEAP32[(R+j+k)>>2] = u1 = (t2 << 16) | (t1 & 0xffff);
            c = t2 >> 16;

            // add `D` back if got carry-out
            if ( c ) {
                qh = (qh+1)|0, rh = (rh-vh)|0;
                c = 0;
                for ( k = 0; (k|0) <= (lD|0); k = (k+4)|0 ) {
                    d = HEAP32[(D+k)>>2]|0;
                    n = HEAP32[(R+j+k)>>2]|0;
                    t1 = ((n & 0xffff) + (d & 0xffff)|0) + c|0;
                    t2 = ((n >>> 16) + (d >>> 16)|0) + (t1 >>> 16)|0;
                    HEAP32[(R+j+k)>>2] = (t2 << 16) | (t1 & 0xffff);
                    c = t2 >>> 16;
                }
                HEAP32[(R+j+k)>>2] = u1 = (u1+c)|0;
            }

            // estimate low part of the quotient
            u0 = HEAP32[(R+i)>>2]|0;
            n = (u1 << 16) | (u0 >>> 16);
            ql = ( (n>>>0) / (vh>>>0) )|0, rl = ( (n>>>0) % (vh>>>0) )|0, t1 = imul(ql, vl)|0;
            while ( ( (ql|0) == 0x10000 ) | ( (t1>>>0) > (((rl << 16)|(u0 & 0xffff))>>>0) ) ) {
                ql = (ql-1)|0, rl = (rl+vh)|0, t1 = (t1-vl)|0;
                if ( (rl|0) >= 0x10000 ) break;
            }

            // bulk multiply-and-subtract
            // m - multiplication carry, c - subtraction carry
            m = 0, c = 0;
            for ( k = 0; (k|0) <= (lD|0); k = (k+4)|0 ) {
                d = HEAP32[(D+k)>>2]|0;
                t1 = (imul(ql, d & 0xffff)|0) + (m & 0xffff)|0;
                t2 = ((imul(ql, d >>> 16)|0) + (t1 >>> 16)|0) + (m >>> 16)|0;
                d = (t1 & 0xffff) | (t2 << 16);
                m = t2 >>> 16;
                n = HEAP32[(R+j+k)>>2]|0;
                t1 = ((n & 0xffff) - (d & 0xffff)|0) + c|0;
                t2 = ((n >>> 16) - (d >>> 16)|0) + (t1 >> 16)|0;
                c = t2 >> 16;
                HEAP32[(R+j+k)>>2] = (t2 << 16) | (t1 & 0xffff);
            }
            t1 = ((u1 & 0xffff) - (m & 0xffff)|0) + c|0;
            t2 = ((u1 >>> 16) - (m >>> 16)|0) + (t1 >> 16)|0;
            HEAP32[(R+j+k)>>2] = u1 = (t2 << 16) | (t1 & 0xffff);
            c = t2 >> 16;

            // add `D` back if got carry-out
            if ( c ) {
                ql = (ql+1)|0, rl = (rl+vh)|0;
                c = 0;
                for ( k = 0; (k|0) <= (lD|0); k = (k+4)|0 ) {
                    d = HEAP32[(D+k)>>2]|0;
                    n = HEAP32[(R+j+k)>>2]|0;
                    t1 = ((n & 0xffff) + (d & 0xffff)|0) + c|0;
                    t2 = ((n >>> 16) + (d >>> 16)|0) + (t1 >>> 16)|0;
                    c = t2 >>> 16;
                    HEAP32[(R+j+k)>>2] = (t1 & 0xffff) | (t2 << 16);
                }
                HEAP32[(R+j+k)>>2] = (u1+c)|0;
            }

            // got quotient limb
            HEAP32[(Q+j)>>2] = (qh << 16) | ql;

            u1 = HEAP32[(R+i)>>2]|0;
        }

        if ( e ) {
            // TODO denormalize `D` in place

            // denormalize `R` in place
            u0 = HEAP32[R>>2]|0;
            for ( i = 4; (i|0) <= (lD|0); i = (i+4)|0 ) {
                n = HEAP32[(R+i)>>2]|0;
                HEAP32[(R+i-4)>>2] = ( n << (32-e|0) ) | (u0 >>> e);
                u0 = n;
            }
            HEAP32[(R+lD)>>2] = u0 >>> e;
        }
    }

    /**
     * Montgomery reduction
     *
     * Definition:
     *
     *  MREDC(A) = A × X (mod N),
     *  M × X = N × Y + 1,
     *
     * where M = 2^(32*m) such that N < M and A < N×M
     *
     * Numbers `X` and `Y` can be calculated using Extended Euclidean Algorithm.
     */
    function mredc_odd ( A, lA, N, lN, y, R ) {
        A  =  A|0;
        lA = lA|0;
        N  =  N|0;
        lN = lN|0;
        y  =  y|0;
        R  =  R|0;

        var T = 0,
            t = 0, c = 0, uh = 0, ul = 0, vl = 0, vh = 0, w0 = 0, w1 = 0, w2 = 0, r0 = 0, r1 = 0,
            i = 0, j = 0, k = 0;

        T = salloc(lA)|0;

        cp( lA, A, T );

        // HAC 14.32
        for ( i = 0; (i|0) < (lN|0); i = (i+4)|0 ) {
            t = HEAP32[(T+i)>>2]|0;
            uh = imul(t,y)|0, ul = uh & 0xffff, uh = uh >>> 16;
            r1 = 0;
            for ( j = 0; (j|0) < (lN|0); j = (j+4)|0 ) {
                k = (i+j)|0;
                vh = HEAP32[(N+j)>>2]|0, vl = vh & 0xffff, vh = vh >>> 16;
                r0 = HEAP32[(T+k)>>2]|0;
                w0 = ((imul(ul, vl)|0) + (r1 & 0xffff)|0) + (r0 & 0xffff)|0;
                w1 = ((imul(ul, vh)|0) + (r1 >>> 16)|0) + (r0 >>> 16)|0;
                w2 = ((imul(uh, vl)|0) + (w1 & 0xffff)|0) + (w0 >>> 16)|0;
                r1 = ((imul(uh, vh)|0) + (w2 >>> 16)|0) + (w1 >>> 16)|0;
                r0 = (w2 << 16) | (w0 & 0xffff);
                HEAP32[(T+k)>>2] = r0;
            }
            k = (i+j)|0;
            r0 = HEAP32[(T+k)>>2]|0;
            w0 = ((r0 & 0xffff) + (r1 & 0xffff)|0) + c|0;
            w1 = ((r0 >>> 16) + (r1 >>> 16)|0) + (w0 >>> 16)|0;
            HEAP32[(T+k)>>2] = (w1 << 16) | (w0 & 0xffff);
            c = w1 >>> 16;
        }

        cp( lN, (T+lN)|0, R );

        sfree(lA);

        if ( (cmp( N, lN, R, lN )|0) <= 0 ) {
            sub( R, lN, N, lN, R, lN )|0;
        }
    }

    return {
        sreset: sreset,
        salloc: salloc,
        sfree:  sfree,
        z: z,
        tst: tst,
        neg: neg,
        cmp: cmp,
        add: add,
        sub: sub,
        mul: mul,
        sqr: sqr,
        div: div,
        mredc_odd: mredc_odd
    };
}
