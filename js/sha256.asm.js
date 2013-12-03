/*
function sha256_asm ( stdlib, foreign, buffer ) {
    "use asm";

    // SHA256 state
    var H0 = 0, H1 = 0, H2 = 0, H3 = 0, H4 = 0, H5 = 0, H6 = 0, H7 = 0,
        TOTAL = 0;

    // HMAC state
    var I0 = 0, I1 = 0, I2 = 0, I3 = 0, I4 = 0, I5 = 0, I6 = 0, I7 = 0,
        O0 = 0, O1 = 0, O2 = 0, O3 = 0, O4 = 0, O5 = 0, O6 = 0, O7 = 0;

    // I/O buffer
    var HEAP = new stdlib.Uint8Array(buffer);

    function _core ( w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15 ) {
        w0 = w0|0;
        w1 = w1|0;
        w2 = w2|0;
        w3 = w3|0;
        w4 = w4|0;
        w5 = w5|0;
        w6 = w6|0;
        w7 = w7|0;
        w8 = w8|0;
        w9 = w9|0;
        w10 = w10|0;
        w11 = w11|0;
        w12 = w12|0;
        w13 = w13|0;
        w14 = w14|0;
        w15 = w15|0;

        var a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0,
            t = 0;

        a = H0;
        b = H1;
        c = H2;
        d = H3;
        e = H4;
        f = H5;
        g = H6;
        h = H7;

        // 0
        t = ( w0 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x428a2f98 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 1
        t = ( w1 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x71374491 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 2
        t = ( w2 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xb5c0fbcf )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 3
        t = ( w3 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xe9b5dba5 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 4
        t = ( w4 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x3956c25b )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 5
        t = ( w5 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x59f111f1 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 6
        t = ( w6 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x923f82a4 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 7
        t = ( w7 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xab1c5ed5 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 8
        t = ( w8 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xd807aa98 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 9
        t = ( w9 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x12835b01 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 10
        t = ( w10 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x243185be )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 11
        t = ( w11 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x550c7dc3 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 12
        t = ( w12 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x72be5d74 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 13
        t = ( w13 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x80deb1fe )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 14
        t = ( w14 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x9bdc06a7 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 15
        t = ( w15 + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xc19bf174 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 16
        w0 = t = ( ( w1>>>7  ^ w1>>>18 ^ w1>>>3  ^ w1<<25 ^ w1<<14 ) + ( w14>>>17 ^ w14>>>19 ^ w14>>>10 ^ w14<<15 ^ w14<<13 ) + w0 + w9 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xe49b69c1 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 17
        w1 = t = ( ( w2>>>7  ^ w2>>>18 ^ w2>>>3  ^ w2<<25 ^ w2<<14 ) + ( w15>>>17 ^ w15>>>19 ^ w15>>>10 ^ w15<<15 ^ w15<<13 ) + w1 + w10 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xefbe4786 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 18
        w2 = t = ( ( w3>>>7  ^ w3>>>18 ^ w3>>>3  ^ w3<<25 ^ w3<<14 ) + ( w0>>>17 ^ w0>>>19 ^ w0>>>10 ^ w0<<15 ^ w0<<13 ) + w2 + w11 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x0fc19dc6 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 19
        w3 = t = ( ( w4>>>7  ^ w4>>>18 ^ w4>>>3  ^ w4<<25 ^ w4<<14 ) + ( w1>>>17 ^ w1>>>19 ^ w1>>>10 ^ w1<<15 ^ w1<<13 ) + w3 + w12 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x240ca1cc )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 20
        w4 = t = ( ( w5>>>7  ^ w5>>>18 ^ w5>>>3  ^ w5<<25 ^ w5<<14 ) + ( w2>>>17 ^ w2>>>19 ^ w2>>>10 ^ w2<<15 ^ w2<<13 ) + w4 + w13 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x2de92c6f )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 21
        w5 = t = ( ( w6>>>7  ^ w6>>>18 ^ w6>>>3  ^ w6<<25 ^ w6<<14 ) + ( w3>>>17 ^ w3>>>19 ^ w3>>>10 ^ w3<<15 ^ w3<<13 ) + w5 + w14 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x4a7484aa )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 22
        w6 = t = ( ( w7>>>7  ^ w7>>>18 ^ w7>>>3  ^ w7<<25 ^ w7<<14 ) + ( w4>>>17 ^ w4>>>19 ^ w4>>>10 ^ w4<<15 ^ w4<<13 ) + w6 + w15 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x5cb0a9dc )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 23
        w7 = t = ( ( w8>>>7  ^ w8>>>18 ^ w8>>>3  ^ w8<<25 ^ w8<<14 ) + ( w5>>>17 ^ w5>>>19 ^ w5>>>10 ^ w5<<15 ^ w5<<13 ) + w7 + w0 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x76f988da )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 24
        w8 = t = ( ( w9>>>7  ^ w9>>>18 ^ w9>>>3  ^ w9<<25 ^ w9<<14 ) + ( w6>>>17 ^ w6>>>19 ^ w6>>>10 ^ w6<<15 ^ w6<<13 ) + w8 + w1 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x983e5152 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 25
        w9 = t = ( ( w10>>>7  ^ w10>>>18 ^ w10>>>3  ^ w10<<25 ^ w10<<14 ) + ( w7>>>17 ^ w7>>>19 ^ w7>>>10 ^ w7<<15 ^ w7<<13 ) + w9 + w2 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xa831c66d )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 26
        w10 = t = ( ( w11>>>7  ^ w11>>>18 ^ w11>>>3  ^ w11<<25 ^ w11<<14 ) + ( w8>>>17 ^ w8>>>19 ^ w8>>>10 ^ w8<<15 ^ w8<<13 ) + w10 + w3 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xb00327c8 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 27
        w11 = t = ( ( w12>>>7  ^ w12>>>18 ^ w12>>>3  ^ w12<<25 ^ w12<<14 ) + ( w9>>>17 ^ w9>>>19 ^ w9>>>10 ^ w9<<15 ^ w9<<13 ) + w11 + w4 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xbf597fc7 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 28
        w12 = t = ( ( w13>>>7  ^ w13>>>18 ^ w13>>>3  ^ w13<<25 ^ w13<<14 ) + ( w10>>>17 ^ w10>>>19 ^ w10>>>10 ^ w10<<15 ^ w10<<13 ) + w12 + w5 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xc6e00bf3 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 29
        w13 = t = ( ( w14>>>7  ^ w14>>>18 ^ w14>>>3  ^ w14<<25 ^ w14<<14 ) + ( w11>>>17 ^ w11>>>19 ^ w11>>>10 ^ w11<<15 ^ w11<<13 ) + w13 + w6 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xd5a79147 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 30
        w14 = t = ( ( w15>>>7  ^ w15>>>18 ^ w15>>>3  ^ w15<<25 ^ w15<<14 ) + ( w12>>>17 ^ w12>>>19 ^ w12>>>10 ^ w12<<15 ^ w12<<13 ) + w14 + w7 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x06ca6351 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 31
        w15 = t = ( ( w0>>>7  ^ w0>>>18 ^ w0>>>3  ^ w0<<25 ^ w0<<14 ) + ( w13>>>17 ^ w13>>>19 ^ w13>>>10 ^ w13<<15 ^ w13<<13 ) + w15 + w8 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x14292967 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 32
        w0 = t = ( ( w1>>>7  ^ w1>>>18 ^ w1>>>3  ^ w1<<25 ^ w1<<14 ) + ( w14>>>17 ^ w14>>>19 ^ w14>>>10 ^ w14<<15 ^ w14<<13 ) + w0 + w9 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x27b70a85 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 33
        w1 = t = ( ( w2>>>7  ^ w2>>>18 ^ w2>>>3  ^ w2<<25 ^ w2<<14 ) + ( w15>>>17 ^ w15>>>19 ^ w15>>>10 ^ w15<<15 ^ w15<<13 ) + w1 + w10 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x2e1b2138 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 34
        w2 = t = ( ( w3>>>7  ^ w3>>>18 ^ w3>>>3  ^ w3<<25 ^ w3<<14 ) + ( w0>>>17 ^ w0>>>19 ^ w0>>>10 ^ w0<<15 ^ w0<<13 ) + w2 + w11 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x4d2c6dfc )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 35
        w3 = t = ( ( w4>>>7  ^ w4>>>18 ^ w4>>>3  ^ w4<<25 ^ w4<<14 ) + ( w1>>>17 ^ w1>>>19 ^ w1>>>10 ^ w1<<15 ^ w1<<13 ) + w3 + w12 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x53380d13 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 36
        w4 = t = ( ( w5>>>7  ^ w5>>>18 ^ w5>>>3  ^ w5<<25 ^ w5<<14 ) + ( w2>>>17 ^ w2>>>19 ^ w2>>>10 ^ w2<<15 ^ w2<<13 ) + w4 + w13 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x650a7354 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 37
        w5 = t = ( ( w6>>>7  ^ w6>>>18 ^ w6>>>3  ^ w6<<25 ^ w6<<14 ) + ( w3>>>17 ^ w3>>>19 ^ w3>>>10 ^ w3<<15 ^ w3<<13 ) + w5 + w14 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x766a0abb )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 38
        w6 = t = ( ( w7>>>7  ^ w7>>>18 ^ w7>>>3  ^ w7<<25 ^ w7<<14 ) + ( w4>>>17 ^ w4>>>19 ^ w4>>>10 ^ w4<<15 ^ w4<<13 ) + w6 + w15 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x81c2c92e )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 39
        w7 = t = ( ( w8>>>7  ^ w8>>>18 ^ w8>>>3  ^ w8<<25 ^ w8<<14 ) + ( w5>>>17 ^ w5>>>19 ^ w5>>>10 ^ w5<<15 ^ w5<<13 ) + w7 + w0 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x92722c85 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 40
        w8 = t = ( ( w9>>>7  ^ w9>>>18 ^ w9>>>3  ^ w9<<25 ^ w9<<14 ) + ( w6>>>17 ^ w6>>>19 ^ w6>>>10 ^ w6<<15 ^ w6<<13 ) + w8 + w1 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xa2bfe8a1 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 41
        w9 = t = ( ( w10>>>7  ^ w10>>>18 ^ w10>>>3  ^ w10<<25 ^ w10<<14 ) + ( w7>>>17 ^ w7>>>19 ^ w7>>>10 ^ w7<<15 ^ w7<<13 ) + w9 + w2 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xa81a664b )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 42
        w10 = t = ( ( w11>>>7  ^ w11>>>18 ^ w11>>>3  ^ w11<<25 ^ w11<<14 ) + ( w8>>>17 ^ w8>>>19 ^ w8>>>10 ^ w8<<15 ^ w8<<13 ) + w10 + w3 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xc24b8b70 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 43
        w11 = t = ( ( w12>>>7  ^ w12>>>18 ^ w12>>>3  ^ w12<<25 ^ w12<<14 ) + ( w9>>>17 ^ w9>>>19 ^ w9>>>10 ^ w9<<15 ^ w9<<13 ) + w11 + w4 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xc76c51a3 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 44
        w12 = t = ( ( w13>>>7  ^ w13>>>18 ^ w13>>>3  ^ w13<<25 ^ w13<<14 ) + ( w10>>>17 ^ w10>>>19 ^ w10>>>10 ^ w10<<15 ^ w10<<13 ) + w12 + w5 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xd192e819 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 45
        w13 = t = ( ( w14>>>7  ^ w14>>>18 ^ w14>>>3  ^ w14<<25 ^ w14<<14 ) + ( w11>>>17 ^ w11>>>19 ^ w11>>>10 ^ w11<<15 ^ w11<<13 ) + w13 + w6 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xd6990624 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 46
        w14 = t = ( ( w15>>>7  ^ w15>>>18 ^ w15>>>3  ^ w15<<25 ^ w15<<14 ) + ( w12>>>17 ^ w12>>>19 ^ w12>>>10 ^ w12<<15 ^ w12<<13 ) + w14 + w7 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xf40e3585 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 47
        w15 = t = ( ( w0>>>7  ^ w0>>>18 ^ w0>>>3  ^ w0<<25 ^ w0<<14 ) + ( w13>>>17 ^ w13>>>19 ^ w13>>>10 ^ w13<<15 ^ w13<<13 ) + w15 + w8 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x106aa070 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 48
        w0 = t = ( ( w1>>>7  ^ w1>>>18 ^ w1>>>3  ^ w1<<25 ^ w1<<14 ) + ( w14>>>17 ^ w14>>>19 ^ w14>>>10 ^ w14<<15 ^ w14<<13 ) + w0 + w9 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x19a4c116 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 49
        w1 = t = ( ( w2>>>7  ^ w2>>>18 ^ w2>>>3  ^ w2<<25 ^ w2<<14 ) + ( w15>>>17 ^ w15>>>19 ^ w15>>>10 ^ w15<<15 ^ w15<<13 ) + w1 + w10 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x1e376c08 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 50
        w2 = t = ( ( w3>>>7  ^ w3>>>18 ^ w3>>>3  ^ w3<<25 ^ w3<<14 ) + ( w0>>>17 ^ w0>>>19 ^ w0>>>10 ^ w0<<15 ^ w0<<13 ) + w2 + w11 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x2748774c )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 51
        w3 = t = ( ( w4>>>7  ^ w4>>>18 ^ w4>>>3  ^ w4<<25 ^ w4<<14 ) + ( w1>>>17 ^ w1>>>19 ^ w1>>>10 ^ w1<<15 ^ w1<<13 ) + w3 + w12 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x34b0bcb5 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 52
        w4 = t = ( ( w5>>>7  ^ w5>>>18 ^ w5>>>3  ^ w5<<25 ^ w5<<14 ) + ( w2>>>17 ^ w2>>>19 ^ w2>>>10 ^ w2<<15 ^ w2<<13 ) + w4 + w13 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x391c0cb3 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 53
        w5 = t = ( ( w6>>>7  ^ w6>>>18 ^ w6>>>3  ^ w6<<25 ^ w6<<14 ) + ( w3>>>17 ^ w3>>>19 ^ w3>>>10 ^ w3<<15 ^ w3<<13 ) + w5 + w14 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x4ed8aa4a )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 54
        w6 = t = ( ( w7>>>7  ^ w7>>>18 ^ w7>>>3  ^ w7<<25 ^ w7<<14 ) + ( w4>>>17 ^ w4>>>19 ^ w4>>>10 ^ w4<<15 ^ w4<<13 ) + w6 + w15 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x5b9cca4f )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 55
        w7 = t = ( ( w8>>>7  ^ w8>>>18 ^ w8>>>3  ^ w8<<25 ^ w8<<14 ) + ( w5>>>17 ^ w5>>>19 ^ w5>>>10 ^ w5<<15 ^ w5<<13 ) + w7 + w0 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x682e6ff3 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 56
        w8 = t = ( ( w9>>>7  ^ w9>>>18 ^ w9>>>3  ^ w9<<25 ^ w9<<14 ) + ( w6>>>17 ^ w6>>>19 ^ w6>>>10 ^ w6<<15 ^ w6<<13 ) + w8 + w1 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x748f82ee )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 57
        w9 = t = ( ( w10>>>7  ^ w10>>>18 ^ w10>>>3  ^ w10<<25 ^ w10<<14 ) + ( w7>>>17 ^ w7>>>19 ^ w7>>>10 ^ w7<<15 ^ w7<<13 ) + w9 + w2 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x78a5636f )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 58
        w10 = t = ( ( w11>>>7  ^ w11>>>18 ^ w11>>>3  ^ w11<<25 ^ w11<<14 ) + ( w8>>>17 ^ w8>>>19 ^ w8>>>10 ^ w8<<15 ^ w8<<13 ) + w10 + w3 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x84c87814 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 59
        w11 = t = ( ( w12>>>7  ^ w12>>>18 ^ w12>>>3  ^ w12<<25 ^ w12<<14 ) + ( w9>>>17 ^ w9>>>19 ^ w9>>>10 ^ w9<<15 ^ w9<<13 ) + w11 + w4 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x8cc70208 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 60
        w12 = t = ( ( w13>>>7  ^ w13>>>18 ^ w13>>>3  ^ w13<<25 ^ w13<<14 ) + ( w10>>>17 ^ w10>>>19 ^ w10>>>10 ^ w10<<15 ^ w10<<13 ) + w12 + w5 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0x90befffa )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 61
        w13 = t = ( ( w14>>>7  ^ w14>>>18 ^ w14>>>3  ^ w14<<25 ^ w14<<14 ) + ( w11>>>17 ^ w11>>>19 ^ w11>>>10 ^ w11<<15 ^ w11<<13 ) + w13 + w6 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xa4506ceb )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 62
        w14 = t = ( ( w15>>>7  ^ w15>>>18 ^ w15>>>3  ^ w15<<25 ^ w15<<14 ) + ( w12>>>17 ^ w12>>>19 ^ w12>>>10 ^ w12<<15 ^ w12<<13 ) + w14 + w7 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xbef9a3f7 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        // 63
        w15 = t = ( ( w0>>>7  ^ w0>>>18 ^ w0>>>3  ^ w0<<25 ^ w0<<14 ) + ( w13>>>17 ^ w13>>>19 ^ w13>>>10 ^ w13<<15 ^ w13<<13 ) + w15 + w8 )|0;
        t = ( t + h + ( e>>>6 ^ e>>>11 ^ e>>>25 ^ e<<26 ^ e<<21 ^ e<<7 ) +  ( g ^ e & (f^g) ) + 0xc67178f2 )|0;
        h = g; g = f; f = e; e = ( d + t )|0; d = c; c = b; b = a;
        a = ( t + ( (b & c) ^ ( d & (b ^ c) ) ) + ( b>>>2 ^ b>>>13 ^ b>>>22 ^ b<<30 ^ b<<19 ^ b<<10 ) )|0;

        H0 = ( H0 + a )|0;
        H1 = ( H1 + b )|0;
        H2 = ( H2 + c )|0;
        H3 = ( H3 + d )|0;
        H4 = ( H4 + e )|0;
        H5 = ( H5 + f )|0;
        H6 = ( H6 + g )|0;
        H7 = ( H7 + h )|0;
    }

    function _core_heap ( offset ) {
        offset = offset|0;

        _core(
            HEAP[offset|0]<<24 | HEAP[offset|1]<<16 | HEAP[offset|2]<<8 | HEAP[offset|3],
            HEAP[offset|4]<<24 | HEAP[offset|5]<<16 | HEAP[offset|6]<<8 | HEAP[offset|7],
            HEAP[offset|8]<<24 | HEAP[offset|9]<<16 | HEAP[offset|10]<<8 | HEAP[offset|11],
            HEAP[offset|12]<<24 | HEAP[offset|13]<<16 | HEAP[offset|14]<<8 | HEAP[offset|15],
            HEAP[offset|16]<<24 | HEAP[offset|17]<<16 | HEAP[offset|18]<<8 | HEAP[offset|19],
            HEAP[offset|20]<<24 | HEAP[offset|21]<<16 | HEAP[offset|22]<<8 | HEAP[offset|23],
            HEAP[offset|24]<<24 | HEAP[offset|25]<<16 | HEAP[offset|26]<<8 | HEAP[offset|27],
            HEAP[offset|28]<<24 | HEAP[offset|29]<<16 | HEAP[offset|30]<<8 | HEAP[offset|31],
            HEAP[offset|32]<<24 | HEAP[offset|33]<<16 | HEAP[offset|34]<<8 | HEAP[offset|35],
            HEAP[offset|36]<<24 | HEAP[offset|37]<<16 | HEAP[offset|38]<<8 | HEAP[offset|39],
            HEAP[offset|40]<<24 | HEAP[offset|41]<<16 | HEAP[offset|42]<<8 | HEAP[offset|43],
            HEAP[offset|44]<<24 | HEAP[offset|45]<<16 | HEAP[offset|46]<<8 | HEAP[offset|47],
            HEAP[offset|48]<<24 | HEAP[offset|49]<<16 | HEAP[offset|50]<<8 | HEAP[offset|51],
            HEAP[offset|52]<<24 | HEAP[offset|53]<<16 | HEAP[offset|54]<<8 | HEAP[offset|55],
            HEAP[offset|56]<<24 | HEAP[offset|57]<<16 | HEAP[offset|58]<<8 | HEAP[offset|59],
            HEAP[offset|60]<<24 | HEAP[offset|61]<<16 | HEAP[offset|62]<<8 | HEAP[offset|63]
        );
    }

    // offset — multiple of 32
    function _state_to_heap ( output ) {
        output = output|0;

        HEAP[output|0] = H0>>>24;
        HEAP[output|1] = H0>>>16&255;
        HEAP[output|2] = H0>>>8&255;
        HEAP[output|3] = H0&255;
        HEAP[output|4] = H1>>>24;
        HEAP[output|5] = H1>>>16&255;
        HEAP[output|6] = H1>>>8&255;
        HEAP[output|7] = H1&255;
        HEAP[output|8] = H2>>>24;
        HEAP[output|9] = H2>>>16&255;
        HEAP[output|10] = H2>>>8&255;
        HEAP[output|11] = H2&255;
        HEAP[output|12] = H3>>>24;
        HEAP[output|13] = H3>>>16&255;
        HEAP[output|14] = H3>>>8&255;
        HEAP[output|15] = H3&255;
        HEAP[output|16] = H4>>>24;
        HEAP[output|17] = H4>>>16&255;
        HEAP[output|18] = H4>>>8&255;
        HEAP[output|19] = H4&255;
        HEAP[output|20] = H5>>>24;
        HEAP[output|21] = H5>>>16&255;
        HEAP[output|22] = H5>>>8&255;
        HEAP[output|23] = H5&255;
        HEAP[output|24] = H6>>>24;
        HEAP[output|25] = H6>>>16&255;
        HEAP[output|26] = H6>>>8&255;
        HEAP[output|27] = H6&255;
        HEAP[output|28] = H7>>>24;
        HEAP[output|29] = H7>>>16&255;
        HEAP[output|30] = H7>>>8&255;
        HEAP[output|31] = H7&255;
    }

    function reset () {
        H0 = 0x6a09e667;
        H1 = 0xbb67ae85;
        H2 = 0x3c6ef372;
        H3 = 0xa54ff53a;
        H4 = 0x510e527f;
        H5 = 0x9b05688c;
        H6 = 0x1f83d9ab;
        H7 = 0x5be0cd19;
        TOTAL = 0;
    }

    function init ( h0, h1, h2, h3, h4, h5, h6, h7, total ) {
        h0 = h0|0;
        h1 = h1|0;
        h2 = h2|0;
        h3 = h3|0;
        h4 = h4|0;
        h5 = h5|0;
        h6 = h6|0;
        h7 = h7|0;
        total = total|0;

        H0 = h0;
        H1 = h1;
        H2 = h2;
        H3 = h3;
        H4 = h4;
        H5 = h5;
        H6 = h6;
        H7 = h7;
        TOTAL = total;
    }

    // offset — multiple of 64
    function process ( offset, length ) {
        offset = offset|0;
        length = length|0;

        var hashed = 0;

        if ( offset & 63 )
            return -1;

        while ( (length|0) >= 64 ) {
            _core_heap(offset);

            offset = ( offset + 64)|0;
            length = ( length - 64)|0;

            hashed = ( hashed + 64)|0;
        }

        TOTAL = ( TOTAL + hashed )|0;

        return hashed|0;
    }

    // offset — multiple of 64
    // output — multiple of 32
    function finish ( offset, length, output ) {
        offset = offset|0;
        length = length|0;
        output = output|0;

        var hashed = 0,
            i = 0;

        if ( offset & 63 )
            return -1;

        if ( ~output )
            if ( output & 31 )
                return -1;

        if ( (length|0) >= 64 ) {
            hashed = process( offset, length )|0;
            if ( (hashed|0) == -1 )
                return -1;

            offset = ( offset + hashed )|0;
            length = ( length - hashed )|0;
        }

        hashed = ( hashed + length )|0
        TOTAL = ( TOTAL + length )|0;

        HEAP[offset|length] = 0x80;

        if ( (length|0) >= 56 ) {
            for ( i = (length+1)|0; (i|0) < 64; i = (i+1)|0 )
                HEAP[offset|i] = 0x00;

            _core_heap(offset);

            length = 0;

            HEAP[offset|0] = 0;
        }

        for ( i = (length+1)|0; (i|0) < 59; i = (i+1)|0 )
            HEAP[offset|i] = 0;

        HEAP[offset|59] = TOTAL>>>29;
        HEAP[offset|60] = TOTAL>>>21&255;
        HEAP[offset|61] = TOTAL>>>13&255
        HEAP[offset|62] = TOTAL>>>5&255;
        HEAP[offset|63] = TOTAL<<3&255;
        _core_heap(offset);

        if ( ~output )
            _state_to_heap(output);

        return hashed|0;
    }

    function hmac_reset () {
        H0 = I0;
        H1 = I1;
        H2 = I2;
        H3 = I3;
        H4 = I4;
        H5 = I5;
        H6 = I6;
        H7 = I7;
        TOTAL = 64;
    }

    function _hmac_opad () {
        H0 = O0;
        H1 = O1;
        H2 = O2;
        H3 = O3;
        H4 = O4;
        H5 = O5;
        H6 = O6;
        H7 = O7;
        TOTAL = 64;
    }

    function hmac_init ( p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15 ) {
        p0 = p0|0;
        p1 = p1|0;
        p2 = p2|0;
        p3 = p3|0;
        p4 = p4|0;
        p5 = p5|0;
        p6 = p6|0;
        p7 = p7|0;
        p8 = p8|0;
        p9 = p9|0;
        p10 = p10|0;
        p11 = p11|0;
        p12 = p12|0;
        p13 = p13|0;
        p14 = p14|0;
        p15 = p15|0;

        // opad
        reset();
        _core(
            p0 ^ 0x5c5c5c5c,
            p1 ^ 0x5c5c5c5c,
            p2 ^ 0x5c5c5c5c,
            p3 ^ 0x5c5c5c5c,
            p4 ^ 0x5c5c5c5c,
            p5 ^ 0x5c5c5c5c,
            p6 ^ 0x5c5c5c5c,
            p7 ^ 0x5c5c5c5c,
            p8 ^ 0x5c5c5c5c,
            p9 ^ 0x5c5c5c5c,
            p10 ^ 0x5c5c5c5c,
            p11 ^ 0x5c5c5c5c,
            p12 ^ 0x5c5c5c5c,
            p13 ^ 0x5c5c5c5c,
            p14 ^ 0x5c5c5c5c,
            p15 ^ 0x5c5c5c5c
        );
        O0 = H0;
        O1 = H1;
        O2 = H2;
        O3 = H3;
        O4 = H4;
        O5 = H5;
        O6 = H6;
        O7 = H7;

        // ipad
        reset();
        _core(
            p0 ^ 0x36363636,
            p1 ^ 0x36363636,
            p2 ^ 0x36363636,
            p3 ^ 0x36363636,
            p4 ^ 0x36363636,
            p5 ^ 0x36363636,
            p6 ^ 0x36363636,
            p7 ^ 0x36363636,
            p8 ^ 0x36363636,
            p9 ^ 0x36363636,
            p10 ^ 0x36363636,
            p11 ^ 0x36363636,
            p12 ^ 0x36363636,
            p13 ^ 0x36363636,
            p14 ^ 0x36363636,
            p15 ^ 0x36363636
        );
        I0 = H0;
        I1 = H1;
        I2 = H2;
        I3 = H3;
        I4 = H4;
        I5 = H5;
        I6 = H6;
        I7 = H7;

        TOTAL = 64;
    }

    // offset — multiple of 64
    // output — multiple of 32
    function hmac_finish ( offset, length, output ) {
        offset = offset|0;
        length = length|0;
        output = output|0;

        var t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0,
            hashed = 0;

        if ( offset & 63 )
            return -1;

        if ( ~output )
            if ( output & 31 )
                return -1;

        hashed = finish( offset, length, -1 )|0;
        t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4, t5 = H5, t6 = H6, t7 = H7;

        _hmac_opad();
        _core( t0, t1, t2, t3, t4, t5, t6, t7, 0x80000000, 0, 0, 0, 0, 0, 0, 768 );

        if ( ~output )
            _state_to_heap(output);

        return hashed|0;
    }

    // salt is assumed to be already processed
    // offset — multiple of 64
    // output — multiple of 32
    function pbkdf2_generate_block ( offset, length, block, count, output ) {
        offset = offset|0;
        length = length|0;
        block = block|0;
        count = count|0
        output = output|0;

        var h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0, h5 = 0, h6 = 0, h7 = 0,
            t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0;

        if ( offset & 63 )
            return -1;

        if ( ~output )
            if ( output & 31 )
                return -1;

        // pad block number into heap
        // FIXME probable OOB write
        HEAP[(offset+length)|0]   = block>>>24;
        HEAP[(offset+length+1)|0] = block>>>16&255;
        HEAP[(offset+length+2)|0] = block>>>8&255;
        HEAP[(offset+length+3)|0] = block&255;

        // finish first iteration
        hmac_finish( offset, (length+4)|0, -1 )|0;
        h0 = t0 = H0, h1 = t1 = H1, h2 = t2 = H2, h3 = t3 = H3, h4 = t4 = H4, h5 = t5 = H5, h6 = t6 = H6, h7 = t7 = H7;
        count = (count-1)|0;

        // perform the rest iterations
        while ( (count|0) > 0 ) {
            hmac_reset();
            _core( t0, t1, t2, t3, t4, t5, t6, t7, 0x80000000, 0, 0, 0, 0, 0, 0, 768 );
            t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4, t5 = H5, t6 = H6, t7 = H7;

            _hmac_opad();
            _core( t0, t1, t2, t3, t4, t5, t6, t7, 0x80000000, 0, 0, 0, 0, 0, 0, 768 );
            t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4, t5 = H5, t6 = H6, t7 = H7;

            h0 = h0 ^ H0;
            h1 = h1 ^ H1;
            h2 = h2 ^ H2;
            h3 = h3 ^ H3;
            h4 = h4 ^ H4;
            h5 = h5 ^ H5;
            h6 = h6 ^ H6;
            h7 = h7 ^ H7;

            count = (count-1)|0;
        }

        H0 = h0;
        H1 = h1;
        H2 = h2;
        H3 = h3;
        H4 = h4;
        H5 = h5;
        H6 = h6;
        H7 = h7;

        if ( ~output )
            _state_to_heap(output);
    }

    return {
        // SHA256
        reset: reset,
        init: init,
        process: process,
        finish: finish,

        // HMAC-SHA256
        hmac_reset: hmac_reset,
        hmac_init: hmac_init,
        hmac_finish: hmac_finish,

        // PBKDF2-HMAC-SHA256
        pbkdf2_generate_block: pbkdf2_generate_block
    }
}
*/
// Workaround Firefox bug, uglified from sha256_asm above with little manual changes
function sha256_asm ( stdlib, foreign, buffer ) {
    return (new Function('e,t,n','"use asm";var r=0,i=0,s=0,o=0,u=0,a=0,f=0,l=0,c=0;var h=0,p=0,d=0,v=0,m=0,g=0,y=0,b=0,w=0,E=0,S=0,x=0,T=0,N=0,C=0,k=0;var L=new e.Uint8Array(n);function A(e,t,n,c,h,p,d,v,m,g,y,b,w,E,S,x){e=e|0;t=t|0;n=n|0;c=c|0;h=h|0;p=p|0;d=d|0;v=v|0;m=m|0;g=g|0;y=y|0;b=b|0;w=w|0;E=E|0;S=S|0;x=x|0;var T=0,N=0,C=0,k=0,L=0,A=0,O=0,M=0,_=0;T=r;N=i;C=s;k=o;L=u;A=a;O=f;M=l;_=e+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1116352408|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=t+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1899447441|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=n+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3049323471|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=c+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3921009573|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=h+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+961987163|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=p+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1508970993|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=d+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2453635748|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=v+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2870763221|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=m+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3624381080|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=g+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+310598401|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=y+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+607225278|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=b+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1426881987|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=w+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1925078388|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=E+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2162078206|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=S+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2614888103|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;_=x+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3248222580|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;e=_=(t>>>7^t>>>18^t>>>3^t<<25^t<<14)+(S>>>17^S>>>19^S>>>10^S<<15^S<<13)+e+g|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3835390401|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;t=_=(n>>>7^n>>>18^n>>>3^n<<25^n<<14)+(x>>>17^x>>>19^x>>>10^x<<15^x<<13)+t+y|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+4022224774|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;n=_=(c>>>7^c>>>18^c>>>3^c<<25^c<<14)+(e>>>17^e>>>19^e>>>10^e<<15^e<<13)+n+b|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+264347078|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;c=_=(h>>>7^h>>>18^h>>>3^h<<25^h<<14)+(t>>>17^t>>>19^t>>>10^t<<15^t<<13)+c+w|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+604807628|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;h=_=(p>>>7^p>>>18^p>>>3^p<<25^p<<14)+(n>>>17^n>>>19^n>>>10^n<<15^n<<13)+h+E|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+770255983|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;p=_=(d>>>7^d>>>18^d>>>3^d<<25^d<<14)+(c>>>17^c>>>19^c>>>10^c<<15^c<<13)+p+S|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1249150122|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;d=_=(v>>>7^v>>>18^v>>>3^v<<25^v<<14)+(h>>>17^h>>>19^h>>>10^h<<15^h<<13)+d+x|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1555081692|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;v=_=(m>>>7^m>>>18^m>>>3^m<<25^m<<14)+(p>>>17^p>>>19^p>>>10^p<<15^p<<13)+v+e|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1996064986|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;m=_=(g>>>7^g>>>18^g>>>3^g<<25^g<<14)+(d>>>17^d>>>19^d>>>10^d<<15^d<<13)+m+t|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2554220882|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;g=_=(y>>>7^y>>>18^y>>>3^y<<25^y<<14)+(v>>>17^v>>>19^v>>>10^v<<15^v<<13)+g+n|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2821834349|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;y=_=(b>>>7^b>>>18^b>>>3^b<<25^b<<14)+(m>>>17^m>>>19^m>>>10^m<<15^m<<13)+y+c|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2952996808|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;b=_=(w>>>7^w>>>18^w>>>3^w<<25^w<<14)+(g>>>17^g>>>19^g>>>10^g<<15^g<<13)+b+h|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3210313671|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;w=_=(E>>>7^E>>>18^E>>>3^E<<25^E<<14)+(y>>>17^y>>>19^y>>>10^y<<15^y<<13)+w+p|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3336571891|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;E=_=(S>>>7^S>>>18^S>>>3^S<<25^S<<14)+(b>>>17^b>>>19^b>>>10^b<<15^b<<13)+E+d|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3584528711|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;S=_=(x>>>7^x>>>18^x>>>3^x<<25^x<<14)+(w>>>17^w>>>19^w>>>10^w<<15^w<<13)+S+v|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+113926993|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;x=_=(e>>>7^e>>>18^e>>>3^e<<25^e<<14)+(E>>>17^E>>>19^E>>>10^E<<15^E<<13)+x+m|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+338241895|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;e=_=(t>>>7^t>>>18^t>>>3^t<<25^t<<14)+(S>>>17^S>>>19^S>>>10^S<<15^S<<13)+e+g|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+666307205|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;t=_=(n>>>7^n>>>18^n>>>3^n<<25^n<<14)+(x>>>17^x>>>19^x>>>10^x<<15^x<<13)+t+y|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+773529912|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;n=_=(c>>>7^c>>>18^c>>>3^c<<25^c<<14)+(e>>>17^e>>>19^e>>>10^e<<15^e<<13)+n+b|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1294757372|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;c=_=(h>>>7^h>>>18^h>>>3^h<<25^h<<14)+(t>>>17^t>>>19^t>>>10^t<<15^t<<13)+c+w|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1396182291|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;h=_=(p>>>7^p>>>18^p>>>3^p<<25^p<<14)+(n>>>17^n>>>19^n>>>10^n<<15^n<<13)+h+E|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1695183700|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;p=_=(d>>>7^d>>>18^d>>>3^d<<25^d<<14)+(c>>>17^c>>>19^c>>>10^c<<15^c<<13)+p+S|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1986661051|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;d=_=(v>>>7^v>>>18^v>>>3^v<<25^v<<14)+(h>>>17^h>>>19^h>>>10^h<<15^h<<13)+d+x|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2177026350|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;v=_=(m>>>7^m>>>18^m>>>3^m<<25^m<<14)+(p>>>17^p>>>19^p>>>10^p<<15^p<<13)+v+e|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2456956037|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;m=_=(g>>>7^g>>>18^g>>>3^g<<25^g<<14)+(d>>>17^d>>>19^d>>>10^d<<15^d<<13)+m+t|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2730485921|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;g=_=(y>>>7^y>>>18^y>>>3^y<<25^y<<14)+(v>>>17^v>>>19^v>>>10^v<<15^v<<13)+g+n|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2820302411|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;y=_=(b>>>7^b>>>18^b>>>3^b<<25^b<<14)+(m>>>17^m>>>19^m>>>10^m<<15^m<<13)+y+c|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3259730800|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;b=_=(w>>>7^w>>>18^w>>>3^w<<25^w<<14)+(g>>>17^g>>>19^g>>>10^g<<15^g<<13)+b+h|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3345764771|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;w=_=(E>>>7^E>>>18^E>>>3^E<<25^E<<14)+(y>>>17^y>>>19^y>>>10^y<<15^y<<13)+w+p|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3516065817|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;E=_=(S>>>7^S>>>18^S>>>3^S<<25^S<<14)+(b>>>17^b>>>19^b>>>10^b<<15^b<<13)+E+d|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3600352804|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;S=_=(x>>>7^x>>>18^x>>>3^x<<25^x<<14)+(w>>>17^w>>>19^w>>>10^w<<15^w<<13)+S+v|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+4094571909|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;x=_=(e>>>7^e>>>18^e>>>3^e<<25^e<<14)+(E>>>17^E>>>19^E>>>10^E<<15^E<<13)+x+m|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+275423344|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;e=_=(t>>>7^t>>>18^t>>>3^t<<25^t<<14)+(S>>>17^S>>>19^S>>>10^S<<15^S<<13)+e+g|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+430227734|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;t=_=(n>>>7^n>>>18^n>>>3^n<<25^n<<14)+(x>>>17^x>>>19^x>>>10^x<<15^x<<13)+t+y|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+506948616|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;n=_=(c>>>7^c>>>18^c>>>3^c<<25^c<<14)+(e>>>17^e>>>19^e>>>10^e<<15^e<<13)+n+b|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+659060556|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;c=_=(h>>>7^h>>>18^h>>>3^h<<25^h<<14)+(t>>>17^t>>>19^t>>>10^t<<15^t<<13)+c+w|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+883997877|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;h=_=(p>>>7^p>>>18^p>>>3^p<<25^p<<14)+(n>>>17^n>>>19^n>>>10^n<<15^n<<13)+h+E|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+958139571|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;p=_=(d>>>7^d>>>18^d>>>3^d<<25^d<<14)+(c>>>17^c>>>19^c>>>10^c<<15^c<<13)+p+S|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1322822218|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;d=_=(v>>>7^v>>>18^v>>>3^v<<25^v<<14)+(h>>>17^h>>>19^h>>>10^h<<15^h<<13)+d+x|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1537002063|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;v=_=(m>>>7^m>>>18^m>>>3^m<<25^m<<14)+(p>>>17^p>>>19^p>>>10^p<<15^p<<13)+v+e|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1747873779|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;m=_=(g>>>7^g>>>18^g>>>3^g<<25^g<<14)+(d>>>17^d>>>19^d>>>10^d<<15^d<<13)+m+t|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+1955562222|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;g=_=(y>>>7^y>>>18^y>>>3^y<<25^y<<14)+(v>>>17^v>>>19^v>>>10^v<<15^v<<13)+g+n|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2024104815|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;y=_=(b>>>7^b>>>18^b>>>3^b<<25^b<<14)+(m>>>17^m>>>19^m>>>10^m<<15^m<<13)+y+c|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2227730452|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;b=_=(w>>>7^w>>>18^w>>>3^w<<25^w<<14)+(g>>>17^g>>>19^g>>>10^g<<15^g<<13)+b+h|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2361852424|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;w=_=(E>>>7^E>>>18^E>>>3^E<<25^E<<14)+(y>>>17^y>>>19^y>>>10^y<<15^y<<13)+w+p|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2428436474|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;E=_=(S>>>7^S>>>18^S>>>3^S<<25^S<<14)+(b>>>17^b>>>19^b>>>10^b<<15^b<<13)+E+d|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+2756734187|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;S=_=(x>>>7^x>>>18^x>>>3^x<<25^x<<14)+(w>>>17^w>>>19^w>>>10^w<<15^w<<13)+S+v|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3204031479|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;x=_=(e>>>7^e>>>18^e>>>3^e<<25^e<<14)+(E>>>17^E>>>19^E>>>10^E<<15^E<<13)+x+m|0;_=_+M+(L>>>6^L>>>11^L>>>25^L<<26^L<<21^L<<7)+(O^L&(A^O))+3329325298|0;M=O;O=A;A=L;L=k+_|0;k=C;C=N;N=T;T=_+(N&C^k&(N^C))+(N>>>2^N>>>13^N>>>22^N<<30^N<<19^N<<10)|0;r=r+T|0;i=i+N|0;s=s+C|0;o=o+k|0;u=u+L|0;a=a+A|0;f=f+O|0;l=l+M|0}function O(e){e=e|0;A(L[e|0]<<24|L[e|1]<<16|L[e|2]<<8|L[e|3],L[e|4]<<24|L[e|5]<<16|L[e|6]<<8|L[e|7],L[e|8]<<24|L[e|9]<<16|L[e|10]<<8|L[e|11],L[e|12]<<24|L[e|13]<<16|L[e|14]<<8|L[e|15],L[e|16]<<24|L[e|17]<<16|L[e|18]<<8|L[e|19],L[e|20]<<24|L[e|21]<<16|L[e|22]<<8|L[e|23],L[e|24]<<24|L[e|25]<<16|L[e|26]<<8|L[e|27],L[e|28]<<24|L[e|29]<<16|L[e|30]<<8|L[e|31],L[e|32]<<24|L[e|33]<<16|L[e|34]<<8|L[e|35],L[e|36]<<24|L[e|37]<<16|L[e|38]<<8|L[e|39],L[e|40]<<24|L[e|41]<<16|L[e|42]<<8|L[e|43],L[e|44]<<24|L[e|45]<<16|L[e|46]<<8|L[e|47],L[e|48]<<24|L[e|49]<<16|L[e|50]<<8|L[e|51],L[e|52]<<24|L[e|53]<<16|L[e|54]<<8|L[e|55],L[e|56]<<24|L[e|57]<<16|L[e|58]<<8|L[e|59],L[e|60]<<24|L[e|61]<<16|L[e|62]<<8|L[e|63])}function M(e){e=e|0;L[e|0]=r>>>24;L[e|1]=r>>>16&255;L[e|2]=r>>>8&255;L[e|3]=r&255;L[e|4]=i>>>24;L[e|5]=i>>>16&255;L[e|6]=i>>>8&255;L[e|7]=i&255;L[e|8]=s>>>24;L[e|9]=s>>>16&255;L[e|10]=s>>>8&255;L[e|11]=s&255;L[e|12]=o>>>24;L[e|13]=o>>>16&255;L[e|14]=o>>>8&255;L[e|15]=o&255;L[e|16]=u>>>24;L[e|17]=u>>>16&255;L[e|18]=u>>>8&255;L[e|19]=u&255;L[e|20]=a>>>24;L[e|21]=a>>>16&255;L[e|22]=a>>>8&255;L[e|23]=a&255;L[e|24]=f>>>24;L[e|25]=f>>>16&255;L[e|26]=f>>>8&255;L[e|27]=f&255;L[e|28]=l>>>24;L[e|29]=l>>>16&255;L[e|30]=l>>>8&255;L[e|31]=l&255}function _(){r=1779033703;i=3144134277;s=1013904242;o=2773480762;u=1359893119;a=2600822924;f=528734635;l=1541459225;c=0}function D(e,t,n,h,p,d,v,m,g){e=e|0;t=t|0;n=n|0;h=h|0;p=p|0;d=d|0;v=v|0;m=m|0;g=g|0;r=e;i=t;s=n;o=h;u=p;a=d;f=v;l=m;c=g}function P(e,t){e=e|0;t=t|0;var n=0;if(e&63)return-1;while((t|0)>=64){O(e);e=e+64|0;t=t-64|0;n=n+64|0}c=c+n|0;return n|0}function H(e,t,n){e=e|0;t=t|0;n=n|0;var r=0,i=0;if(e&63)return-1;if(~n)if(n&31)return-1;if((t|0)>=64){r=P(e,t)|0;if((r|0)==-1)return-1;e=e+r|0;t=t-r|0}r=r+t|0;c=c+t|0;L[e|t]=128;if((t|0)>=56){for(i=t+1|0;(i|0)<64;i=i+1|0)L[e|i]=0;O(e);t=0;L[e|0]=0}for(i=t+1|0;(i|0)<59;i=i+1|0)L[e|i]=0;L[e|59]=c>>>29;L[e|60]=c>>>21&255;L[e|61]=c>>>13&255;L[e|62]=c>>>5&255;L[e|63]=c<<3&255;O(e);if(~n)M(n);return r|0}function B(){r=h;i=p;s=d;o=v;u=m;a=g;f=y;l=b;c=64}function j(){r=w;i=E;s=S;o=x;u=T;a=N;f=C;l=k;c=64}function F(e,t,n,L,O,M,D,P,H,B,j,F,I,q,R,U){e=e|0;t=t|0;n=n|0;L=L|0;O=O|0;M=M|0;D=D|0;P=P|0;H=H|0;B=B|0;j=j|0;F=F|0;I=I|0;q=q|0;R=R|0;U=U|0;_();A(e^1549556828,t^1549556828,n^1549556828,L^1549556828,O^1549556828,M^1549556828,D^1549556828,P^1549556828,H^1549556828,B^1549556828,j^1549556828,F^1549556828,I^1549556828,q^1549556828,R^1549556828,U^1549556828);w=r;E=i;S=s;x=o;T=u;N=a;C=f;k=l;_();A(e^909522486,t^909522486,n^909522486,L^909522486,O^909522486,M^909522486,D^909522486,P^909522486,H^909522486,B^909522486,j^909522486,F^909522486,I^909522486,q^909522486,R^909522486,U^909522486);h=r;p=i;d=s;v=o;m=u;g=a;y=f;b=l;c=64}function I(e,t,n){e=e|0;t=t|0;n=n|0;var c=0,h=0,p=0,d=0,v=0,m=0,g=0,y=0,b=0;if(e&63)return-1;if(~n)if(n&31)return-1;b=H(e,t,-1)|0;c=r,h=i,p=s,d=o,v=u,m=a,g=f,y=l;j();A(c,h,p,d,v,m,g,y,2147483648,0,0,0,0,0,0,768);if(~n)M(n);return b|0}function q(e,t,n,c,h){e=e|0;t=t|0;n=n|0;c=c|0;h=h|0;var p=0,d=0,v=0,m=0,g=0,y=0,b=0,w=0,E=0,S=0,x=0,T=0,N=0,C=0,k=0,O=0;if(e&63)return-1;if(~h)if(h&31)return-1;L[e+t|0]=n>>>24;L[e+t+1|0]=n>>>16&255;L[e+t+2|0]=n>>>8&255;L[e+t+3|0]=n&255;I(e,t+4|0,-1)|0;p=E=r,d=S=i,v=x=s,m=T=o,g=N=u,y=C=a,b=k=f,w=O=l;c=c-1|0;while((c|0)>0){B();A(E,S,x,T,N,C,k,O,2147483648,0,0,0,0,0,0,768);E=r,S=i,x=s,T=o,N=u,C=a,k=f,O=l;j();A(E,S,x,T,N,C,k,O,2147483648,0,0,0,0,0,0,768);E=r,S=i,x=s,T=o,N=u,C=a,k=f,O=l;p=p^r;d=d^i;v=v^s;m=m^o;g=g^u;y=y^a;b=b^f;w=w^l;c=c-1|0}r=p;i=d;s=v;o=m;u=g;a=y;f=b;l=w;if(~h)M(h)}return{reset:_,init:D,process:P,finish:H,hmac_reset:B,hmac_init:F,hmac_finish:I,pbkdf2_generate_block:q}'))( stdlib, foreign, buffer );
}
