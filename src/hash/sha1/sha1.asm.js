function sha1_asm ( stdlib, foreign, buffer ) {
    "use asm";

    // SHA256 state
    var H0 = 0, H1 = 0, H2 = 0, H3 = 0, H4 = 0, TOTAL = 0;

    // HMAC state
    var I0 = 0, I1 = 0, I2 = 0, I3 = 0, I4 = 0,
        O0 = 0, O1 = 0, O2 = 0, O3 = 0, O4 = 0;

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

        var a = 0, b = 0, c = 0, d = 0, e = 0, n = 0, t = 0,
            w16 = 0, w17 = 0, w18 = 0, w19 = 0,
            w20 = 0, w21 = 0, w22 = 0, w23 = 0, w24 = 0, w25 = 0, w26 = 0, w27 = 0, w28 = 0, w29 = 0,
            w30 = 0, w31 = 0, w32 = 0, w33 = 0, w34 = 0, w35 = 0, w36 = 0, w37 = 0, w38 = 0, w39 = 0,
            w40 = 0, w41 = 0, w42 = 0, w43 = 0, w44 = 0, w45 = 0, w46 = 0, w47 = 0, w48 = 0, w49 = 0,
            w50 = 0, w51 = 0, w52 = 0, w53 = 0, w54 = 0, w55 = 0, w56 = 0, w57 = 0, w58 = 0, w59 = 0,
            w60 = 0, w61 = 0, w62 = 0, w63 = 0, w64 = 0, w65 = 0, w66 = 0, w67 = 0, w68 = 0, w69 = 0,
            w70 = 0, w71 = 0, w72 = 0, w73 = 0, w74 = 0, w75 = 0, w76 = 0, w77 = 0, w78 = 0, w79 = 0;

        a = H0;
        b = H1;
        c = H2;
        d = H3;
        e = H4;

        // 0
        t = ( w0 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 1
        t = ( w1 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 2
        t = ( w2 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 3
        t = ( w3 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 4
        t = ( w4 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 5
        t = ( w5 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 6
        t = ( w6 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 7
        t = ( w7 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 8
        t = ( w8 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 9
        t = ( w9 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 10
        t = ( w10 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 11
        t = ( w11 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 12
        t = ( w12 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 13
        t = ( w13 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 14
        t = ( w14 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 15
        t = ( w15 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 16
        n = w13 ^ w8 ^ w2 ^ w0;
        w16 = (n << 1) | (n >>> 31);
        t = (w16 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 17
        n = w14 ^ w9 ^ w3 ^ w1;
        w17 = (n << 1) | (n >>> 31);
        t = (w17 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 18
        n = w15 ^ w10 ^ w4 ^ w2;
        w18 = (n << 1) | (n >>> 31);
        t = (w18 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 19
        n = w16 ^ w11 ^ w5 ^ w3;
        w19 = (n << 1) | (n >>> 31);
        t = (w19 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (~b & d)) + 0x5a827999 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 20
        n = w17 ^ w12 ^ w6 ^ w4;
        w20 = (n << 1) | (n >>> 31);
        t = (w20 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 21
        n = w18 ^ w13 ^ w7 ^ w5;
        w21 = (n << 1) | (n >>> 31);
        t = (w21 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 22
        n = w19 ^ w14 ^ w8 ^ w6;
        w22 = (n << 1) | (n >>> 31);
        t = (w22 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 23
        n = w20 ^ w15 ^ w9 ^ w7;
        w23 = (n << 1) | (n >>> 31);
        t = (w23 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 24
        n = w21 ^ w16 ^ w10 ^ w8;
        w24 = (n << 1) | (n >>> 31);
        t = (w24 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 25
        n = w22 ^ w17 ^ w11 ^ w9;
        w25 = (n << 1) | (n >>> 31);
        t = (w25 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 26
        n = w23 ^ w18 ^ w12 ^ w10;
        w26 = (n << 1) | (n >>> 31);
        t = (w26 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 27
        n = w24 ^ w19 ^ w13 ^ w11;
        w27 = (n << 1) | (n >>> 31);
        t = (w27 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 28
        n = w25 ^ w20 ^ w14 ^ w12;
        w28 = (n << 1) | (n >>> 31);
        t = (w28 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 29
        n = w26 ^ w21 ^ w15 ^ w13;
        w29 = (n << 1) | (n >>> 31);
        t = (w29 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 30
        n = w27 ^ w22 ^ w16 ^ w14;
        w30 = (n << 1) | (n >>> 31);
        t = (w30 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 31
        n = w28 ^ w23 ^ w17 ^ w15;
        w31 = (n << 1) | (n >>> 31);
        t = (w31 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 32
        n = w29 ^ w24 ^ w18 ^ w16;
        w32 = (n << 1) | (n >>> 31);
        t = (w32 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 33
        n = w30 ^ w25 ^ w19 ^ w17;
        w33 = (n << 1) | (n >>> 31);
        t = (w33 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 34
        n = w31 ^ w26 ^ w20 ^ w18;
        w34 = (n << 1) | (n >>> 31);
        t = (w34 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 35
        n = w32 ^ w27 ^ w21 ^ w19;
        w35 = (n << 1) | (n >>> 31);
        t = (w35 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 36
        n = w33 ^ w28 ^ w22 ^ w20;
        w36 = (n << 1) | (n >>> 31);
        t = (w36 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 37
        n = w34 ^ w29 ^ w23 ^ w21;
        w37 = (n << 1) | (n >>> 31);
        t = (w37 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 38
        n = w35 ^ w30 ^ w24 ^ w22;
        w38 = (n << 1) | (n >>> 31);
        t = (w38 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 39
        n = w36 ^ w31 ^ w25 ^ w23;
        w39 = (n << 1) | (n >>> 31);
        t = (w39 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) + 0x6ed9eba1 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 40
        n = w37 ^ w32 ^ w26 ^ w24;
        w40 = (n << 1) | (n >>> 31);
        t = (w40 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 41
        n = w38 ^ w33 ^ w27 ^ w25;
        w41 = (n << 1) | (n >>> 31);
        t = (w41 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 42
        n = w39 ^ w34 ^ w28 ^ w26;
        w42 = (n << 1) | (n >>> 31);
        t = (w42 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 43
        n = w40 ^ w35 ^ w29 ^ w27;
        w43 = (n << 1) | (n >>> 31);
        t = (w43 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 44
        n = w41 ^ w36 ^ w30 ^ w28;
        w44 = (n << 1) | (n >>> 31);
        t = (w44 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 45
        n = w42 ^ w37 ^ w31 ^ w29;
        w45 = (n << 1) | (n >>> 31);
        t = (w45 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 46
        n = w43 ^ w38 ^ w32 ^ w30;
        w46 = (n << 1) | (n >>> 31);
        t = (w46 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 47
        n = w44 ^ w39 ^ w33 ^ w31;
        w47 = (n << 1) | (n >>> 31);
        t = (w47 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 48
        n = w45 ^ w40 ^ w34 ^ w32;
        w48 = (n << 1) | (n >>> 31);
        t = (w48 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 49
        n = w46 ^ w41 ^ w35 ^ w33;
        w49 = (n << 1) | (n >>> 31);
        t = (w49 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 50
        n = w47 ^ w42 ^ w36 ^ w34;
        w50 = (n << 1) | (n >>> 31);
        t = (w50 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 51
        n = w48 ^ w43 ^ w37 ^ w35;
        w51 = (n << 1) | (n >>> 31);
        t = (w51 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 52
        n = w49 ^ w44 ^ w38 ^ w36;
        w52 = (n << 1) | (n >>> 31);
        t = (w52 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 53
        n = w50 ^ w45 ^ w39 ^ w37;
        w53 = (n << 1) | (n >>> 31);
        t = (w53 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 54
        n = w51 ^ w46 ^ w40 ^ w38;
        w54 = (n << 1) | (n >>> 31);
        t = (w54 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 55
        n = w52 ^ w47 ^ w41 ^ w39;
        w55 = (n << 1) | (n >>> 31);
        t = (w55 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 56
        n = w53 ^ w48 ^ w42 ^ w40;
        w56 = (n << 1) | (n >>> 31);
        t = (w56 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 57
        n = w54 ^ w49 ^ w43 ^ w41;
        w57 = (n << 1) | (n >>> 31);
        t = (w57 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 58
        n = w55 ^ w50 ^ w44 ^ w42;
        w58 = (n << 1) | (n >>> 31);
        t = (w58 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 59
        n = w56 ^ w51 ^ w45 ^ w43;
        w59 = (n << 1) | (n >>> 31);
        t = (w59 + ((a << 5) | (a >>> 27)) + e + ((b & c) | (b & d) | (c & d)) - 0x70e44324 )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 60
        n = w57 ^ w52 ^ w46 ^ w44;
        w60 = (n << 1) | (n >>> 31);
        t = (w60 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 61
        n = w58 ^ w53 ^ w47 ^ w45;
        w61 = (n << 1) | (n >>> 31);
        t = (w61 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 62
        n = w59 ^ w54 ^ w48 ^ w46;
        w62 = (n << 1) | (n >>> 31);
        t = (w62 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 63
        n = w60 ^ w55 ^ w49 ^ w47;
        w63 = (n << 1) | (n >>> 31);
        t = (w63 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 64
        n = w61 ^ w56 ^ w50 ^ w48;
        w64 = (n << 1) | (n >>> 31);
        t = (w64 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 65
        n = w62 ^ w57 ^ w51 ^ w49;
        w65 = (n << 1) | (n >>> 31);
        t = (w65 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 66
        n = w63 ^ w58 ^ w52 ^ w50;
        w66 = (n << 1) | (n >>> 31);
        t = (w66 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 67
        n = w64 ^ w59 ^ w53 ^ w51;
        w67 = (n << 1) | (n >>> 31);
        t = (w67 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 68
        n = w65 ^ w60 ^ w54 ^ w52;
        w68 = (n << 1) | (n >>> 31);
        t = (w68 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 69
        n = w66 ^ w61 ^ w55 ^ w53;
        w69 = (n << 1) | (n >>> 31);
        t = (w69 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 70
        n = w67 ^ w62 ^ w56 ^ w54;
        w70 = (n << 1) | (n >>> 31);
        t = (w70 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 71
        n = w68 ^ w63 ^ w57 ^ w55;
        w71 = (n << 1) | (n >>> 31);
        t = (w71 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 72
        n = w69 ^ w64 ^ w58 ^ w56;
        w72 = (n << 1) | (n >>> 31);
        t = (w72 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 73
        n = w70 ^ w65 ^ w59 ^ w57;
        w73 = (n << 1) | (n >>> 31);
        t = (w73 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 74
        n = w71 ^ w66 ^ w60 ^ w58;
        w74 = (n << 1) | (n >>> 31);
        t = (w74 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 75
        n = w72 ^ w67 ^ w61 ^ w59;
        w75 = (n << 1) | (n >>> 31);
        t = (w75 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 76
        n = w73 ^ w68 ^ w62 ^ w60;
        w76 = (n << 1) | (n >>> 31);
        t = (w76 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 77
        n = w74 ^ w69 ^ w63 ^ w61;
        w77 = (n << 1) | (n >>> 31);
        t = (w77 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 78
        n = w75 ^ w70 ^ w64 ^ w62;
        w78 = (n << 1) | (n >>> 31);
        t = (w78 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        // 79
        n = w76 ^ w71 ^ w65 ^ w63;
        w79 = (n << 1) | (n >>> 31);
        t = (w79 + ((a << 5) | (a >>> 27)) + e + (b ^ c ^ d) - 0x359d3e2a )|0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;

        H0 = ( H0 + a )|0;
        H1 = ( H1 + b )|0;
        H2 = ( H2 + c )|0;
        H3 = ( H3 + d )|0;
        H4 = ( H4 + e )|0;

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
    }

    function reset () {
        H0 = 0x67452301;
        H1 = 0xefcdab89;
        H2 = 0x98badcfe;
        H3 = 0x10325476;
        H4 = 0xc3d2e1f0;
        TOTAL = 0;
    }

    function init ( h0, h1, h2, h3, h4, total ) {
        h0 = h0|0;
        h1 = h1|0;
        h2 = h2|0;
        h3 = h3|0;
        h4 = h4|0;
        total = total|0;

        H0 = h0;
        H1 = h1;
        H2 = h2;
        H3 = h3;
        H4 = h4;
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

        hashed = ( hashed + length )|0;
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
        HEAP[offset|61] = TOTAL>>>13&255;
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
        TOTAL = 64;
    }

    function _hmac_opad () {
        H0 = O0;
        H1 = O1;
        H2 = O2;
        H3 = O3;
        H4 = O4;
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

        TOTAL = 64;
    }

    // offset — multiple of 64
    // output — multiple of 32
    function hmac_finish ( offset, length, output ) {
        offset = offset|0;
        length = length|0;
        output = output|0;

        var t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, hashed = 0;

        if ( offset & 63 )
            return -1;

        if ( ~output )
            if ( output & 31 )
                return -1;

        hashed = finish( offset, length, -1 )|0;
        t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4;

        _hmac_opad();
        _core( t0, t1, t2, t3, t4, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 672 );

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
        count = count|0;
        output = output|0;

        var h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0,
            t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;

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
        h0 = t0 = H0, h1 = t1 = H1, h2 = t2 = H2, h3 = t3 = H3, h4 = t4 = H4;
        count = (count-1)|0;

        // perform the rest iterations
        while ( (count|0) > 0 ) {
            hmac_reset();
            _core( t0, t1, t2, t3, t4, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 672 );
            t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4;

            _hmac_opad();
            _core( t0, t1, t2, t3, t4, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 672 );
            t0 = H0, t1 = H1, t2 = H2, t3 = H3, t4 = H4;

            h0 = h0 ^ H0;
            h1 = h1 ^ H1;
            h2 = h2 ^ H2;
            h3 = h3 ^ H3;
            h4 = h4 ^ H4;

            count = (count-1)|0;
        }

        H0 = h0;
        H1 = h1;
        H2 = h2;
        H3 = h3;
        H4 = h4;

        if ( ~output )
            _state_to_heap(output);

        return 0;
    }

    return {
        // SHA1
        reset: reset,
        init: init,
        process: process,
        finish: finish,

        // HMAC-SHA1
        hmac_reset: hmac_reset,
        hmac_init: hmac_init,
        hmac_finish: hmac_finish,

        // PBKDF2-HMAC-SHA1
        pbkdf2_generate_block: pbkdf2_generate_block
    }
}
