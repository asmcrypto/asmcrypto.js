/*
function sha256_asm ( stdlib, foreign, buffer ) {
    "use asm";

    // SHA256 const
    var H00 = 0x6A09E667, H01 = 0xBB67AE85, H02 = 0x3C6EF372, H03 = 0xA54FF53A, H04 = 0x510E527F, H05 = 0x9B05688C, H06 = 0x1F83D9AB, H07 = 0x5BE0CD19;

    var K00 = 0x428A2F98, K01 = 0x71374491, K02 = 0xB5C0FBCF, K03 = 0xE9B5DBA5, K04 = 0x3956C25B, K05 = 0x59F111F1, K06 = 0x923F82A4, K07 = 0xAB1C5ED5,
        K08 = 0xD807AA98, K09 = 0x12835B01, K10 = 0x243185BE, K11 = 0x550C7DC3, K12 = 0x72BE5D74, K13 = 0x80DEB1FE, K14 = 0x9BDC06A7, K15 = 0xC19BF174,
        K16 = 0xE49B69C1, K17 = 0xEFBE4786, K18 = 0x0FC19DC6, K19 = 0x240CA1CC, K20 = 0x2DE92C6F, K21 = 0x4A7484AA, K22 = 0x5CB0A9DC, K23 = 0x76F988DA,
        K24 = 0x983E5152, K25 = 0xA831C66D, K26 = 0xB00327C8, K27 = 0xBF597FC7, K28 = 0xC6E00BF3, K29 = 0xD5A79147, K30 = 0x06CA6351, K31 = 0x14292967,
        K32 = 0x27B70A85, K33 = 0x2E1B2138, K34 = 0x4D2C6DFC, K35 = 0x53380D13, K36 = 0x650A7354, K37 = 0x766A0ABB, K38 = 0x81C2C92E, K39 = 0x92722C85,
        K40 = 0xA2BFE8A1, K41 = 0xA81A664B, K42 = 0xC24B8B70, K43 = 0xC76C51A3, K44 = 0xD192E819, K45 = 0xD6990624, K46 = 0xF40E3585, K47 = 0x106AA070,
        K48 = 0x19A4C116, K49 = 0x1E376C08, K50 = 0x2748774C, K51 = 0x34B0BCB5, K52 = 0x391C0CB3, K53 = 0x4ED8AA4A, K54 = 0x5B9CCA4F, K55 = 0x682E6FF3,
        K56 = 0x748F82EE, K57 = 0x78A5636F, K58 = 0x84C87814, K59 = 0x8CC70208, K60 = 0x90BEFFFA, K61 = 0xA4506CEB, K62 = 0xBEF9A3F7, K63 = 0xC67178F2;

    // SHA256 block
    var W00 = 0, W01 = 0, W02 = 0, W03 = 0, W04 = 0, W05 = 0, W06 = 0, W07 = 0, W08 = 0, W09 = 0, W10 = 0, W11 = 0, W12 = 0, W13 = 0, W14 = 0, W15 = 0;

    // SHA256 state
    var ST0 = 0, ST1 = 0, ST2 = 0, ST3 = 0, ST4 = 0, ST5 = 0, ST6 = 0, ST7 = 0,
        TOTAL = 0;

    // HMAC state
    var I0 = 0, I1 = 0, I2 = 0, I3 = 0, I4 = 0, I5 = 0, I6 = 0, I7 = 0,
        O0 = 0, O1 = 0, O2 = 0, O3 = 0, O4 = 0, O5 = 0, O6 = 0, O7 = 0;

    // I/O buffer
    var HEAP = new stdlib.Uint8Array(buffer);

    function _core () {
        var A = 0, B = 0, C = 0, D = 0, E = 0, F = 0, G = 0, H = 0,
            T = 0;

        A = ST0;
        B = ST1;
        C = ST2;
        D = ST3;
        E = ST4;
        F = ST5;
        G = ST6;
        H = ST7;

        // 0
        T = ( W00 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K00 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 1
        T = ( W01 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K01 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 2
        T = ( W02 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K02 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 3
        T = ( W03 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K03 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 4
        T = ( W04 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K04 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 5
        T = ( W05 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K05 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 6
        T = ( W06 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K06 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 7
        T = ( W07 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K07 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 8
        T = ( W08 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K08 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 9
        T = ( W09 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K09 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 10
        T = ( W10 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K10 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 11
        T = ( W11 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K11 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 12
        T = ( W12 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K12 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 13
        T = ( W13 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K13 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 14
        T = ( W14 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K14 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 15
        T = ( W15 + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K15 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 16
        W00 = T = ( ( W01>>>7  ^ W01>>>18 ^ W01>>>3  ^ W01<<25 ^ W01<<14 ) + ( W14>>>17 ^ W14>>>19 ^ W14>>>10 ^ W14<<15 ^ W14<<13 ) + W00 + W09 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K16 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 17
        W01 = T = ( ( W02>>>7  ^ W02>>>18 ^ W02>>>3  ^ W02<<25 ^ W02<<14 ) + ( W15>>>17 ^ W15>>>19 ^ W15>>>10 ^ W15<<15 ^ W15<<13 ) + W01 + W10 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K17 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 18
        W02 = T = ( ( W03>>>7  ^ W03>>>18 ^ W03>>>3  ^ W03<<25 ^ W03<<14 ) + ( W00>>>17 ^ W00>>>19 ^ W00>>>10 ^ W00<<15 ^ W00<<13 ) + W02 + W11 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K18 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 19
        W03 = T = ( ( W04>>>7  ^ W04>>>18 ^ W04>>>3  ^ W04<<25 ^ W04<<14 ) + ( W01>>>17 ^ W01>>>19 ^ W01>>>10 ^ W01<<15 ^ W01<<13 ) + W03 + W12 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K19 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 20
        W04 = T = ( ( W05>>>7  ^ W05>>>18 ^ W05>>>3  ^ W05<<25 ^ W05<<14 ) + ( W02>>>17 ^ W02>>>19 ^ W02>>>10 ^ W02<<15 ^ W02<<13 ) + W04 + W13 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K20 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 21
        W05 = T = ( ( W06>>>7  ^ W06>>>18 ^ W06>>>3  ^ W06<<25 ^ W06<<14 ) + ( W03>>>17 ^ W03>>>19 ^ W03>>>10 ^ W03<<15 ^ W03<<13 ) + W05 + W14 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K21 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 22
        W06 = T = ( ( W07>>>7  ^ W07>>>18 ^ W07>>>3  ^ W07<<25 ^ W07<<14 ) + ( W04>>>17 ^ W04>>>19 ^ W04>>>10 ^ W04<<15 ^ W04<<13 ) + W06 + W15 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K22 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 23
        W07 = T = ( ( W08>>>7  ^ W08>>>18 ^ W08>>>3  ^ W08<<25 ^ W08<<14 ) + ( W05>>>17 ^ W05>>>19 ^ W05>>>10 ^ W05<<15 ^ W05<<13 ) + W07 + W00 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K23 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 24
        W08 = T = ( ( W09>>>7  ^ W09>>>18 ^ W09>>>3  ^ W09<<25 ^ W09<<14 ) + ( W06>>>17 ^ W06>>>19 ^ W06>>>10 ^ W06<<15 ^ W06<<13 ) + W08 + W01 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K24 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 25
        W09 = T = ( ( W10>>>7  ^ W10>>>18 ^ W10>>>3  ^ W10<<25 ^ W10<<14 ) + ( W07>>>17 ^ W07>>>19 ^ W07>>>10 ^ W07<<15 ^ W07<<13 ) + W09 + W02 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K25 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 26
        W10 = T = ( ( W11>>>7  ^ W11>>>18 ^ W11>>>3  ^ W11<<25 ^ W11<<14 ) + ( W08>>>17 ^ W08>>>19 ^ W08>>>10 ^ W08<<15 ^ W08<<13 ) + W10 + W03 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K26 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 27
        W11 = T = ( ( W12>>>7  ^ W12>>>18 ^ W12>>>3  ^ W12<<25 ^ W12<<14 ) + ( W09>>>17 ^ W09>>>19 ^ W09>>>10 ^ W09<<15 ^ W09<<13 ) + W11 + W04 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K27 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 28
        W12 = T = ( ( W13>>>7  ^ W13>>>18 ^ W13>>>3  ^ W13<<25 ^ W13<<14 ) + ( W10>>>17 ^ W10>>>19 ^ W10>>>10 ^ W10<<15 ^ W10<<13 ) + W12 + W05 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K28 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 29
        W13 = T = ( ( W14>>>7  ^ W14>>>18 ^ W14>>>3  ^ W14<<25 ^ W14<<14 ) + ( W11>>>17 ^ W11>>>19 ^ W11>>>10 ^ W11<<15 ^ W11<<13 ) + W13 + W06 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K29 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 30
        W14 = T = ( ( W15>>>7  ^ W15>>>18 ^ W15>>>3  ^ W15<<25 ^ W15<<14 ) + ( W12>>>17 ^ W12>>>19 ^ W12>>>10 ^ W12<<15 ^ W12<<13 ) + W14 + W07 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K30 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 31
        W15 = T = ( ( W00>>>7  ^ W00>>>18 ^ W00>>>3  ^ W00<<25 ^ W00<<14 ) + ( W13>>>17 ^ W13>>>19 ^ W13>>>10 ^ W13<<15 ^ W13<<13 ) + W15 + W08 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K31 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 32
        W00 = T = ( ( W01>>>7  ^ W01>>>18 ^ W01>>>3  ^ W01<<25 ^ W01<<14 ) + ( W14>>>17 ^ W14>>>19 ^ W14>>>10 ^ W14<<15 ^ W14<<13 ) + W00 + W09 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K32 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 33
        W01 = T = ( ( W02>>>7  ^ W02>>>18 ^ W02>>>3  ^ W02<<25 ^ W02<<14 ) + ( W15>>>17 ^ W15>>>19 ^ W15>>>10 ^ W15<<15 ^ W15<<13 ) + W01 + W10 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K33 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 34
        W02 = T = ( ( W03>>>7  ^ W03>>>18 ^ W03>>>3  ^ W03<<25 ^ W03<<14 ) + ( W00>>>17 ^ W00>>>19 ^ W00>>>10 ^ W00<<15 ^ W00<<13 ) + W02 + W11 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K34 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 35
        W03 = T = ( ( W04>>>7  ^ W04>>>18 ^ W04>>>3  ^ W04<<25 ^ W04<<14 ) + ( W01>>>17 ^ W01>>>19 ^ W01>>>10 ^ W01<<15 ^ W01<<13 ) + W03 + W12 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K35 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 36
        W04 = T = ( ( W05>>>7  ^ W05>>>18 ^ W05>>>3  ^ W05<<25 ^ W05<<14 ) + ( W02>>>17 ^ W02>>>19 ^ W02>>>10 ^ W02<<15 ^ W02<<13 ) + W04 + W13 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K36 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 37
        W05 = T = ( ( W06>>>7  ^ W06>>>18 ^ W06>>>3  ^ W06<<25 ^ W06<<14 ) + ( W03>>>17 ^ W03>>>19 ^ W03>>>10 ^ W03<<15 ^ W03<<13 ) + W05 + W14 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K37 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 38
        W06 = T = ( ( W07>>>7  ^ W07>>>18 ^ W07>>>3  ^ W07<<25 ^ W07<<14 ) + ( W04>>>17 ^ W04>>>19 ^ W04>>>10 ^ W04<<15 ^ W04<<13 ) + W06 + W15 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K38 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 39
        W07 = T = ( ( W08>>>7  ^ W08>>>18 ^ W08>>>3  ^ W08<<25 ^ W08<<14 ) + ( W05>>>17 ^ W05>>>19 ^ W05>>>10 ^ W05<<15 ^ W05<<13 ) + W07 + W00 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K39 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 40
        W08 = T = ( ( W09>>>7  ^ W09>>>18 ^ W09>>>3  ^ W09<<25 ^ W09<<14 ) + ( W06>>>17 ^ W06>>>19 ^ W06>>>10 ^ W06<<15 ^ W06<<13 ) + W08 + W01 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K40 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 41
        W09 = T = ( ( W10>>>7  ^ W10>>>18 ^ W10>>>3  ^ W10<<25 ^ W10<<14 ) + ( W07>>>17 ^ W07>>>19 ^ W07>>>10 ^ W07<<15 ^ W07<<13 ) + W09 + W02 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K41 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 42
        W10 = T = ( ( W11>>>7  ^ W11>>>18 ^ W11>>>3  ^ W11<<25 ^ W11<<14 ) + ( W08>>>17 ^ W08>>>19 ^ W08>>>10 ^ W08<<15 ^ W08<<13 ) + W10 + W03 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K42 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 43
        W11 = T = ( ( W12>>>7  ^ W12>>>18 ^ W12>>>3  ^ W12<<25 ^ W12<<14 ) + ( W09>>>17 ^ W09>>>19 ^ W09>>>10 ^ W09<<15 ^ W09<<13 ) + W11 + W04 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K43 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 44
        W12 = T = ( ( W13>>>7  ^ W13>>>18 ^ W13>>>3  ^ W13<<25 ^ W13<<14 ) + ( W10>>>17 ^ W10>>>19 ^ W10>>>10 ^ W10<<15 ^ W10<<13 ) + W12 + W05 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K44 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 45
        W13 = T = ( ( W14>>>7  ^ W14>>>18 ^ W14>>>3  ^ W14<<25 ^ W14<<14 ) + ( W11>>>17 ^ W11>>>19 ^ W11>>>10 ^ W11<<15 ^ W11<<13 ) + W13 + W06 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K45 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 46
        W14 = T = ( ( W15>>>7  ^ W15>>>18 ^ W15>>>3  ^ W15<<25 ^ W15<<14 ) + ( W12>>>17 ^ W12>>>19 ^ W12>>>10 ^ W12<<15 ^ W12<<13 ) + W14 + W07 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K46 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 47
        W15 = T = ( ( W00>>>7  ^ W00>>>18 ^ W00>>>3  ^ W00<<25 ^ W00<<14 ) + ( W13>>>17 ^ W13>>>19 ^ W13>>>10 ^ W13<<15 ^ W13<<13 ) + W15 + W08 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K47 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 48
        W00 = T = ( ( W01>>>7  ^ W01>>>18 ^ W01>>>3  ^ W01<<25 ^ W01<<14 ) + ( W14>>>17 ^ W14>>>19 ^ W14>>>10 ^ W14<<15 ^ W14<<13 ) + W00 + W09 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K48 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 49
        W01 = T = ( ( W02>>>7  ^ W02>>>18 ^ W02>>>3  ^ W02<<25 ^ W02<<14 ) + ( W15>>>17 ^ W15>>>19 ^ W15>>>10 ^ W15<<15 ^ W15<<13 ) + W01 + W10 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K49 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 50
        W02 = T = ( ( W03>>>7  ^ W03>>>18 ^ W03>>>3  ^ W03<<25 ^ W03<<14 ) + ( W00>>>17 ^ W00>>>19 ^ W00>>>10 ^ W00<<15 ^ W00<<13 ) + W02 + W11 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K50 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 51
        W03 = T = ( ( W04>>>7  ^ W04>>>18 ^ W04>>>3  ^ W04<<25 ^ W04<<14 ) + ( W01>>>17 ^ W01>>>19 ^ W01>>>10 ^ W01<<15 ^ W01<<13 ) + W03 + W12 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K51 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 52
        W04 = T = ( ( W05>>>7  ^ W05>>>18 ^ W05>>>3  ^ W05<<25 ^ W05<<14 ) + ( W02>>>17 ^ W02>>>19 ^ W02>>>10 ^ W02<<15 ^ W02<<13 ) + W04 + W13 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K52 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 53
        W05 = T = ( ( W06>>>7  ^ W06>>>18 ^ W06>>>3  ^ W06<<25 ^ W06<<14 ) + ( W03>>>17 ^ W03>>>19 ^ W03>>>10 ^ W03<<15 ^ W03<<13 ) + W05 + W14 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K53 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 54
        W06 = T = ( ( W07>>>7  ^ W07>>>18 ^ W07>>>3  ^ W07<<25 ^ W07<<14 ) + ( W04>>>17 ^ W04>>>19 ^ W04>>>10 ^ W04<<15 ^ W04<<13 ) + W06 + W15 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K54 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 55
        W07 = T = ( ( W08>>>7  ^ W08>>>18 ^ W08>>>3  ^ W08<<25 ^ W08<<14 ) + ( W05>>>17 ^ W05>>>19 ^ W05>>>10 ^ W05<<15 ^ W05<<13 ) + W07 + W00 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K55 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 56
        W08 = T = ( ( W09>>>7  ^ W09>>>18 ^ W09>>>3  ^ W09<<25 ^ W09<<14 ) + ( W06>>>17 ^ W06>>>19 ^ W06>>>10 ^ W06<<15 ^ W06<<13 ) + W08 + W01 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K56 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 57
        W09 = T = ( ( W10>>>7  ^ W10>>>18 ^ W10>>>3  ^ W10<<25 ^ W10<<14 ) + ( W07>>>17 ^ W07>>>19 ^ W07>>>10 ^ W07<<15 ^ W07<<13 ) + W09 + W02 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K57 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 58
        W10 = T = ( ( W11>>>7  ^ W11>>>18 ^ W11>>>3  ^ W11<<25 ^ W11<<14 ) + ( W08>>>17 ^ W08>>>19 ^ W08>>>10 ^ W08<<15 ^ W08<<13 ) + W10 + W03 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K58 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 59
        W11 = T = ( ( W12>>>7  ^ W12>>>18 ^ W12>>>3  ^ W12<<25 ^ W12<<14 ) + ( W09>>>17 ^ W09>>>19 ^ W09>>>10 ^ W09<<15 ^ W09<<13 ) + W11 + W04 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K59 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 60
        W12 = T = ( ( W13>>>7  ^ W13>>>18 ^ W13>>>3  ^ W13<<25 ^ W13<<14 ) + ( W10>>>17 ^ W10>>>19 ^ W10>>>10 ^ W10<<15 ^ W10<<13 ) + W12 + W05 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K60 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 61
        W13 = T = ( ( W14>>>7  ^ W14>>>18 ^ W14>>>3  ^ W14<<25 ^ W14<<14 ) + ( W11>>>17 ^ W11>>>19 ^ W11>>>10 ^ W11<<15 ^ W11<<13 ) + W13 + W06 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K61 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 62
        W14 = T = ( ( W15>>>7  ^ W15>>>18 ^ W15>>>3  ^ W15<<25 ^ W15<<14 ) + ( W12>>>17 ^ W12>>>19 ^ W12>>>10 ^ W12<<15 ^ W12<<13 ) + W14 + W07 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K62 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 63
        W15 = T = ( ( W00>>>7  ^ W00>>>18 ^ W00>>>3  ^ W00<<25 ^ W00<<14 ) + ( W13>>>17 ^ W13>>>19 ^ W13>>>10 ^ W13<<15 ^ W13<<13 ) + W15 + W08 )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K63 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        ST0 = ( ST0 + A )|0;
        ST1 = ( ST1 + B )|0;
        ST2 = ( ST2 + C )|0;
        ST3 = ( ST3 + D )|0;
        ST4 = ( ST4 + E )|0;
        ST5 = ( ST5 + F )|0;
        ST6 = ( ST6 + G )|0;
        ST7 = ( ST7 + H )|0;
    }

    // offset — multiple of 32
    function _state_to_heap ( offset ) {
        offset = offset|0;

        HEAP[offset|0] = ST0>>>24;
        HEAP[offset|1] = ST0>>>16&255;
        HEAP[offset|2] = ST0>>>8&255;
        HEAP[offset|3] = ST0&255;
        HEAP[offset|4] = ST1>>>24;
        HEAP[offset|5] = ST1>>>16&255;
        HEAP[offset|6] = ST1>>>8&255;
        HEAP[offset|7] = ST1&255;
        HEAP[offset|8] = ST2>>>24;
        HEAP[offset|9] = ST2>>>16&255;
        HEAP[offset|10] = ST2>>>8&255;
        HEAP[offset|11] = ST2&255;
        HEAP[offset|12] = ST3>>>24;
        HEAP[offset|13] = ST3>>>16&255;
        HEAP[offset|14] = ST3>>>8&255;
        HEAP[offset|15] = ST3&255;
        HEAP[offset|16] = ST4>>>24;
        HEAP[offset|17] = ST4>>>16&255;
        HEAP[offset|18] = ST4>>>8&255;
        HEAP[offset|19] = ST4&255;
        HEAP[offset|20] = ST5>>>24;
        HEAP[offset|21] = ST5>>>16&255;
        HEAP[offset|22] = ST5>>>8&255;
        HEAP[offset|23] = ST5&255;
        HEAP[offset|24] = ST6>>>24;
        HEAP[offset|25] = ST6>>>16&255;
        HEAP[offset|26] = ST6>>>8&255;
        HEAP[offset|27] = ST6&255;
        HEAP[offset|28] = ST7>>>24;
        HEAP[offset|29] = ST7>>>16&255;
        HEAP[offset|30] = ST7>>>8&255;
        HEAP[offset|31] = ST7&255;
    }

    function _heap_to_words ( offset ) {
        offset = offset|0;

        W00 = HEAP[offset|0]<<24 | HEAP[offset|1]<<16 | HEAP[offset|2]<<8 | HEAP[offset|3];
        W01 = HEAP[offset|4]<<24 | HEAP[offset|5]<<16 | HEAP[offset|6]<<8 | HEAP[offset|7];
        W02 = HEAP[offset|8]<<24 | HEAP[offset|9]<<16 | HEAP[offset|10]<<8 | HEAP[offset|11];
        W03 = HEAP[offset|12]<<24 | HEAP[offset|13]<<16 | HEAP[offset|14]<<8 | HEAP[offset|15];
        W04 = HEAP[offset|16]<<24 | HEAP[offset|17]<<16 | HEAP[offset|18]<<8 | HEAP[offset|19];
        W05 = HEAP[offset|20]<<24 | HEAP[offset|21]<<16 | HEAP[offset|22]<<8 | HEAP[offset|23];
        W06 = HEAP[offset|24]<<24 | HEAP[offset|25]<<16 | HEAP[offset|26]<<8 | HEAP[offset|27];
        W07 = HEAP[offset|28]<<24 | HEAP[offset|29]<<16 | HEAP[offset|30]<<8 | HEAP[offset|31];
        W08 = HEAP[offset|32]<<24 | HEAP[offset|33]<<16 | HEAP[offset|34]<<8 | HEAP[offset|35];
        W09 = HEAP[offset|36]<<24 | HEAP[offset|37]<<16 | HEAP[offset|38]<<8 | HEAP[offset|39];
        W10 = HEAP[offset|40]<<24 | HEAP[offset|41]<<16 | HEAP[offset|42]<<8 | HEAP[offset|43];
        W11 = HEAP[offset|44]<<24 | HEAP[offset|45]<<16 | HEAP[offset|46]<<8 | HEAP[offset|47];
        W12 = HEAP[offset|48]<<24 | HEAP[offset|49]<<16 | HEAP[offset|50]<<8 | HEAP[offset|51];
        W13 = HEAP[offset|52]<<24 | HEAP[offset|53]<<16 | HEAP[offset|54]<<8 | HEAP[offset|55];
        W14 = HEAP[offset|56]<<24 | HEAP[offset|57]<<16 | HEAP[offset|58]<<8 | HEAP[offset|59];
        W15 = HEAP[offset|60]<<24 | HEAP[offset|61]<<16 | HEAP[offset|62]<<8 | HEAP[offset|63];
    }

    function reset () {
        ST0 = H00;
        ST1 = H01;
        ST2 = H02;
        ST3 = H03;
        ST4 = H04;
        ST5 = H05;
        ST6 = H06;
        ST7 = H07;
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

        ST0 = h0;
        ST1 = h1;
        ST2 = h2;
        ST3 = h3;
        ST4 = h4;
        ST5 = h5;
        ST6 = h6;
        ST7 = h7;
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
            _heap_to_words(offset);
            _core();

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

            _heap_to_words(offset);
            _core();

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
        _heap_to_words(offset);
        _core();

        if ( ~output )
            _state_to_heap(output);

        return hashed|0;
    }

    function hmac_reset () {
        ST0 = I0;
        ST1 = I1;
        ST2 = I2;
        ST3 = I3;
        ST4 = I4;
        ST5 = I5;
        ST6 = I6;
        ST7 = I7;
        TOTAL = 64;
    }

    function _hmac_opad () {
        ST0 = O0;
        ST1 = O1;
        ST2 = O2;
        ST3 = O3;
        ST4 = O4;
        ST5 = O5;
        ST6 = O6;
        ST7 = O7;
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
        W00 = p0 ^ 0x5c5c5c5c;
        W01 = p1 ^ 0x5c5c5c5c;
        W02 = p2 ^ 0x5c5c5c5c;
        W03 = p3 ^ 0x5c5c5c5c;
        W04 = p4 ^ 0x5c5c5c5c;
        W05 = p5 ^ 0x5c5c5c5c;
        W06 = p6 ^ 0x5c5c5c5c;
        W07 = p7 ^ 0x5c5c5c5c;
        W08 = p8 ^ 0x5c5c5c5c;
        W09 = p9 ^ 0x5c5c5c5c;
        W10 = p10 ^ 0x5c5c5c5c;
        W11 = p11 ^ 0x5c5c5c5c;
        W12 = p12 ^ 0x5c5c5c5c;
        W13 = p13 ^ 0x5c5c5c5c;
        W14 = p14 ^ 0x5c5c5c5c;
        W15 = p15 ^ 0x5c5c5c5c;
        _core();
        O0 = ST0;
        O1 = ST1;
        O2 = ST2;
        O3 = ST3;
        O4 = ST4;
        O5 = ST5;
        O6 = ST6;
        O7 = ST7;

        // ipad
        reset();
        W00 = p0 ^ 0x36363636;
        W01 = p1 ^ 0x36363636;
        W02 = p2 ^ 0x36363636;
        W03 = p3 ^ 0x36363636;
        W04 = p4 ^ 0x36363636;
        W05 = p5 ^ 0x36363636;
        W06 = p6 ^ 0x36363636;
        W07 = p7 ^ 0x36363636;
        W08 = p8 ^ 0x36363636;
        W09 = p9 ^ 0x36363636;
        W10 = p10 ^ 0x36363636;
        W11 = p11 ^ 0x36363636;
        W12 = p12 ^ 0x36363636;
        W13 = p13 ^ 0x36363636;
        W14 = p14 ^ 0x36363636;
        W15 = p15 ^ 0x36363636;
        _core();
        I0 = ST0;
        I1 = ST1;
        I2 = ST2;
        I3 = ST3;
        I4 = ST4;
        I5 = ST5;
        I6 = ST6;
        I7 = ST7;

        TOTAL = 64;
    }

    // offset — multiple of 64
    // output — multiple of 32
    function hmac_finish ( offset, length, output ) {
        offset = offset|0;
        length = length|0;
        output = output|0;

        var hashed = 0;

        if ( offset & 63 )
            return -1;

        if ( ~output )
            if ( output & 31 )
                return -1;

        hashed = finish( offset, length, -1 )|0;
        W00 = ST0;
        W01 = ST1;
        W02 = ST2;
        W03 = ST3;
        W04 = ST4;
        W05 = ST5;
        W06 = ST6;
        W07 = ST7;

        _hmac_opad();
        W08 = 0x80000000;
        W09 = W10 = W11 = W12 = W13 = W14 = 0;
        W15 = 768;
        _core();

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

        var st0 = 0, st1 = 0, st2 = 0, st3 = 0, st4 = 0, st5 = 0, st6 = 0, st7 = 0;

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
        st0 = W00 = ST0;
        st1 = W01 = ST1;
        st2 = W02 = ST2;
        st3 = W03 = ST3;
        st4 = W04 = ST4;
        st5 = W05 = ST5;
        st6 = W06 = ST6;
        st7 = W07 = ST7;
        count = (count-1)|0;

        // perform the rest iterations
        while ( (count|0) > 0 ) {
            hmac_reset();
            W08 = 0x80000000;
            W09 = W10 = W11 = W12 = W13 = W14 = 0;
            W15 = 768;
            _core();
            W00 = ST0;
            W01 = ST1;
            W02 = ST2;
            W03 = ST3;
            W04 = ST4;
            W05 = ST5;
            W06 = ST6;
            W07 = ST7;

            _hmac_opad();
            W08 = 0x80000000;
            W09 = W10 = W11 = W12 = W13 = W14 = 0;
            W15 = 768;
            _core();
            W00 = ST0;
            W01 = ST1;
            W02 = ST2;
            W03 = ST3;
            W04 = ST4;
            W05 = ST5;
            W06 = ST6;
            W07 = ST7;

            st0 = st0 ^ ST0;
            st1 = st1 ^ ST1;
            st2 = st2 ^ ST2;
            st3 = st3 ^ ST3;
            st4 = st4 ^ ST4;
            st5 = st5 ^ ST5;
            st6 = st6 ^ ST6;
            st7 = st7 ^ ST7;

            count = (count-1)|0;
        }

        ST0 = st0;
        ST1 = st1;
        ST2 = st2;
        ST3 = st3;
        ST4 = st4;
        ST5 = st5;
        ST6 = st6;
        ST7 = st7;

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
    return (new Function('e,t,n','"use asm";var r=1779033703,i=3144134277,s=1013904242,o=2773480762,u=1359893119,a=2600822924,f=528734635,l=1541459225;var c=1116352408,h=1899447441,p=3049323471,d=3921009573,v=961987163,m=1508970993,g=2453635748,y=2870763221,b=3624381080,w=310598401,E=607225278,S=1426881987,x=1925078388,T=2162078206,N=2614888103,C=3248222580,k=3835390401,L=4022224774,A=264347078,O=604807628,M=770255983,_=1249150122,D=1555081692,P=1996064986,H=2554220882,B=2821834349,j=2952996808,F=3210313671,I=3336571891,q=3584528711,R=113926993,U=338241895,z=666307205,W=773529912,X=1294757372,V=1396182291,$=1695183700,J=1986661051,K=2177026350,Q=2456956037,G=2730485921,Y=2820302411,Z=3259730800,et=3345764771,tt=3516065817,nt=3600352804,rt=4094571909,it=275423344,st=430227734,ot=506948616,ut=659060556,at=883997877,ft=958139571,lt=1322822218,ct=1537002063,ht=1747873779,pt=1955562222,dt=2024104815,vt=2227730452,mt=2361852424,gt=2428436474,yt=2756734187,bt=3204031479,wt=3329325298;var Et=0,St=0,xt=0,Tt=0,Nt=0,Ct=0,kt=0,Lt=0,At=0,Ot=0,Mt=0,_t=0,Dt=0,Pt=0,Ht=0,Bt=0;var jt=0,Ft=0,It=0,qt=0,Rt=0,Ut=0,zt=0,Wt=0,Xt=0;var Vt=0,$t=0,Jt=0,Kt=0,Qt=0,Gt=0,Yt=0,Zt=0,en=0,tn=0,nn=0,rn=0,sn=0,on=0,un=0,an=0;var fn=new e.Uint8Array(n);function ln(){var e=0,t=0,n=0,r=0,i=0,s=0,o=0,u=0,a=0;e=jt;t=Ft;n=It;r=qt;i=Rt;s=Ut;o=zt;u=Wt;a=Et+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+c|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=St+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+h|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=xt+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+p|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=Tt+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+d|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=Nt+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+v|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=Ct+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+m|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=kt+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+g|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=Lt+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+y|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=At+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+b|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=Ot+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+w|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=Mt+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+E|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=_t+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+S|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=Dt+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+x|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=Pt+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+T|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=Ht+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+N|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;a=Bt+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+C|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Et=a=(St>>>7^St>>>18^St>>>3^St<<25^St<<14)+(Ht>>>17^Ht>>>19^Ht>>>10^Ht<<15^Ht<<13)+Et+Ot|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+k|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;St=a=(xt>>>7^xt>>>18^xt>>>3^xt<<25^xt<<14)+(Bt>>>17^Bt>>>19^Bt>>>10^Bt<<15^Bt<<13)+St+Mt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+L|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;xt=a=(Tt>>>7^Tt>>>18^Tt>>>3^Tt<<25^Tt<<14)+(Et>>>17^Et>>>19^Et>>>10^Et<<15^Et<<13)+xt+_t|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+A|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Tt=a=(Nt>>>7^Nt>>>18^Nt>>>3^Nt<<25^Nt<<14)+(St>>>17^St>>>19^St>>>10^St<<15^St<<13)+Tt+Dt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+O|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Nt=a=(Ct>>>7^Ct>>>18^Ct>>>3^Ct<<25^Ct<<14)+(xt>>>17^xt>>>19^xt>>>10^xt<<15^xt<<13)+Nt+Pt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+M|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Ct=a=(kt>>>7^kt>>>18^kt>>>3^kt<<25^kt<<14)+(Tt>>>17^Tt>>>19^Tt>>>10^Tt<<15^Tt<<13)+Ct+Ht|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+_|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;kt=a=(Lt>>>7^Lt>>>18^Lt>>>3^Lt<<25^Lt<<14)+(Nt>>>17^Nt>>>19^Nt>>>10^Nt<<15^Nt<<13)+kt+Bt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+D|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Lt=a=(At>>>7^At>>>18^At>>>3^At<<25^At<<14)+(Ct>>>17^Ct>>>19^Ct>>>10^Ct<<15^Ct<<13)+Lt+Et|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+P|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;At=a=(Ot>>>7^Ot>>>18^Ot>>>3^Ot<<25^Ot<<14)+(kt>>>17^kt>>>19^kt>>>10^kt<<15^kt<<13)+At+St|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+H|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Ot=a=(Mt>>>7^Mt>>>18^Mt>>>3^Mt<<25^Mt<<14)+(Lt>>>17^Lt>>>19^Lt>>>10^Lt<<15^Lt<<13)+Ot+xt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+B|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Mt=a=(_t>>>7^_t>>>18^_t>>>3^_t<<25^_t<<14)+(At>>>17^At>>>19^At>>>10^At<<15^At<<13)+Mt+Tt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+j|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;_t=a=(Dt>>>7^Dt>>>18^Dt>>>3^Dt<<25^Dt<<14)+(Ot>>>17^Ot>>>19^Ot>>>10^Ot<<15^Ot<<13)+_t+Nt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+F|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Dt=a=(Pt>>>7^Pt>>>18^Pt>>>3^Pt<<25^Pt<<14)+(Mt>>>17^Mt>>>19^Mt>>>10^Mt<<15^Mt<<13)+Dt+Ct|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+I|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Pt=a=(Ht>>>7^Ht>>>18^Ht>>>3^Ht<<25^Ht<<14)+(_t>>>17^_t>>>19^_t>>>10^_t<<15^_t<<13)+Pt+kt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+q|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Ht=a=(Bt>>>7^Bt>>>18^Bt>>>3^Bt<<25^Bt<<14)+(Dt>>>17^Dt>>>19^Dt>>>10^Dt<<15^Dt<<13)+Ht+Lt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+R|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Bt=a=(Et>>>7^Et>>>18^Et>>>3^Et<<25^Et<<14)+(Pt>>>17^Pt>>>19^Pt>>>10^Pt<<15^Pt<<13)+Bt+At|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+U|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Et=a=(St>>>7^St>>>18^St>>>3^St<<25^St<<14)+(Ht>>>17^Ht>>>19^Ht>>>10^Ht<<15^Ht<<13)+Et+Ot|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+z|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;St=a=(xt>>>7^xt>>>18^xt>>>3^xt<<25^xt<<14)+(Bt>>>17^Bt>>>19^Bt>>>10^Bt<<15^Bt<<13)+St+Mt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+W|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;xt=a=(Tt>>>7^Tt>>>18^Tt>>>3^Tt<<25^Tt<<14)+(Et>>>17^Et>>>19^Et>>>10^Et<<15^Et<<13)+xt+_t|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+X|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Tt=a=(Nt>>>7^Nt>>>18^Nt>>>3^Nt<<25^Nt<<14)+(St>>>17^St>>>19^St>>>10^St<<15^St<<13)+Tt+Dt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+V|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Nt=a=(Ct>>>7^Ct>>>18^Ct>>>3^Ct<<25^Ct<<14)+(xt>>>17^xt>>>19^xt>>>10^xt<<15^xt<<13)+Nt+Pt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+$|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Ct=a=(kt>>>7^kt>>>18^kt>>>3^kt<<25^kt<<14)+(Tt>>>17^Tt>>>19^Tt>>>10^Tt<<15^Tt<<13)+Ct+Ht|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+J|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;kt=a=(Lt>>>7^Lt>>>18^Lt>>>3^Lt<<25^Lt<<14)+(Nt>>>17^Nt>>>19^Nt>>>10^Nt<<15^Nt<<13)+kt+Bt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+K|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Lt=a=(At>>>7^At>>>18^At>>>3^At<<25^At<<14)+(Ct>>>17^Ct>>>19^Ct>>>10^Ct<<15^Ct<<13)+Lt+Et|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+Q|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;At=a=(Ot>>>7^Ot>>>18^Ot>>>3^Ot<<25^Ot<<14)+(kt>>>17^kt>>>19^kt>>>10^kt<<15^kt<<13)+At+St|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+G|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Ot=a=(Mt>>>7^Mt>>>18^Mt>>>3^Mt<<25^Mt<<14)+(Lt>>>17^Lt>>>19^Lt>>>10^Lt<<15^Lt<<13)+Ot+xt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+Y|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Mt=a=(_t>>>7^_t>>>18^_t>>>3^_t<<25^_t<<14)+(At>>>17^At>>>19^At>>>10^At<<15^At<<13)+Mt+Tt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+Z|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;_t=a=(Dt>>>7^Dt>>>18^Dt>>>3^Dt<<25^Dt<<14)+(Ot>>>17^Ot>>>19^Ot>>>10^Ot<<15^Ot<<13)+_t+Nt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+et|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Dt=a=(Pt>>>7^Pt>>>18^Pt>>>3^Pt<<25^Pt<<14)+(Mt>>>17^Mt>>>19^Mt>>>10^Mt<<15^Mt<<13)+Dt+Ct|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+tt|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Pt=a=(Ht>>>7^Ht>>>18^Ht>>>3^Ht<<25^Ht<<14)+(_t>>>17^_t>>>19^_t>>>10^_t<<15^_t<<13)+Pt+kt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+nt|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Ht=a=(Bt>>>7^Bt>>>18^Bt>>>3^Bt<<25^Bt<<14)+(Dt>>>17^Dt>>>19^Dt>>>10^Dt<<15^Dt<<13)+Ht+Lt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+rt|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Bt=a=(Et>>>7^Et>>>18^Et>>>3^Et<<25^Et<<14)+(Pt>>>17^Pt>>>19^Pt>>>10^Pt<<15^Pt<<13)+Bt+At|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+it|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Et=a=(St>>>7^St>>>18^St>>>3^St<<25^St<<14)+(Ht>>>17^Ht>>>19^Ht>>>10^Ht<<15^Ht<<13)+Et+Ot|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+st|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;St=a=(xt>>>7^xt>>>18^xt>>>3^xt<<25^xt<<14)+(Bt>>>17^Bt>>>19^Bt>>>10^Bt<<15^Bt<<13)+St+Mt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+ot|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;xt=a=(Tt>>>7^Tt>>>18^Tt>>>3^Tt<<25^Tt<<14)+(Et>>>17^Et>>>19^Et>>>10^Et<<15^Et<<13)+xt+_t|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+ut|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Tt=a=(Nt>>>7^Nt>>>18^Nt>>>3^Nt<<25^Nt<<14)+(St>>>17^St>>>19^St>>>10^St<<15^St<<13)+Tt+Dt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+at|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Nt=a=(Ct>>>7^Ct>>>18^Ct>>>3^Ct<<25^Ct<<14)+(xt>>>17^xt>>>19^xt>>>10^xt<<15^xt<<13)+Nt+Pt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+ft|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Ct=a=(kt>>>7^kt>>>18^kt>>>3^kt<<25^kt<<14)+(Tt>>>17^Tt>>>19^Tt>>>10^Tt<<15^Tt<<13)+Ct+Ht|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+lt|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;kt=a=(Lt>>>7^Lt>>>18^Lt>>>3^Lt<<25^Lt<<14)+(Nt>>>17^Nt>>>19^Nt>>>10^Nt<<15^Nt<<13)+kt+Bt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+ct|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Lt=a=(At>>>7^At>>>18^At>>>3^At<<25^At<<14)+(Ct>>>17^Ct>>>19^Ct>>>10^Ct<<15^Ct<<13)+Lt+Et|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+ht|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;At=a=(Ot>>>7^Ot>>>18^Ot>>>3^Ot<<25^Ot<<14)+(kt>>>17^kt>>>19^kt>>>10^kt<<15^kt<<13)+At+St|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+pt|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Ot=a=(Mt>>>7^Mt>>>18^Mt>>>3^Mt<<25^Mt<<14)+(Lt>>>17^Lt>>>19^Lt>>>10^Lt<<15^Lt<<13)+Ot+xt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+dt|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Mt=a=(_t>>>7^_t>>>18^_t>>>3^_t<<25^_t<<14)+(At>>>17^At>>>19^At>>>10^At<<15^At<<13)+Mt+Tt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+vt|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;_t=a=(Dt>>>7^Dt>>>18^Dt>>>3^Dt<<25^Dt<<14)+(Ot>>>17^Ot>>>19^Ot>>>10^Ot<<15^Ot<<13)+_t+Nt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+mt|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Dt=a=(Pt>>>7^Pt>>>18^Pt>>>3^Pt<<25^Pt<<14)+(Mt>>>17^Mt>>>19^Mt>>>10^Mt<<15^Mt<<13)+Dt+Ct|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+gt|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Pt=a=(Ht>>>7^Ht>>>18^Ht>>>3^Ht<<25^Ht<<14)+(_t>>>17^_t>>>19^_t>>>10^_t<<15^_t<<13)+Pt+kt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+yt|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Ht=a=(Bt>>>7^Bt>>>18^Bt>>>3^Bt<<25^Bt<<14)+(Dt>>>17^Dt>>>19^Dt>>>10^Dt<<15^Dt<<13)+Ht+Lt|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+bt|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;Bt=a=(Et>>>7^Et>>>18^Et>>>3^Et<<25^Et<<14)+(Pt>>>17^Pt>>>19^Pt>>>10^Pt<<15^Pt<<13)+Bt+At|0;a=a+u+(i>>>6^i>>>11^i>>>25^i<<26^i<<21^i<<7)+(o^i&(s^o))+wt|0;u=o;o=s;s=i;i=r+a|0;r=n;n=t;t=e;e=a+(t&n^r&(t^n))+(t>>>2^t>>>13^t>>>22^t<<30^t<<19^t<<10)|0;jt=jt+e|0;Ft=Ft+t|0;It=It+n|0;qt=qt+r|0;Rt=Rt+i|0;Ut=Ut+s|0;zt=zt+o|0;Wt=Wt+u|0}function cn(e){e=e|0;fn[e|0]=jt>>>24;fn[e|1]=jt>>>16&255;fn[e|2]=jt>>>8&255;fn[e|3]=jt&255;fn[e|4]=Ft>>>24;fn[e|5]=Ft>>>16&255;fn[e|6]=Ft>>>8&255;fn[e|7]=Ft&255;fn[e|8]=It>>>24;fn[e|9]=It>>>16&255;fn[e|10]=It>>>8&255;fn[e|11]=It&255;fn[e|12]=qt>>>24;fn[e|13]=qt>>>16&255;fn[e|14]=qt>>>8&255;fn[e|15]=qt&255;fn[e|16]=Rt>>>24;fn[e|17]=Rt>>>16&255;fn[e|18]=Rt>>>8&255;fn[e|19]=Rt&255;fn[e|20]=Ut>>>24;fn[e|21]=Ut>>>16&255;fn[e|22]=Ut>>>8&255;fn[e|23]=Ut&255;fn[e|24]=zt>>>24;fn[e|25]=zt>>>16&255;fn[e|26]=zt>>>8&255;fn[e|27]=zt&255;fn[e|28]=Wt>>>24;fn[e|29]=Wt>>>16&255;fn[e|30]=Wt>>>8&255;fn[e|31]=Wt&255}function hn(e){e=e|0;Et=fn[e|0]<<24|fn[e|1]<<16|fn[e|2]<<8|fn[e|3];St=fn[e|4]<<24|fn[e|5]<<16|fn[e|6]<<8|fn[e|7];xt=fn[e|8]<<24|fn[e|9]<<16|fn[e|10]<<8|fn[e|11];Tt=fn[e|12]<<24|fn[e|13]<<16|fn[e|14]<<8|fn[e|15];Nt=fn[e|16]<<24|fn[e|17]<<16|fn[e|18]<<8|fn[e|19];Ct=fn[e|20]<<24|fn[e|21]<<16|fn[e|22]<<8|fn[e|23];kt=fn[e|24]<<24|fn[e|25]<<16|fn[e|26]<<8|fn[e|27];Lt=fn[e|28]<<24|fn[e|29]<<16|fn[e|30]<<8|fn[e|31];At=fn[e|32]<<24|fn[e|33]<<16|fn[e|34]<<8|fn[e|35];Ot=fn[e|36]<<24|fn[e|37]<<16|fn[e|38]<<8|fn[e|39];Mt=fn[e|40]<<24|fn[e|41]<<16|fn[e|42]<<8|fn[e|43];_t=fn[e|44]<<24|fn[e|45]<<16|fn[e|46]<<8|fn[e|47];Dt=fn[e|48]<<24|fn[e|49]<<16|fn[e|50]<<8|fn[e|51];Pt=fn[e|52]<<24|fn[e|53]<<16|fn[e|54]<<8|fn[e|55];Ht=fn[e|56]<<24|fn[e|57]<<16|fn[e|58]<<8|fn[e|59];Bt=fn[e|60]<<24|fn[e|61]<<16|fn[e|62]<<8|fn[e|63]}function pn(){jt=r;Ft=i;It=s;qt=o;Rt=u;Ut=a;zt=f;Wt=l;Xt=0}function dn(e,t,n,r,i,s,o,u,a){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;s=s|0;o=o|0;u=u|0;a=a|0;jt=e;Ft=t;It=n;qt=r;Rt=i;Ut=s;zt=o;Wt=u;Xt=a}function vn(e,t){e=e|0;t=t|0;var n=0;if(e&63)return-1;while((t|0)>=64){hn(e);ln();e=e+64|0;t=t-64|0;n=n+64|0}Xt=Xt+n|0;return n|0}function mn(e,t,n){e=e|0;t=t|0;n=n|0;var r=0,i=0;if(e&63)return-1;if(~n)if(n&31)return-1;if((t|0)>=64){r=vn(e,t)|0;if((r|0)==-1)return-1;e=e+r|0;t=t-r|0}r=r+t|0;Xt=Xt+t|0;fn[e|t]=128;if((t|0)>=56){for(i=t+1|0;(i|0)<64;i=i+1|0)fn[e|i]=0;hn(e);ln();t=0;fn[e|0]=0}for(i=t+1|0;(i|0)<59;i=i+1|0)fn[e|i]=0;fn[e|59]=Xt>>>29;fn[e|60]=Xt>>>21&255;fn[e|61]=Xt>>>13&255;fn[e|62]=Xt>>>5&255;fn[e|63]=Xt<<3&255;hn(e);ln();if(~n)cn(n);return r|0}function gn(){jt=Vt;Ft=$t;It=Jt;qt=Kt;Rt=Qt;Ut=Gt;zt=Yt;Wt=Zt;Xt=64}function yn(){jt=en;Ft=tn;It=nn;qt=rn;Rt=sn;Ut=on;zt=un;Wt=an;Xt=64}function bn(e,t,n,r,i,s,o,u,a,f,l,c,h,p,d,v){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;s=s|0;o=o|0;u=u|0;a=a|0;f=f|0;l=l|0;c=c|0;h=h|0;p=p|0;d=d|0;v=v|0;pn();Et=e^1549556828;St=t^1549556828;xt=n^1549556828;Tt=r^1549556828;Nt=i^1549556828;Ct=s^1549556828;kt=o^1549556828;Lt=u^1549556828;At=a^1549556828;Ot=f^1549556828;Mt=l^1549556828;_t=c^1549556828;Dt=h^1549556828;Pt=p^1549556828;Ht=d^1549556828;Bt=v^1549556828;ln();en=jt;tn=Ft;nn=It;rn=qt;sn=Rt;on=Ut;un=zt;an=Wt;pn();Et=e^909522486;St=t^909522486;xt=n^909522486;Tt=r^909522486;Nt=i^909522486;Ct=s^909522486;kt=o^909522486;Lt=u^909522486;At=a^909522486;Ot=f^909522486;Mt=l^909522486;_t=c^909522486;Dt=h^909522486;Pt=p^909522486;Ht=d^909522486;Bt=v^909522486;ln();Vt=jt;$t=Ft;Jt=It;Kt=qt;Qt=Rt;Gt=Ut;Yt=zt;Zt=Wt;Xt=64}function wn(e,t,n){e=e|0;t=t|0;n=n|0;var r=0;if(e&63)return-1;if(~n)if(n&31)return-1;r=mn(e,t,-1)|0;Et=jt;St=Ft;xt=It;Tt=qt;Nt=Rt;Ct=Ut;kt=zt;Lt=Wt;yn();At=2147483648;Ot=Mt=_t=Dt=Pt=Ht=0;Bt=768;ln();if(~n)cn(n);return r|0}function En(e,t,n,r,i){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;var s=0,o=0,u=0,a=0,f=0,l=0,c=0,h=0;if(e&63)return-1;if(~i)if(i&31)return-1;fn[e+t|0]=n>>>24;fn[e+t+1|0]=n>>>16&255;fn[e+t+2|0]=n>>>8&255;fn[e+t+3|0]=n&255;wn(e,t+4|0,-1)|0;s=Et=jt;o=St=Ft;u=xt=It;a=Tt=qt;f=Nt=Rt;l=Ct=Ut;c=kt=zt;h=Lt=Wt;r=r-1|0;while((r|0)>0){gn();At=2147483648;Ot=Mt=_t=Dt=Pt=Ht=0;Bt=768;ln();Et=jt;St=Ft;xt=It;Tt=qt;Nt=Rt;Ct=Ut;kt=zt;Lt=Wt;yn();At=2147483648;Ot=Mt=_t=Dt=Pt=Ht=0;Bt=768;ln();Et=jt;St=Ft;xt=It;Tt=qt;Nt=Rt;Ct=Ut;kt=zt;Lt=Wt;s=s^jt;o=o^Ft;u=u^It;a=a^qt;f=f^Rt;l=l^Ut;c=c^zt;h=h^Wt;r=r-1|0}jt=s;Ft=o;It=u;qt=a;Rt=f;Ut=l;zt=c;Wt=h;if(~i)cn(i)}return{reset:pn,init:dn,process:vn,finish:mn,hmac_reset:gn,hmac_init:bn,hmac_finish:wn,pbkdf2_generate_block:En}'))( stdlib, foreign, buffer );
}
