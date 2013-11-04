/*
function sha256_asm ( stdlib, foreign, buffer ) {
    "use asm";

    // SHA256 state
    var H00 = 0x6A09E667, H01 = 0xBB67AE85, H02 = 0x3C6EF372, H03 = 0xA54FF53A, H04 = 0x510E527F, H05 = 0x9B05688C, H06 = 0x1F83D9AB, H07 = 0x5BE0CD19;

    var K00 = 0x428A2F98, K01 = 0x71374491, K02 = 0xB5C0FBCF, K03 = 0xE9B5DBA5, K04 = 0x3956C25B, K05 = 0x59F111F1, K06 = 0x923F82A4, K07 = 0xAB1C5ED5,
        K08 = 0xD807AA98, K09 = 0x12835B01, K10 = 0x243185BE, K11 = 0x550C7DC3, K12 = 0x72BE5D74, K13 = 0x80DEB1FE, K14 = 0x9BDC06A7, K15 = 0xC19BF174,
        K16 = 0xE49B69C1, K17 = 0xEFBE4786, K18 = 0x0FC19DC6, K19 = 0x240CA1CC, K20 = 0x2DE92C6F, K21 = 0x4A7484AA, K22 = 0x5CB0A9DC, K23 = 0x76F988DA,
        K24 = 0x983E5152, K25 = 0xA831C66D, K26 = 0xB00327C8, K27 = 0xBF597FC7, K28 = 0xC6E00BF3, K29 = 0xD5A79147, K30 = 0x06CA6351, K31 = 0x14292967,
        K32 = 0x27B70A85, K33 = 0x2E1B2138, K34 = 0x4D2C6DFC, K35 = 0x53380D13, K36 = 0x650A7354, K37 = 0x766A0ABB, K38 = 0x81C2C92E, K39 = 0x92722C85,
        K40 = 0xA2BFE8A1, K41 = 0xA81A664B, K42 = 0xC24B8B70, K43 = 0xC76C51A3, K44 = 0xD192E819, K45 = 0xD6990624, K46 = 0xF40E3585, K47 = 0x106AA070,
        K48 = 0x19A4C116, K49 = 0x1E376C08, K50 = 0x2748774C, K51 = 0x34B0BCB5, K52 = 0x391C0CB3, K53 = 0x4ED8AA4A, K54 = 0x5B9CCA4F, K55 = 0x682E6FF3,
        K56 = 0x748F82EE, K57 = 0x78A5636F, K58 = 0x84C87814, K59 = 0x8CC70208, K60 = 0x90BEFFFA, K61 = 0xA4506CEB, K62 = 0xBEF9A3F7, K63 = 0xC67178F2;

    var ST0 = 0, ST1 = 0, ST2 = 0, ST3 = 0, ST4 = 0, ST5 = 0, ST6 = 0, ST7 = 0;

    var TOTAL = 0;

    // HMAC state
    var P0 = 0, P1 = 0, P2 = 0, P3 = 0, P4 = 0, P5 = 0, P6 = 0, P7 = 0, P8 = 0, P9 = 0, P10 = 0, P11 = 0, P12 = 0, P13 = 0, P14 = 0, P15 = 0;

    // PBKDF2 state
    var D0 = 0, D1 = 0, D2 = 0, D3 = 0, D4 = 0, D5 = 0, D6 = 0, D7 = 0;

    // I/O buffer
    var HEAP = new stdlib.Uint8Array(buffer);

    function _core ( offset ) {
        offset = offset|0;

        var W00 = 0, W01 = 0, W02 = 0, W03 = 0, W04 = 0, W05 = 0, W06 = 0, W07 = 0,
            W08 = 0, W09 = 0, W10 = 0, W11 = 0, W12 = 0, W13 = 0, W14 = 0, W15 = 0,
            A = 0, B = 0, C = 0, D = 0, E = 0, F = 0, G = 0, H = 0,
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
        W00 = T = ( HEAP[offset]<<24 | HEAP[(offset+1)|0]<<16 | HEAP[(offset+2)|0]<<8 | HEAP[(offset+3)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K00 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 1
        W01 = T = ( HEAP[(offset+4)|0]<<24 | HEAP[(offset+5)|0]<<16 | HEAP[(offset+6)|0]<<8 | HEAP[(offset+7)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K01 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 2
        W02 = T = ( HEAP[(offset+8)|0]<<24 | HEAP[(offset+9)|0]<<16 | HEAP[(offset+10)|0]<<8 | HEAP[(offset+11)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K02 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 3
        W03 = T = ( HEAP[(offset+12)|0]<<24 | HEAP[(offset+13)|0]<<16 | HEAP[(offset+14)|0]<<8 | HEAP[(offset+15)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K03 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 4
        W04 = T = ( HEAP[(offset+16)|0]<<24 | HEAP[(offset+17)|0]<<16 | HEAP[(offset+18)|0]<<8 | HEAP[(offset+19)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K04 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 5
        W05 = T = ( HEAP[(offset+20)|0]<<24 | HEAP[(offset+21)|0]<<16 | HEAP[(offset+22)|0]<<8 | HEAP[(offset+23)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K05 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 6
        W06 = T = ( HEAP[(offset+24)|0]<<24 | HEAP[(offset+25)|0]<<16 | HEAP[(offset+26)|0]<<8 | HEAP[(offset+27)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K06 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 7
        W07 = T = ( HEAP[(offset+28)|0]<<24 | HEAP[(offset+29)|0]<<16 | HEAP[(offset+30)|0]<<8 | HEAP[(offset+31)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K07 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 8
        W08 = T = ( HEAP[(offset+32)|0]<<24 | HEAP[(offset+33)|0]<<16 | HEAP[(offset+34)|0]<<8 | HEAP[(offset+35)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K08 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 9
        W09 = T = ( HEAP[(offset+36)|0]<<24 | HEAP[(offset+37)|0]<<16 | HEAP[(offset+38)|0]<<8 | HEAP[(offset+39)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K09 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 10
        W10 = T = ( HEAP[(offset+40)|0]<<24 | HEAP[(offset+41)|0]<<16 | HEAP[(offset+42)|0]<<8 | HEAP[(offset+43)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K10 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 11
        W11 = T = ( HEAP[(offset+44)|0]<<24 | HEAP[(offset+45)|0]<<16 | HEAP[(offset+46)|0]<<8 | HEAP[(offset+47)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K11 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 12
        W12 = T = ( HEAP[(offset+48)|0]<<24 | HEAP[(offset+49)|0]<<16 | HEAP[(offset+50)|0]<<8 | HEAP[(offset+51)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K12 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 13
        W13 = T = ( HEAP[(offset+52)|0]<<24 | HEAP[(offset+53)|0]<<16 | HEAP[(offset+54)|0]<<8 | HEAP[(offset+55)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K13 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 14
        W14 = T = ( HEAP[(offset+56)|0]<<24 | HEAP[(offset+57)|0]<<16 | HEAP[(offset+58)|0]<<8 | HEAP[(offset+59)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K14 )|0;
        H = G; G = F; F = E; E = ( D + T )|0; D = C; C = B; B = A;
        A = ( T + ( (B & C) ^ ( D & (B ^ C) ) ) + ( B>>>2 ^ B>>>13 ^ B>>>22 ^ B<<30 ^ B<<19 ^ B<<10 ) )|0;

        // 15
        W15 = T = ( HEAP[(offset+60)|0]<<24 | HEAP[(offset+61)|0]<<16 | HEAP[(offset+62)|0]<<8 | HEAP[(offset+63)|0] )|0;
        T = ( T + H + ( E>>>6 ^ E>>>11 ^ E>>>25 ^ E<<26 ^ E<<21 ^ E<<7 ) +  ( G ^ E & (F^G) ) + K15 )|0;
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

    function _state_to_heap ( offset ) {
        offset = offset|0;

        HEAP[offset|0]      = (ST0>>>24)|0;
        HEAP[(offset+1)|0]  = (ST0>>>16)&0xff;
        HEAP[(offset+2)|0]  = (ST0>>>8)&0xff;
        HEAP[(offset+3)|0]  = ST0&0xff;
        HEAP[(offset+4)|0]  = (ST1>>>24)|0;
        HEAP[(offset+5)|0]  = (ST1>>>16)&0xff;
        HEAP[(offset+6)|0]  = (ST1>>>8)&0xff;
        HEAP[(offset+7)|0]  = ST1&0xff;
        HEAP[(offset+8)|0]  = (ST2>>>24)|0;
        HEAP[(offset+9)|0]  = (ST2>>>16)&0xff;
        HEAP[(offset+10)|0] = (ST2>>>8)&0xff;
        HEAP[(offset+11)|0] = ST2&0xff;
        HEAP[(offset+12)|0] = (ST3>>>24)|0;
        HEAP[(offset+13)|0] = (ST3>>>16)&0xff;
        HEAP[(offset+14)|0] = (ST3>>>8)&0xff;
        HEAP[(offset+15)|0] = ST3&0xff;
        HEAP[(offset+16)|0] = (ST4>>>24)|0;
        HEAP[(offset+17)|0] = (ST4>>>16)&0xff;
        HEAP[(offset+18)|0] = (ST4>>>8)&0xff;
        HEAP[(offset+19)|0] = ST4&0xff;
        HEAP[(offset+20)|0] = (ST5>>>24)|0;
        HEAP[(offset+21)|0] = (ST5>>>16)&0xff;
        HEAP[(offset+22)|0] = (ST5>>>8)&0xff;
        HEAP[(offset+23)|0] = ST5&0xff;
        HEAP[(offset+24)|0] = (ST6>>>24)|0;
        HEAP[(offset+25)|0] = (ST6>>>16)&0xff;
        HEAP[(offset+26)|0] = (ST6>>>8)&0xff;
        HEAP[(offset+27)|0] = ST6&0xff;
        HEAP[(offset+28)|0] = (ST7>>>24)|0;
        HEAP[(offset+29)|0] = (ST7>>>16)&0xff;
        HEAP[(offset+30)|0] = (ST7>>>8)&0xff;
        HEAP[(offset+31)|0] = ST7&0xff;
    }

    function _pad_to_heap ( pad, offset ) {
        pad = pad|0;
        offset = offset|0;

        HEAP[offset|0]      = pad^(P0>>>24);
        HEAP[(offset+1)|0]  = pad^(P0>>>16)&0xff;
        HEAP[(offset+2)|0]  = pad^(P0>>>8)&0xff;
        HEAP[(offset+3)|0]  = pad^P0&0xff;
        HEAP[(offset+4)|0]  = pad^(P1>>>24);
        HEAP[(offset+5)|0]  = pad^(P1>>>16)&0xff;
        HEAP[(offset+6)|0]  = pad^(P1>>>8)&0xff;
        HEAP[(offset+7)|0]  = pad^P1&0xff;
        HEAP[(offset+8)|0]  = pad^(P2>>>24);
        HEAP[(offset+9)|0]  = pad^(P2>>>16)&0xff;
        HEAP[(offset+10)|0] = pad^(P2>>>8)&0xff;
        HEAP[(offset+11)|0] = pad^P2&0xff;
        HEAP[(offset+12)|0] = pad^(P3>>>24);
        HEAP[(offset+13)|0] = pad^(P3>>>16)&0xff;
        HEAP[(offset+14)|0] = pad^(P3>>>8)&0xff;
        HEAP[(offset+15)|0] = pad^P3&0xff;
        HEAP[(offset+16)|0] = pad^(P4>>>24);
        HEAP[(offset+17)|0] = pad^(P4>>>16)&0xff;
        HEAP[(offset+18)|0] = pad^(P4>>>8)&0xff;
        HEAP[(offset+19)|0] = pad^P4&0xff;
        HEAP[(offset+20)|0] = pad^(P5>>>24);
        HEAP[(offset+21)|0] = pad^(P5>>>16)&0xff;
        HEAP[(offset+22)|0] = pad^(P5>>>8)&0xff;
        HEAP[(offset+23)|0] = pad^P5&0xff;
        HEAP[(offset+24)|0] = pad^(P6>>>24);
        HEAP[(offset+25)|0] = pad^(P6>>>16)&0xff;
        HEAP[(offset+26)|0] = pad^(P6>>>8)&0xff;
        HEAP[(offset+27)|0] = pad^P6&0xff;
        HEAP[(offset+28)|0] = pad^(P7>>>24);
        HEAP[(offset+29)|0] = pad^(P7>>>16)&0xff;
        HEAP[(offset+30)|0] = pad^(P7>>>8)&0xff;
        HEAP[(offset+31)|0] = pad^P7&0xff;
        HEAP[(offset+32)|0] = pad^(P8>>>24);
        HEAP[(offset+33)|0] = pad^(P8>>>16)&0xff;
        HEAP[(offset+34)|0] = pad^(P8>>>8)&0xff;
        HEAP[(offset+35)|0] = pad^P8&0xff;
        HEAP[(offset+36)|0] = pad^(P9>>>24);
        HEAP[(offset+37)|0] = pad^(P9>>>16)&0xff;
        HEAP[(offset+38)|0] = pad^(P9>>>8)&0xff;
        HEAP[(offset+39)|0] = pad^P9&0xff;
        HEAP[(offset+40)|0] = pad^(P10>>>24);
        HEAP[(offset+41)|0] = pad^(P10>>>16)&0xff;
        HEAP[(offset+42)|0] = pad^(P10>>>8)&0xff;
        HEAP[(offset+43)|0] = pad^P10&0xff;
        HEAP[(offset+44)|0] = pad^(P11>>>24);
        HEAP[(offset+45)|0] = pad^(P11>>>16)&0xff;
        HEAP[(offset+46)|0] = pad^(P11>>>8)&0xff;
        HEAP[(offset+47)|0] = pad^P11&0xff;
        HEAP[(offset+48)|0] = pad^(P12>>>24);
        HEAP[(offset+49)|0] = pad^(P12>>>16)&0xff;
        HEAP[(offset+50)|0] = pad^(P12>>>8)&0xff;
        HEAP[(offset+51)|0] = pad^P12&0xff;
        HEAP[(offset+52)|0] = pad^(P13>>>24);
        HEAP[(offset+53)|0] = pad^(P13>>>16)&0xff;
        HEAP[(offset+54)|0] = pad^(P13>>>8)&0xff;
        HEAP[(offset+55)|0] = pad^P13&0xff;
        HEAP[(offset+56)|0] = pad^(P14>>>24);
        HEAP[(offset+57)|0] = pad^(P14>>>16)&0xff;
        HEAP[(offset+58)|0] = pad^(P14>>>8)&0xff;
        HEAP[(offset+59)|0] = pad^P14&0xff;
        HEAP[(offset+60)|0] = pad^(P15>>>24);
        HEAP[(offset+61)|0] = pad^(P15>>>16)&0xff;
        HEAP[(offset+62)|0] = pad^(P15>>>8)&0xff;
        HEAP[(offset+63)|0] = pad^P15&0xff;
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

    function process ( offset, length ) {
        offset = offset|0;
        length = length|0;

        var hashed = 0;

        if ( (( (offset|0) % 64 )|0) != 0 )
            return -1;

        while ( (length|0) >= 64 ) {
            _core(offset);
            offset = (offset+64)|0;
            length = (length-64)|0;
            hashed = (hashed+64)|0;
        }

        TOTAL = ( TOTAL + hashed )|0;

        return hashed|0;
    }

    function finish ( offset, length, out ) {
        offset = offset|0;
        length = length|0;
        out  = out|0;

        var hashed = 0,
            i = 0;

        if ( (length|0) >= 64 ) {
            hashed = process( offset, length )|0;
            if ( (hashed|0) == -1 )
                return -1;

            offset = ( offset + hashed )|0;
            length = ( length - hashed )|0;
        }

        hashed = (hashed + length)|0
        TOTAL = (TOTAL + length)|0;

        HEAP[(offset+length)|0] = 0x80;

        if ( (length|0) >= 56 ) {
            for ( i = (length+1)|0; (i|0) < 64; i = (i+1)|0 )
                HEAP[(offset+i)|0] = 0x00;
            _core(offset);
            length = 0;

            HEAP[offset|0] = 0x00;
        }

        for ( i = (length+1)|0; (i|0) < 59; i = (i+1)|0 )
            HEAP[(offset+i)|0] = 0x00;

        HEAP[(offset+59)|0] = (TOTAL>>>29) & 0xff;
        HEAP[(offset+60)|0] = (TOTAL>>>21) & 0xff
        HEAP[(offset+61)|0] = (TOTAL>>>13) & 0xff
        HEAP[(offset+62)|0] = (TOTAL>>>5) & 0xff
        HEAP[(offset+63)|0] = (TOTAL<<3) & 0xff;
        _core(offset);

        if ( (out|0) == -1 ) return hashed|0;

        _state_to_heap(out);

        return hashed|0;
    }

    function hmac_reset () {
        reset();
        _pad_to_heap( 0x36, 0 ); // ipad
        _core(0);
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

        // key
        P0 = p0;
        P1 = p1;
        P2 = p2;
        P3 = p3;
        P4 = p4;
        P5 = p5;
        P6 = p6;
        P7 = p7;
        P8 = p8;
        P9 = p9;
        P10 = p10;
        P11 = p11;
        P12 = p12;
        P13 = p13;
        P14 = p14;
        P15 = p15;

        hmac_reset();
    }

    function hmac_finish ( offset, length, out ) {
        offset = offset|0;
        length = length|0;
        out  = out|0;

        var hashed = 0;

        hashed = finish( offset, length, 64 )|0;

        reset();
        _pad_to_heap( 0x5c, 0 ); // opad
        finish( 0, 96, out )|0;

        return hashed|0;
    }

    // salt is assumed to be already processed
    function pbkdf2_block ( offset, length, block, count, out ) {
        offset = offset|0;
        length = length|0;
        block = block|0;
        count = count|0
        out  = out|0;

        var i = 0;

        // pad block number into heap
        HEAP[(offset+length)|0]   = block>>>24&0xff;
        HEAP[(offset+length+1)|0] = block>>>16&0xff;
        HEAP[(offset+length+2)|0] = block>>>8&0xff;
        HEAP[(offset+length+3)|0] = block&0xff;

        // finish first iteration
        hmac_finish( offset, (length+4)|0, 128 )|0;
        D0 = ST0;
        D1 = ST1;
        D2 = ST2;
        D3 = ST3;
        D4 = ST4;
        D5 = ST5;
        D6 = ST6;
        D7 = ST7;
        count = (count-1)|0;

        // prepare hmac paddings
        _pad_to_heap( 0x5c, 0 );
        _pad_to_heap( 0x36, 64 );

        // prepare last hash block
        for ( i = 160; (i|0) < 192; i = (i+1)|0 ) HEAP[i|0] = 0;
        HEAP[160] = 0x80;   // terminating bit
        HEAP[190] = 3;      // size of hmac-ed data is 96 bytes

        // perform the rest iterations
        while ( (count|0) > 0 ) {
            reset();
            _core(64);
            _core(128);
            _state_to_heap(128);

            reset();
            _core(0);
            _core(128);
            _state_to_heap(128);

            D0 = D0^ST0;
            D1 = D1^ST1;
            D2 = D2^ST2;
            D3 = D3^ST3;
            D4 = D4^ST4;
            D5 = D5^ST5;
            D6 = D6^ST6;
            D7 = D7^ST7;

            count = (count-1)|0;
        }

        ST0 = D0;
        ST1 = D1;
        ST2 = D2;
        ST3 = D3;
        ST4 = D4;
        ST5 = D5;
        ST6 = D6;
        ST7 = D7;
        _state_to_heap(out);
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
        pbkdf2_block: pbkdf2_block
    }
}
*/
// Workaround Firefox bug, uglified from sha256_asm above with little manual changes
function sha256_asm ( stdlib, foreign, buffer ) {
    return (new Function('e,t,n','"use asm";var r=1779033703,i=3144134277,s=1013904242,o=2773480762,u=1359893119,a=2600822924,f=528734635,l=1541459225;var c=1116352408,h=1899447441,p=3049323471,d=3921009573,v=961987163,m=1508970993,g=2453635748,y=2870763221,b=3624381080,w=310598401,E=607225278,S=1426881987,x=1925078388,T=2162078206,N=2614888103,C=3248222580,k=3835390401,L=4022224774,A=264347078,O=604807628,M=770255983,_=1249150122,D=1555081692,P=1996064986,H=2554220882,B=2821834349,j=2952996808,F=3210313671,I=3336571891,q=3584528711,R=113926993,U=338241895,z=666307205,W=773529912,X=1294757372,V=1396182291,$=1695183700,J=1986661051,K=2177026350,Q=2456956037,G=2730485921,Y=2820302411,Z=3259730800,et=3345764771,tt=3516065817,nt=3600352804,rt=4094571909,it=275423344,st=430227734,ot=506948616,ut=659060556,at=883997877,ft=958139571,lt=1322822218,ct=1537002063,ht=1747873779,pt=1955562222,dt=2024104815,vt=2227730452,mt=2361852424,gt=2428436474,yt=2756734187,bt=3204031479,wt=3329325298;var Et=0,St=0,xt=0,Tt=0,Nt=0,Ct=0,kt=0,Lt=0;var At=0;var Ot=0,Mt=0,_t=0,Dt=0,Pt=0,Ht=0,Bt=0,jt=0,Ft=0,It=0,qt=0,Rt=0,Ut=0,zt=0,Wt=0,Xt=0;var Vt=0,$t=0,Jt=0,Kt=0,Qt=0,Gt=0,Yt=0,Zt=0;var en=new e.Uint8Array(n);function tn(e){e=e|0;var t=0,n=0,r=0,i=0,s=0,o=0,u=0,a=0,f=0,l=0,At=0,Ot=0,Mt=0,_t=0,Dt=0,Pt=0,Ht=0,Bt=0,jt=0,Ft=0,It=0,qt=0,Rt=0,Ut=0,zt=0;Ht=Et;Bt=St;jt=xt;Ft=Tt;It=Nt;qt=Ct;Rt=kt;Ut=Lt;t=zt=en[e]<<24|en[e+1|0]<<16|en[e+2|0]<<8|en[e+3|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+c|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;n=zt=en[e+4|0]<<24|en[e+5|0]<<16|en[e+6|0]<<8|en[e+7|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+h|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;r=zt=en[e+8|0]<<24|en[e+9|0]<<16|en[e+10|0]<<8|en[e+11|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+p|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;i=zt=en[e+12|0]<<24|en[e+13|0]<<16|en[e+14|0]<<8|en[e+15|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+d|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;s=zt=en[e+16|0]<<24|en[e+17|0]<<16|en[e+18|0]<<8|en[e+19|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+v|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;o=zt=en[e+20|0]<<24|en[e+21|0]<<16|en[e+22|0]<<8|en[e+23|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+m|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;u=zt=en[e+24|0]<<24|en[e+25|0]<<16|en[e+26|0]<<8|en[e+27|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+g|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;a=zt=en[e+28|0]<<24|en[e+29|0]<<16|en[e+30|0]<<8|en[e+31|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+y|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;f=zt=en[e+32|0]<<24|en[e+33|0]<<16|en[e+34|0]<<8|en[e+35|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+b|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;l=zt=en[e+36|0]<<24|en[e+37|0]<<16|en[e+38|0]<<8|en[e+39|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+w|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;At=zt=en[e+40|0]<<24|en[e+41|0]<<16|en[e+42|0]<<8|en[e+43|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+E|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Ot=zt=en[e+44|0]<<24|en[e+45|0]<<16|en[e+46|0]<<8|en[e+47|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+S|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Mt=zt=en[e+48|0]<<24|en[e+49|0]<<16|en[e+50|0]<<8|en[e+51|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+x|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;_t=zt=en[e+52|0]<<24|en[e+53|0]<<16|en[e+54|0]<<8|en[e+55|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+T|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Dt=zt=en[e+56|0]<<24|en[e+57|0]<<16|en[e+58|0]<<8|en[e+59|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+N|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Pt=zt=en[e+60|0]<<24|en[e+61|0]<<16|en[e+62|0]<<8|en[e+63|0]|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+C|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;t=zt=(n>>>7^n>>>18^n>>>3^n<<25^n<<14)+(Dt>>>17^Dt>>>19^Dt>>>10^Dt<<15^Dt<<13)+t+l|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+k|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;n=zt=(r>>>7^r>>>18^r>>>3^r<<25^r<<14)+(Pt>>>17^Pt>>>19^Pt>>>10^Pt<<15^Pt<<13)+n+At|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+L|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;r=zt=(i>>>7^i>>>18^i>>>3^i<<25^i<<14)+(t>>>17^t>>>19^t>>>10^t<<15^t<<13)+r+Ot|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+A|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;i=zt=(s>>>7^s>>>18^s>>>3^s<<25^s<<14)+(n>>>17^n>>>19^n>>>10^n<<15^n<<13)+i+Mt|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+O|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;s=zt=(o>>>7^o>>>18^o>>>3^o<<25^o<<14)+(r>>>17^r>>>19^r>>>10^r<<15^r<<13)+s+_t|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+M|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;o=zt=(u>>>7^u>>>18^u>>>3^u<<25^u<<14)+(i>>>17^i>>>19^i>>>10^i<<15^i<<13)+o+Dt|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+_|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;u=zt=(a>>>7^a>>>18^a>>>3^a<<25^a<<14)+(s>>>17^s>>>19^s>>>10^s<<15^s<<13)+u+Pt|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+D|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;a=zt=(f>>>7^f>>>18^f>>>3^f<<25^f<<14)+(o>>>17^o>>>19^o>>>10^o<<15^o<<13)+a+t|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+P|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;f=zt=(l>>>7^l>>>18^l>>>3^l<<25^l<<14)+(u>>>17^u>>>19^u>>>10^u<<15^u<<13)+f+n|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+H|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;l=zt=(At>>>7^At>>>18^At>>>3^At<<25^At<<14)+(a>>>17^a>>>19^a>>>10^a<<15^a<<13)+l+r|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+B|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;At=zt=(Ot>>>7^Ot>>>18^Ot>>>3^Ot<<25^Ot<<14)+(f>>>17^f>>>19^f>>>10^f<<15^f<<13)+At+i|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+j|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Ot=zt=(Mt>>>7^Mt>>>18^Mt>>>3^Mt<<25^Mt<<14)+(l>>>17^l>>>19^l>>>10^l<<15^l<<13)+Ot+s|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+F|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Mt=zt=(_t>>>7^_t>>>18^_t>>>3^_t<<25^_t<<14)+(At>>>17^At>>>19^At>>>10^At<<15^At<<13)+Mt+o|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+I|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;_t=zt=(Dt>>>7^Dt>>>18^Dt>>>3^Dt<<25^Dt<<14)+(Ot>>>17^Ot>>>19^Ot>>>10^Ot<<15^Ot<<13)+_t+u|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+q|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Dt=zt=(Pt>>>7^Pt>>>18^Pt>>>3^Pt<<25^Pt<<14)+(Mt>>>17^Mt>>>19^Mt>>>10^Mt<<15^Mt<<13)+Dt+a|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+R|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Pt=zt=(t>>>7^t>>>18^t>>>3^t<<25^t<<14)+(_t>>>17^_t>>>19^_t>>>10^_t<<15^_t<<13)+Pt+f|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+U|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;t=zt=(n>>>7^n>>>18^n>>>3^n<<25^n<<14)+(Dt>>>17^Dt>>>19^Dt>>>10^Dt<<15^Dt<<13)+t+l|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+z|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;n=zt=(r>>>7^r>>>18^r>>>3^r<<25^r<<14)+(Pt>>>17^Pt>>>19^Pt>>>10^Pt<<15^Pt<<13)+n+At|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+W|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;r=zt=(i>>>7^i>>>18^i>>>3^i<<25^i<<14)+(t>>>17^t>>>19^t>>>10^t<<15^t<<13)+r+Ot|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+X|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;i=zt=(s>>>7^s>>>18^s>>>3^s<<25^s<<14)+(n>>>17^n>>>19^n>>>10^n<<15^n<<13)+i+Mt|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+V|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;s=zt=(o>>>7^o>>>18^o>>>3^o<<25^o<<14)+(r>>>17^r>>>19^r>>>10^r<<15^r<<13)+s+_t|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+$|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;o=zt=(u>>>7^u>>>18^u>>>3^u<<25^u<<14)+(i>>>17^i>>>19^i>>>10^i<<15^i<<13)+o+Dt|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+J|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;u=zt=(a>>>7^a>>>18^a>>>3^a<<25^a<<14)+(s>>>17^s>>>19^s>>>10^s<<15^s<<13)+u+Pt|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+K|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;a=zt=(f>>>7^f>>>18^f>>>3^f<<25^f<<14)+(o>>>17^o>>>19^o>>>10^o<<15^o<<13)+a+t|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+Q|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;f=zt=(l>>>7^l>>>18^l>>>3^l<<25^l<<14)+(u>>>17^u>>>19^u>>>10^u<<15^u<<13)+f+n|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+G|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;l=zt=(At>>>7^At>>>18^At>>>3^At<<25^At<<14)+(a>>>17^a>>>19^a>>>10^a<<15^a<<13)+l+r|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+Y|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;At=zt=(Ot>>>7^Ot>>>18^Ot>>>3^Ot<<25^Ot<<14)+(f>>>17^f>>>19^f>>>10^f<<15^f<<13)+At+i|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+Z|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Ot=zt=(Mt>>>7^Mt>>>18^Mt>>>3^Mt<<25^Mt<<14)+(l>>>17^l>>>19^l>>>10^l<<15^l<<13)+Ot+s|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+et|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Mt=zt=(_t>>>7^_t>>>18^_t>>>3^_t<<25^_t<<14)+(At>>>17^At>>>19^At>>>10^At<<15^At<<13)+Mt+o|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+tt|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;_t=zt=(Dt>>>7^Dt>>>18^Dt>>>3^Dt<<25^Dt<<14)+(Ot>>>17^Ot>>>19^Ot>>>10^Ot<<15^Ot<<13)+_t+u|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+nt|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Dt=zt=(Pt>>>7^Pt>>>18^Pt>>>3^Pt<<25^Pt<<14)+(Mt>>>17^Mt>>>19^Mt>>>10^Mt<<15^Mt<<13)+Dt+a|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+rt|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Pt=zt=(t>>>7^t>>>18^t>>>3^t<<25^t<<14)+(_t>>>17^_t>>>19^_t>>>10^_t<<15^_t<<13)+Pt+f|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+it|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;t=zt=(n>>>7^n>>>18^n>>>3^n<<25^n<<14)+(Dt>>>17^Dt>>>19^Dt>>>10^Dt<<15^Dt<<13)+t+l|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+st|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;n=zt=(r>>>7^r>>>18^r>>>3^r<<25^r<<14)+(Pt>>>17^Pt>>>19^Pt>>>10^Pt<<15^Pt<<13)+n+At|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+ot|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;r=zt=(i>>>7^i>>>18^i>>>3^i<<25^i<<14)+(t>>>17^t>>>19^t>>>10^t<<15^t<<13)+r+Ot|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+ut|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;i=zt=(s>>>7^s>>>18^s>>>3^s<<25^s<<14)+(n>>>17^n>>>19^n>>>10^n<<15^n<<13)+i+Mt|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+at|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;s=zt=(o>>>7^o>>>18^o>>>3^o<<25^o<<14)+(r>>>17^r>>>19^r>>>10^r<<15^r<<13)+s+_t|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+ft|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;o=zt=(u>>>7^u>>>18^u>>>3^u<<25^u<<14)+(i>>>17^i>>>19^i>>>10^i<<15^i<<13)+o+Dt|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+lt|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;u=zt=(a>>>7^a>>>18^a>>>3^a<<25^a<<14)+(s>>>17^s>>>19^s>>>10^s<<15^s<<13)+u+Pt|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+ct|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;a=zt=(f>>>7^f>>>18^f>>>3^f<<25^f<<14)+(o>>>17^o>>>19^o>>>10^o<<15^o<<13)+a+t|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+ht|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;f=zt=(l>>>7^l>>>18^l>>>3^l<<25^l<<14)+(u>>>17^u>>>19^u>>>10^u<<15^u<<13)+f+n|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+pt|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;l=zt=(At>>>7^At>>>18^At>>>3^At<<25^At<<14)+(a>>>17^a>>>19^a>>>10^a<<15^a<<13)+l+r|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+dt|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;At=zt=(Ot>>>7^Ot>>>18^Ot>>>3^Ot<<25^Ot<<14)+(f>>>17^f>>>19^f>>>10^f<<15^f<<13)+At+i|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+vt|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Ot=zt=(Mt>>>7^Mt>>>18^Mt>>>3^Mt<<25^Mt<<14)+(l>>>17^l>>>19^l>>>10^l<<15^l<<13)+Ot+s|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+mt|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Mt=zt=(_t>>>7^_t>>>18^_t>>>3^_t<<25^_t<<14)+(At>>>17^At>>>19^At>>>10^At<<15^At<<13)+Mt+o|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+gt|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;_t=zt=(Dt>>>7^Dt>>>18^Dt>>>3^Dt<<25^Dt<<14)+(Ot>>>17^Ot>>>19^Ot>>>10^Ot<<15^Ot<<13)+_t+u|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+yt|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Dt=zt=(Pt>>>7^Pt>>>18^Pt>>>3^Pt<<25^Pt<<14)+(Mt>>>17^Mt>>>19^Mt>>>10^Mt<<15^Mt<<13)+Dt+a|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+bt|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Pt=zt=(t>>>7^t>>>18^t>>>3^t<<25^t<<14)+(_t>>>17^_t>>>19^_t>>>10^_t<<15^_t<<13)+Pt+f|0;zt=zt+Ut+(It>>>6^It>>>11^It>>>25^It<<26^It<<21^It<<7)+(Rt^It&(qt^Rt))+wt|0;Ut=Rt;Rt=qt;qt=It;It=Ft+zt|0;Ft=jt;jt=Bt;Bt=Ht;Ht=zt+(Bt&jt^Ft&(Bt^jt))+(Bt>>>2^Bt>>>13^Bt>>>22^Bt<<30^Bt<<19^Bt<<10)|0;Et=Et+Ht|0;St=St+Bt|0;xt=xt+jt|0;Tt=Tt+Ft|0;Nt=Nt+It|0;Ct=Ct+qt|0;kt=kt+Rt|0;Lt=Lt+Ut|0}function nn(e){e=e|0;en[e|0]=Et>>>24|0;en[e+1|0]=Et>>>16&255;en[e+2|0]=Et>>>8&255;en[e+3|0]=Et&255;en[e+4|0]=St>>>24|0;en[e+5|0]=St>>>16&255;en[e+6|0]=St>>>8&255;en[e+7|0]=St&255;en[e+8|0]=xt>>>24|0;en[e+9|0]=xt>>>16&255;en[e+10|0]=xt>>>8&255;en[e+11|0]=xt&255;en[e+12|0]=Tt>>>24|0;en[e+13|0]=Tt>>>16&255;en[e+14|0]=Tt>>>8&255;en[e+15|0]=Tt&255;en[e+16|0]=Nt>>>24|0;en[e+17|0]=Nt>>>16&255;en[e+18|0]=Nt>>>8&255;en[e+19|0]=Nt&255;en[e+20|0]=Ct>>>24|0;en[e+21|0]=Ct>>>16&255;en[e+22|0]=Ct>>>8&255;en[e+23|0]=Ct&255;en[e+24|0]=kt>>>24|0;en[e+25|0]=kt>>>16&255;en[e+26|0]=kt>>>8&255;en[e+27|0]=kt&255;en[e+28|0]=Lt>>>24|0;en[e+29|0]=Lt>>>16&255;en[e+30|0]=Lt>>>8&255;en[e+31|0]=Lt&255}function rn(e,t){e=e|0;t=t|0;en[t|0]=e^Ot>>>24;en[t+1|0]=e^Ot>>>16&255;en[t+2|0]=e^Ot>>>8&255;en[t+3|0]=e^Ot&255;en[t+4|0]=e^Mt>>>24;en[t+5|0]=e^Mt>>>16&255;en[t+6|0]=e^Mt>>>8&255;en[t+7|0]=e^Mt&255;en[t+8|0]=e^_t>>>24;en[t+9|0]=e^_t>>>16&255;en[t+10|0]=e^_t>>>8&255;en[t+11|0]=e^_t&255;en[t+12|0]=e^Dt>>>24;en[t+13|0]=e^Dt>>>16&255;en[t+14|0]=e^Dt>>>8&255;en[t+15|0]=e^Dt&255;en[t+16|0]=e^Pt>>>24;en[t+17|0]=e^Pt>>>16&255;en[t+18|0]=e^Pt>>>8&255;en[t+19|0]=e^Pt&255;en[t+20|0]=e^Ht>>>24;en[t+21|0]=e^Ht>>>16&255;en[t+22|0]=e^Ht>>>8&255;en[t+23|0]=e^Ht&255;en[t+24|0]=e^Bt>>>24;en[t+25|0]=e^Bt>>>16&255;en[t+26|0]=e^Bt>>>8&255;en[t+27|0]=e^Bt&255;en[t+28|0]=e^jt>>>24;en[t+29|0]=e^jt>>>16&255;en[t+30|0]=e^jt>>>8&255;en[t+31|0]=e^jt&255;en[t+32|0]=e^Ft>>>24;en[t+33|0]=e^Ft>>>16&255;en[t+34|0]=e^Ft>>>8&255;en[t+35|0]=e^Ft&255;en[t+36|0]=e^It>>>24;en[t+37|0]=e^It>>>16&255;en[t+38|0]=e^It>>>8&255;en[t+39|0]=e^It&255;en[t+40|0]=e^qt>>>24;en[t+41|0]=e^qt>>>16&255;en[t+42|0]=e^qt>>>8&255;en[t+43|0]=e^qt&255;en[t+44|0]=e^Rt>>>24;en[t+45|0]=e^Rt>>>16&255;en[t+46|0]=e^Rt>>>8&255;en[t+47|0]=e^Rt&255;en[t+48|0]=e^Ut>>>24;en[t+49|0]=e^Ut>>>16&255;en[t+50|0]=e^Ut>>>8&255;en[t+51|0]=e^Ut&255;en[t+52|0]=e^zt>>>24;en[t+53|0]=e^zt>>>16&255;en[t+54|0]=e^zt>>>8&255;en[t+55|0]=e^zt&255;en[t+56|0]=e^Wt>>>24;en[t+57|0]=e^Wt>>>16&255;en[t+58|0]=e^Wt>>>8&255;en[t+59|0]=e^Wt&255;en[t+60|0]=e^Xt>>>24;en[t+61|0]=e^Xt>>>16&255;en[t+62|0]=e^Xt>>>8&255;en[t+63|0]=e^Xt&255}function sn(){Et=r;St=i;xt=s;Tt=o;Nt=u;Ct=a;kt=f;Lt=l;At=0}function on(e,t,n,r,i,s,o,u,a){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;s=s|0;o=o|0;u=u|0;a=a|0;Et=e;St=t;xt=n;Tt=r;Nt=i;Ct=s;kt=o;Lt=u;At=a}function un(e,t){e=e|0;t=t|0;var n=0;if(((e|0)%64|0)!=0)return-1;while((t|0)>=64){tn(e);e=e+64|0;t=t-64|0;n=n+64|0}At=At+n|0;return n|0}function an(e,t,n){e=e|0;t=t|0;n=n|0;var r=0,i=0;if((t|0)>=64){r=un(e,t)|0;if((r|0)==-1)return-1;e=e+r|0;t=t-r|0}r=r+t|0;At=At+t|0;en[e+t|0]=128;if((t|0)>=56){for(i=t+1|0;(i|0)<64;i=i+1|0)en[e+i|0]=0;tn(e);t=0;en[e|0]=0}for(i=t+1|0;(i|0)<59;i=i+1|0)en[e+i|0]=0;en[e+59|0]=At>>>29&255;en[e+60|0]=At>>>21&255;en[e+61|0]=At>>>13&255;en[e+62|0]=At>>>5&255;en[e+63|0]=At<<3&255;tn(e);if((n|0)==-1)return r|0;nn(n);return r|0}function fn(){sn();rn(54,0);tn(0);At=64}function ln(e,t,n,r,i,s,o,u,a,f,l,c,h,p,d,v){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;s=s|0;o=o|0;u=u|0;a=a|0;f=f|0;l=l|0;c=c|0;h=h|0;p=p|0;d=d|0;v=v|0;Ot=e;Mt=t;_t=n;Dt=r;Pt=i;Ht=s;Bt=o;jt=u;Ft=a;It=f;qt=l;Rt=c;Ut=h;zt=p;Wt=d;Xt=v;fn()}function cn(e,t,n){e=e|0;t=t|0;n=n|0;var r=0;r=an(e,t,64)|0;sn();rn(92,0);an(0,96,n)|0;return r|0}function hn(e,t,n,r,i){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;var s=0;en[e+t|0]=n>>>24&255;en[e+t+1|0]=n>>>16&255;en[e+t+2|0]=n>>>8&255;en[e+t+3|0]=n&255;cn(e,t+4|0,128)|0;Vt=Et;$t=St;Jt=xt;Kt=Tt;Qt=Nt;Gt=Ct;Yt=kt;Zt=Lt;r=r-1|0;rn(92,0);rn(54,64);for(s=160;(s|0)<192;s=s+1|0)en[s|0]=0;en[160]=128;en[190]=3;while((r|0)>0){sn();tn(64);tn(128);nn(128);sn();tn(0);tn(128);nn(128);Vt=Vt^Et;$t=$t^St;Jt=Jt^xt;Kt=Kt^Tt;Qt=Qt^Nt;Gt=Gt^Ct;Yt=Yt^kt;Zt=Zt^Lt;r=r-1|0}Et=Vt;St=$t;xt=Jt;Tt=Kt;Nt=Qt;Ct=Gt;kt=Yt;Lt=Zt;nn(i)}return{reset:sn,init:on,process:un,finish:an,hmac_reset:fn,hmac_init:ln,hmac_finish:cn,pbkdf2_block:hn}'))( stdlib, foreign, buffer );
}
