/*
function aes_asm ( stdlib, foreign, buffer ) {
    "use asm";

    // AES precomputed tables
    var SBOX = 0, INV_SBOX = 0x100, X2_SBOX = 0x200, X3_SBOX = 0x300,
        X9 = 0x400, XB = 0x500, XD = 0x600, XE = 0x700;

    // AES state
    var S0 = 0, S1 = 0, S2 = 0, S3 = 0, S4 = 0, S5 = 0, S6 = 0, S7 = 0, S8 = 0, S9 = 0, SA = 0, SB = 0, SC = 0, SD = 0, SE = 0, SF = 0;

    // AES key schedule
    var R00 = 0, R01 = 0, R02 = 0, R03 = 0, R04 = 0, R05 = 0, R06 = 0, R07 = 0, R08 = 0, R09 = 0, R0A = 0, R0B = 0, R0C = 0, R0D = 0, R0E = 0, R0F = 0, // cipher key
        R10 = 0, R11 = 0, R12 = 0, R13 = 0, R14 = 0, R15 = 0, R16 = 0, R17 = 0, R18 = 0, R19 = 0, R1A = 0, R1B = 0, R1C = 0, R1D = 0, R1E = 0, R1F = 0, // round 1 key
        R20 = 0, R21 = 0, R22 = 0, R23 = 0, R24 = 0, R25 = 0, R26 = 0, R27 = 0, R28 = 0, R29 = 0, R2A = 0, R2B = 0, R2C = 0, R2D = 0, R2E = 0, R2F = 0, // round 2 key
        R30 = 0, R31 = 0, R32 = 0, R33 = 0, R34 = 0, R35 = 0, R36 = 0, R37 = 0, R38 = 0, R39 = 0, R3A = 0, R3B = 0, R3C = 0, R3D = 0, R3E = 0, R3F = 0, // round 3 key
        R40 = 0, R41 = 0, R42 = 0, R43 = 0, R44 = 0, R45 = 0, R46 = 0, R47 = 0, R48 = 0, R49 = 0, R4A = 0, R4B = 0, R4C = 0, R4D = 0, R4E = 0, R4F = 0, // round 4 key
        R50 = 0, R51 = 0, R52 = 0, R53 = 0, R54 = 0, R55 = 0, R56 = 0, R57 = 0, R58 = 0, R59 = 0, R5A = 0, R5B = 0, R5C = 0, R5D = 0, R5E = 0, R5F = 0, // round 5 key
        R60 = 0, R61 = 0, R62 = 0, R63 = 0, R64 = 0, R65 = 0, R66 = 0, R67 = 0, R68 = 0, R69 = 0, R6A = 0, R6B = 0, R6C = 0, R6D = 0, R6E = 0, R6F = 0, // round 6 key
        R70 = 0, R71 = 0, R72 = 0, R73 = 0, R74 = 0, R75 = 0, R76 = 0, R77 = 0, R78 = 0, R79 = 0, R7A = 0, R7B = 0, R7C = 0, R7D = 0, R7E = 0, R7F = 0, // round 7 key
        R80 = 0, R81 = 0, R82 = 0, R83 = 0, R84 = 0, R85 = 0, R86 = 0, R87 = 0, R88 = 0, R89 = 0, R8A = 0, R8B = 0, R8C = 0, R8D = 0, R8E = 0, R8F = 0, // round 8 key
        R90 = 0, R91 = 0, R92 = 0, R93 = 0, R94 = 0, R95 = 0, R96 = 0, R97 = 0, R98 = 0, R99 = 0, R9A = 0, R9B = 0, R9C = 0, R9D = 0, R9E = 0, R9F = 0, // round 9 key
        RA0 = 0, RA1 = 0, RA2 = 0, RA3 = 0, RA4 = 0, RA5 = 0, RA6 = 0, RA7 = 0, RA8 = 0, RA9 = 0, RAA = 0, RAB = 0, RAC = 0, RAD = 0, RAE = 0, RAF = 0; // round 10 key

    // I/O buffer
    var HEAP = new stdlib.Uint8Array(buffer);

    function _expand_key_128 () {
        // key 1
        R10 = R00 ^ HEAP[SBOX|R0D] ^ 0x01;
        R11 = R01 ^ HEAP[SBOX|R0E];
        R12 = R02 ^ HEAP[SBOX|R0F];
        R13 = R03 ^ HEAP[SBOX|R0C];
        R14 = R04 ^ R10;
        R15 = R05 ^ R11;
        R16 = R06 ^ R12;
        R17 = R07 ^ R13;
        R18 = R08 ^ R14;
        R19 = R09 ^ R15;
        R1A = R0A ^ R16;
        R1B = R0B ^ R17;
        R1C = R0C ^ R18;
        R1D = R0D ^ R19;
        R1E = R0E ^ R1A;
        R1F = R0F ^ R1B;

        // key 2
        R20 = R10 ^ HEAP[SBOX|R1D] ^ 0x02;
        R21 = R11 ^ HEAP[SBOX|R1E];
        R22 = R12 ^ HEAP[SBOX|R1F];
        R23 = R13 ^ HEAP[SBOX|R1C];
        R24 = R14 ^ R20;
        R25 = R15 ^ R21;
        R26 = R16 ^ R22;
        R27 = R17 ^ R23;
        R28 = R18 ^ R24;
        R29 = R19 ^ R25;
        R2A = R1A ^ R26;
        R2B = R1B ^ R27;
        R2C = R1C ^ R28;
        R2D = R1D ^ R29;
        R2E = R1E ^ R2A;
        R2F = R1F ^ R2B;

        // key 3
        R30 = R20 ^ HEAP[SBOX|R2D] ^ 0x04;
        R31 = R21 ^ HEAP[SBOX|R2E];
        R32 = R22 ^ HEAP[SBOX|R2F];
        R33 = R23 ^ HEAP[SBOX|R2C];
        R34 = R24 ^ R30;
        R35 = R25 ^ R31;
        R36 = R26 ^ R32;
        R37 = R27 ^ R33;
        R38 = R28 ^ R34;
        R39 = R29 ^ R35;
        R3A = R2A ^ R36;
        R3B = R2B ^ R37;
        R3C = R2C ^ R38;
        R3D = R2D ^ R39;
        R3E = R2E ^ R3A;
        R3F = R2F ^ R3B;

        // key 4
        R40 = R30 ^ HEAP[SBOX|R3D] ^ 0x08;
        R41 = R31 ^ HEAP[SBOX|R3E];
        R42 = R32 ^ HEAP[SBOX|R3F];
        R43 = R33 ^ HEAP[SBOX|R3C];
        R44 = R34 ^ R40;
        R45 = R35 ^ R41;
        R46 = R36 ^ R42;
        R47 = R37 ^ R43;
        R48 = R38 ^ R44;
        R49 = R39 ^ R45;
        R4A = R3A ^ R46;
        R4B = R3B ^ R47;
        R4C = R3C ^ R48;
        R4D = R3D ^ R49;
        R4E = R3E ^ R4A;
        R4F = R3F ^ R4B;

        // key 5
        R50 = R40 ^ HEAP[SBOX|R4D] ^ 0x10;
        R51 = R41 ^ HEAP[SBOX|R4E];
        R52 = R42 ^ HEAP[SBOX|R4F];
        R53 = R43 ^ HEAP[SBOX|R4C];
        R54 = R44 ^ R50;
        R55 = R45 ^ R51;
        R56 = R46 ^ R52;
        R57 = R47 ^ R53;
        R58 = R48 ^ R54;
        R59 = R49 ^ R55;
        R5A = R4A ^ R56;
        R5B = R4B ^ R57;
        R5C = R4C ^ R58;
        R5D = R4D ^ R59;
        R5E = R4E ^ R5A;
        R5F = R4F ^ R5B;

        // key 6
        R60 = R50 ^ HEAP[SBOX|R5D] ^ 0x20;
        R61 = R51 ^ HEAP[SBOX|R5E];
        R62 = R52 ^ HEAP[SBOX|R5F];
        R63 = R53 ^ HEAP[SBOX|R5C];
        R64 = R54 ^ R60;
        R65 = R55 ^ R61;
        R66 = R56 ^ R62;
        R67 = R57 ^ R63;
        R68 = R58 ^ R64;
        R69 = R59 ^ R65;
        R6A = R5A ^ R66;
        R6B = R5B ^ R67;
        R6C = R5C ^ R68;
        R6D = R5D ^ R69;
        R6E = R5E ^ R6A;
        R6F = R5F ^ R6B;

        // key 7
        R70 = R60 ^ HEAP[SBOX|R6D] ^ 0x40;
        R71 = R61 ^ HEAP[SBOX|R6E];
        R72 = R62 ^ HEAP[SBOX|R6F];
        R73 = R63 ^ HEAP[SBOX|R6C];
        R74 = R64 ^ R70;
        R75 = R65 ^ R71;
        R76 = R66 ^ R72;
        R77 = R67 ^ R73;
        R78 = R68 ^ R74;
        R79 = R69 ^ R75;
        R7A = R6A ^ R76;
        R7B = R6B ^ R77;
        R7C = R6C ^ R78;
        R7D = R6D ^ R79;
        R7E = R6E ^ R7A;
        R7F = R6F ^ R7B;

        // key 8
        R80 = R70 ^ HEAP[SBOX|R7D] ^ 0x80;
        R81 = R71 ^ HEAP[SBOX|R7E];
        R82 = R72 ^ HEAP[SBOX|R7F];
        R83 = R73 ^ HEAP[SBOX|R7C];
        R84 = R74 ^ R80;
        R85 = R75 ^ R81;
        R86 = R76 ^ R82;
        R87 = R77 ^ R83;
        R88 = R78 ^ R84;
        R89 = R79 ^ R85;
        R8A = R7A ^ R86;
        R8B = R7B ^ R87;
        R8C = R7C ^ R88;
        R8D = R7D ^ R89;
        R8E = R7E ^ R8A;
        R8F = R7F ^ R8B;

        // key 9
        R90 = R80 ^ HEAP[SBOX|R8D] ^ 0x1b;
        R91 = R81 ^ HEAP[SBOX|R8E];
        R92 = R82 ^ HEAP[SBOX|R8F];
        R93 = R83 ^ HEAP[SBOX|R8C];
        R94 = R84 ^ R90;
        R95 = R85 ^ R91;
        R96 = R86 ^ R92;
        R97 = R87 ^ R93;
        R98 = R88 ^ R94;
        R99 = R89 ^ R95;
        R9A = R8A ^ R96;
        R9B = R8B ^ R97;
        R9C = R8C ^ R98;
        R9D = R8D ^ R99;
        R9E = R8E ^ R9A;
        R9F = R8F ^ R9B;

        // key 10
        RA0 = R90 ^ HEAP[SBOX|R9D] ^ 0x36;
        RA1 = R91 ^ HEAP[SBOX|R9E];
        RA2 = R92 ^ HEAP[SBOX|R9F];
        RA3 = R93 ^ HEAP[SBOX|R9C];
        RA4 = R94 ^ RA0;
        RA5 = R95 ^ RA1;
        RA6 = R96 ^ RA2;
        RA7 = R97 ^ RA3;
        RA8 = R98 ^ RA4;
        RA9 = R99 ^ RA5;
        RAA = R9A ^ RA6;
        RAB = R9B ^ RA7;
        RAC = R9C ^ RA8;
        RAD = R9D ^ RA9;
        RAE = R9E ^ RAA;
        RAF = R9F ^ RAB;
    }

    function _encrypt_128 ( s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, sA, sB, sC, sD, sE, sF ) {
        s0 = s0|0;
        s1 = s1|0;
        s2 = s2|0;
        s3 = s3|0;
        s4 = s4|0;
        s5 = s5|0;
        s6 = s6|0;
        s7 = s7|0;
        s8 = s8|0;
        s9 = s9|0;
        sA = sA|0;
        sB = sB|0;
        sC = sC|0;
        sD = sD|0;
        sE = sE|0;
        sF = sF|0;

        var t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, t8 = 0, t9 = 0, tA = 0, tB = 0, tC = 0, tD = 0, tE = 0, tF = 0;

        // round 0
        s0 = s0 ^ R00;
        s1 = s1 ^ R01;
        s2 = s2 ^ R02;
        s3 = s3 ^ R03;
        s4 = s4 ^ R04;
        s5 = s5 ^ R05;
        s6 = s6 ^ R06;
        s7 = s7 ^ R07;
        s8 = s8 ^ R08;
        s9 = s9 ^ R09;
        sA = sA ^ R0A;
        sB = sB ^ R0B;
        sC = sC ^ R0C;
        sD = sD ^ R0D;
        sE = sE ^ R0E;
        sF = sF ^ R0F;

        // round 1
        t0 = HEAP[X2_SBOX|s0] ^ HEAP[X3_SBOX|s5] ^ HEAP[SBOX|sA] ^ HEAP[SBOX|sF] ^ R10;
        t1 = HEAP[SBOX|s0] ^ HEAP[X2_SBOX|s5] ^ HEAP[X3_SBOX|sA] ^ HEAP[SBOX|sF] ^ R11;
        t2 = HEAP[SBOX|s0] ^ HEAP[SBOX|s5] ^ HEAP[X2_SBOX|sA] ^ HEAP[X3_SBOX|sF] ^ R12;
        t3 = HEAP[X3_SBOX|s0] ^ HEAP[SBOX|s5] ^ HEAP[SBOX|sA] ^ HEAP[X2_SBOX|sF] ^ R13;
        t4 = HEAP[X2_SBOX|s4] ^ HEAP[X3_SBOX|s9] ^ HEAP[SBOX|sE] ^ HEAP[SBOX|s3] ^ R14;
        t5 = HEAP[SBOX|s4] ^ HEAP[X2_SBOX|s9] ^ HEAP[X3_SBOX|sE] ^ HEAP[SBOX|s3] ^ R15;
        t6 = HEAP[SBOX|s4] ^ HEAP[SBOX|s9] ^ HEAP[X2_SBOX|sE] ^ HEAP[X3_SBOX|s3] ^ R16;
        t7 = HEAP[X3_SBOX|s4] ^ HEAP[SBOX|s9] ^ HEAP[SBOX|sE] ^ HEAP[X2_SBOX|s3] ^ R17;
        t8 = HEAP[X2_SBOX|s8] ^ HEAP[X3_SBOX|sD] ^ HEAP[SBOX|s2] ^ HEAP[SBOX|s7] ^ R18;
        t9 = HEAP[SBOX|s8] ^ HEAP[X2_SBOX|sD] ^ HEAP[X3_SBOX|s2] ^ HEAP[SBOX|s7] ^ R19;
        tA = HEAP[SBOX|s8] ^ HEAP[SBOX|sD] ^ HEAP[X2_SBOX|s2] ^ HEAP[X3_SBOX|s7] ^ R1A;
        tB = HEAP[X3_SBOX|s8] ^ HEAP[SBOX|sD] ^ HEAP[SBOX|s2] ^ HEAP[X2_SBOX|s7] ^ R1B;
        tC = HEAP[X2_SBOX|sC] ^ HEAP[X3_SBOX|s1] ^ HEAP[SBOX|s6] ^ HEAP[SBOX|sB] ^ R1C;
        tD = HEAP[SBOX|sC] ^ HEAP[X2_SBOX|s1] ^ HEAP[X3_SBOX|s6] ^ HEAP[SBOX|sB] ^ R1D;
        tE = HEAP[SBOX|sC] ^ HEAP[SBOX|s1] ^ HEAP[X2_SBOX|s6] ^ HEAP[X3_SBOX|sB] ^ R1E;
        tF = HEAP[X3_SBOX|sC] ^ HEAP[SBOX|s1] ^ HEAP[SBOX|s6] ^ HEAP[X2_SBOX|sB] ^ R1F;

        // round 2
        s0 = HEAP[X2_SBOX|t0] ^ HEAP[X3_SBOX|t5] ^ HEAP[SBOX|tA] ^ HEAP[SBOX|tF] ^ R20;
        s1 = HEAP[SBOX|t0] ^ HEAP[X2_SBOX|t5] ^ HEAP[X3_SBOX|tA] ^ HEAP[SBOX|tF] ^ R21;
        s2 = HEAP[SBOX|t0] ^ HEAP[SBOX|t5] ^ HEAP[X2_SBOX|tA] ^ HEAP[X3_SBOX|tF] ^ R22;
        s3 = HEAP[X3_SBOX|t0] ^ HEAP[SBOX|t5] ^ HEAP[SBOX|tA] ^ HEAP[X2_SBOX|tF] ^ R23;
        s4 = HEAP[X2_SBOX|t4] ^ HEAP[X3_SBOX|t9] ^ HEAP[SBOX|tE] ^ HEAP[SBOX|t3] ^ R24;
        s5 = HEAP[SBOX|t4] ^ HEAP[X2_SBOX|t9] ^ HEAP[X3_SBOX|tE] ^ HEAP[SBOX|t3] ^ R25;
        s6 = HEAP[SBOX|t4] ^ HEAP[SBOX|t9] ^ HEAP[X2_SBOX|tE] ^ HEAP[X3_SBOX|t3] ^ R26;
        s7 = HEAP[X3_SBOX|t4] ^ HEAP[SBOX|t9] ^ HEAP[SBOX|tE] ^ HEAP[X2_SBOX|t3] ^ R27;
        s8 = HEAP[X2_SBOX|t8] ^ HEAP[X3_SBOX|tD] ^ HEAP[SBOX|t2] ^ HEAP[SBOX|t7] ^ R28;
        s9 = HEAP[SBOX|t8] ^ HEAP[X2_SBOX|tD] ^ HEAP[X3_SBOX|t2] ^ HEAP[SBOX|t7] ^ R29;
        sA = HEAP[SBOX|t8] ^ HEAP[SBOX|tD] ^ HEAP[X2_SBOX|t2] ^ HEAP[X3_SBOX|t7] ^ R2A;
        sB = HEAP[X3_SBOX|t8] ^ HEAP[SBOX|tD] ^ HEAP[SBOX|t2] ^ HEAP[X2_SBOX|t7] ^ R2B;
        sC = HEAP[X2_SBOX|tC] ^ HEAP[X3_SBOX|t1] ^ HEAP[SBOX|t6] ^ HEAP[SBOX|tB] ^ R2C;
        sD = HEAP[SBOX|tC] ^ HEAP[X2_SBOX|t1] ^ HEAP[X3_SBOX|t6] ^ HEAP[SBOX|tB] ^ R2D;
        sE = HEAP[SBOX|tC] ^ HEAP[SBOX|t1] ^ HEAP[X2_SBOX|t6] ^ HEAP[X3_SBOX|tB] ^ R2E;
        sF = HEAP[X3_SBOX|tC] ^ HEAP[SBOX|t1] ^ HEAP[SBOX|t6] ^ HEAP[X2_SBOX|tB] ^ R2F;

        // round 3
        t0 = HEAP[X2_SBOX|s0] ^ HEAP[X3_SBOX|s5] ^ HEAP[SBOX|sA] ^ HEAP[SBOX|sF] ^ R30;
        t1 = HEAP[SBOX|s0] ^ HEAP[X2_SBOX|s5] ^ HEAP[X3_SBOX|sA] ^ HEAP[SBOX|sF] ^ R31;
        t2 = HEAP[SBOX|s0] ^ HEAP[SBOX|s5] ^ HEAP[X2_SBOX|sA] ^ HEAP[X3_SBOX|sF] ^ R32;
        t3 = HEAP[X3_SBOX|s0] ^ HEAP[SBOX|s5] ^ HEAP[SBOX|sA] ^ HEAP[X2_SBOX|sF] ^ R33;
        t4 = HEAP[X2_SBOX|s4] ^ HEAP[X3_SBOX|s9] ^ HEAP[SBOX|sE] ^ HEAP[SBOX|s3] ^ R34;
        t5 = HEAP[SBOX|s4] ^ HEAP[X2_SBOX|s9] ^ HEAP[X3_SBOX|sE] ^ HEAP[SBOX|s3] ^ R35;
        t6 = HEAP[SBOX|s4] ^ HEAP[SBOX|s9] ^ HEAP[X2_SBOX|sE] ^ HEAP[X3_SBOX|s3] ^ R36;
        t7 = HEAP[X3_SBOX|s4] ^ HEAP[SBOX|s9] ^ HEAP[SBOX|sE] ^ HEAP[X2_SBOX|s3] ^ R37;
        t8 = HEAP[X2_SBOX|s8] ^ HEAP[X3_SBOX|sD] ^ HEAP[SBOX|s2] ^ HEAP[SBOX|s7] ^ R38;
        t9 = HEAP[SBOX|s8] ^ HEAP[X2_SBOX|sD] ^ HEAP[X3_SBOX|s2] ^ HEAP[SBOX|s7] ^ R39;
        tA = HEAP[SBOX|s8] ^ HEAP[SBOX|sD] ^ HEAP[X2_SBOX|s2] ^ HEAP[X3_SBOX|s7] ^ R3A;
        tB = HEAP[X3_SBOX|s8] ^ HEAP[SBOX|sD] ^ HEAP[SBOX|s2] ^ HEAP[X2_SBOX|s7] ^ R3B;
        tC = HEAP[X2_SBOX|sC] ^ HEAP[X3_SBOX|s1] ^ HEAP[SBOX|s6] ^ HEAP[SBOX|sB] ^ R3C;
        tD = HEAP[SBOX|sC] ^ HEAP[X2_SBOX|s1] ^ HEAP[X3_SBOX|s6] ^ HEAP[SBOX|sB] ^ R3D;
        tE = HEAP[SBOX|sC] ^ HEAP[SBOX|s1] ^ HEAP[X2_SBOX|s6] ^ HEAP[X3_SBOX|sB] ^ R3E;
        tF = HEAP[X3_SBOX|sC] ^ HEAP[SBOX|s1] ^ HEAP[SBOX|s6] ^ HEAP[X2_SBOX|sB] ^ R3F;

        // round 4
        s0 = HEAP[X2_SBOX|t0] ^ HEAP[X3_SBOX|t5] ^ HEAP[SBOX|tA] ^ HEAP[SBOX|tF] ^ R40;
        s1 = HEAP[SBOX|t0] ^ HEAP[X2_SBOX|t5] ^ HEAP[X3_SBOX|tA] ^ HEAP[SBOX|tF] ^ R41;
        s2 = HEAP[SBOX|t0] ^ HEAP[SBOX|t5] ^ HEAP[X2_SBOX|tA] ^ HEAP[X3_SBOX|tF] ^ R42;
        s3 = HEAP[X3_SBOX|t0] ^ HEAP[SBOX|t5] ^ HEAP[SBOX|tA] ^ HEAP[X2_SBOX|tF] ^ R43;
        s4 = HEAP[X2_SBOX|t4] ^ HEAP[X3_SBOX|t9] ^ HEAP[SBOX|tE] ^ HEAP[SBOX|t3] ^ R44;
        s5 = HEAP[SBOX|t4] ^ HEAP[X2_SBOX|t9] ^ HEAP[X3_SBOX|tE] ^ HEAP[SBOX|t3] ^ R45;
        s6 = HEAP[SBOX|t4] ^ HEAP[SBOX|t9] ^ HEAP[X2_SBOX|tE] ^ HEAP[X3_SBOX|t3] ^ R46;
        s7 = HEAP[X3_SBOX|t4] ^ HEAP[SBOX|t9] ^ HEAP[SBOX|tE] ^ HEAP[X2_SBOX|t3] ^ R47;
        s8 = HEAP[X2_SBOX|t8] ^ HEAP[X3_SBOX|tD] ^ HEAP[SBOX|t2] ^ HEAP[SBOX|t7] ^ R48;
        s9 = HEAP[SBOX|t8] ^ HEAP[X2_SBOX|tD] ^ HEAP[X3_SBOX|t2] ^ HEAP[SBOX|t7] ^ R49;
        sA = HEAP[SBOX|t8] ^ HEAP[SBOX|tD] ^ HEAP[X2_SBOX|t2] ^ HEAP[X3_SBOX|t7] ^ R4A;
        sB = HEAP[X3_SBOX|t8] ^ HEAP[SBOX|tD] ^ HEAP[SBOX|t2] ^ HEAP[X2_SBOX|t7] ^ R4B;
        sC = HEAP[X2_SBOX|tC] ^ HEAP[X3_SBOX|t1] ^ HEAP[SBOX|t6] ^ HEAP[SBOX|tB] ^ R4C;
        sD = HEAP[SBOX|tC] ^ HEAP[X2_SBOX|t1] ^ HEAP[X3_SBOX|t6] ^ HEAP[SBOX|tB] ^ R4D;
        sE = HEAP[SBOX|tC] ^ HEAP[SBOX|t1] ^ HEAP[X2_SBOX|t6] ^ HEAP[X3_SBOX|tB] ^ R4E;
        sF = HEAP[X3_SBOX|tC] ^ HEAP[SBOX|t1] ^ HEAP[SBOX|t6] ^ HEAP[X2_SBOX|tB] ^ R4F;

        // round 5
        t0 = HEAP[X2_SBOX|s0] ^ HEAP[X3_SBOX|s5] ^ HEAP[SBOX|sA] ^ HEAP[SBOX|sF] ^ R50;
        t1 = HEAP[SBOX|s0] ^ HEAP[X2_SBOX|s5] ^ HEAP[X3_SBOX|sA] ^ HEAP[SBOX|sF] ^ R51;
        t2 = HEAP[SBOX|s0] ^ HEAP[SBOX|s5] ^ HEAP[X2_SBOX|sA] ^ HEAP[X3_SBOX|sF] ^ R52;
        t3 = HEAP[X3_SBOX|s0] ^ HEAP[SBOX|s5] ^ HEAP[SBOX|sA] ^ HEAP[X2_SBOX|sF] ^ R53;
        t4 = HEAP[X2_SBOX|s4] ^ HEAP[X3_SBOX|s9] ^ HEAP[SBOX|sE] ^ HEAP[SBOX|s3] ^ R54;
        t5 = HEAP[SBOX|s4] ^ HEAP[X2_SBOX|s9] ^ HEAP[X3_SBOX|sE] ^ HEAP[SBOX|s3] ^ R55;
        t6 = HEAP[SBOX|s4] ^ HEAP[SBOX|s9] ^ HEAP[X2_SBOX|sE] ^ HEAP[X3_SBOX|s3] ^ R56;
        t7 = HEAP[X3_SBOX|s4] ^ HEAP[SBOX|s9] ^ HEAP[SBOX|sE] ^ HEAP[X2_SBOX|s3] ^ R57;
        t8 = HEAP[X2_SBOX|s8] ^ HEAP[X3_SBOX|sD] ^ HEAP[SBOX|s2] ^ HEAP[SBOX|s7] ^ R58;
        t9 = HEAP[SBOX|s8] ^ HEAP[X2_SBOX|sD] ^ HEAP[X3_SBOX|s2] ^ HEAP[SBOX|s7] ^ R59;
        tA = HEAP[SBOX|s8] ^ HEAP[SBOX|sD] ^ HEAP[X2_SBOX|s2] ^ HEAP[X3_SBOX|s7] ^ R5A;
        tB = HEAP[X3_SBOX|s8] ^ HEAP[SBOX|sD] ^ HEAP[SBOX|s2] ^ HEAP[X2_SBOX|s7] ^ R5B;
        tC = HEAP[X2_SBOX|sC] ^ HEAP[X3_SBOX|s1] ^ HEAP[SBOX|s6] ^ HEAP[SBOX|sB] ^ R5C;
        tD = HEAP[SBOX|sC] ^ HEAP[X2_SBOX|s1] ^ HEAP[X3_SBOX|s6] ^ HEAP[SBOX|sB] ^ R5D;
        tE = HEAP[SBOX|sC] ^ HEAP[SBOX|s1] ^ HEAP[X2_SBOX|s6] ^ HEAP[X3_SBOX|sB] ^ R5E;
        tF = HEAP[X3_SBOX|sC] ^ HEAP[SBOX|s1] ^ HEAP[SBOX|s6] ^ HEAP[X2_SBOX|sB] ^ R5F;

        // round 6
        s0 = HEAP[X2_SBOX|t0] ^ HEAP[X3_SBOX|t5] ^ HEAP[SBOX|tA] ^ HEAP[SBOX|tF] ^ R60;
        s1 = HEAP[SBOX|t0] ^ HEAP[X2_SBOX|t5] ^ HEAP[X3_SBOX|tA] ^ HEAP[SBOX|tF] ^ R61;
        s2 = HEAP[SBOX|t0] ^ HEAP[SBOX|t5] ^ HEAP[X2_SBOX|tA] ^ HEAP[X3_SBOX|tF] ^ R62;
        s3 = HEAP[X3_SBOX|t0] ^ HEAP[SBOX|t5] ^ HEAP[SBOX|tA] ^ HEAP[X2_SBOX|tF] ^ R63;
        s4 = HEAP[X2_SBOX|t4] ^ HEAP[X3_SBOX|t9] ^ HEAP[SBOX|tE] ^ HEAP[SBOX|t3] ^ R64;
        s5 = HEAP[SBOX|t4] ^ HEAP[X2_SBOX|t9] ^ HEAP[X3_SBOX|tE] ^ HEAP[SBOX|t3] ^ R65;
        s6 = HEAP[SBOX|t4] ^ HEAP[SBOX|t9] ^ HEAP[X2_SBOX|tE] ^ HEAP[X3_SBOX|t3] ^ R66;
        s7 = HEAP[X3_SBOX|t4] ^ HEAP[SBOX|t9] ^ HEAP[SBOX|tE] ^ HEAP[X2_SBOX|t3] ^ R67;
        s8 = HEAP[X2_SBOX|t8] ^ HEAP[X3_SBOX|tD] ^ HEAP[SBOX|t2] ^ HEAP[SBOX|t7] ^ R68;
        s9 = HEAP[SBOX|t8] ^ HEAP[X2_SBOX|tD] ^ HEAP[X3_SBOX|t2] ^ HEAP[SBOX|t7] ^ R69;
        sA = HEAP[SBOX|t8] ^ HEAP[SBOX|tD] ^ HEAP[X2_SBOX|t2] ^ HEAP[X3_SBOX|t7] ^ R6A;
        sB = HEAP[X3_SBOX|t8] ^ HEAP[SBOX|tD] ^ HEAP[SBOX|t2] ^ HEAP[X2_SBOX|t7] ^ R6B;
        sC = HEAP[X2_SBOX|tC] ^ HEAP[X3_SBOX|t1] ^ HEAP[SBOX|t6] ^ HEAP[SBOX|tB] ^ R6C;
        sD = HEAP[SBOX|tC] ^ HEAP[X2_SBOX|t1] ^ HEAP[X3_SBOX|t6] ^ HEAP[SBOX|tB] ^ R6D;
        sE = HEAP[SBOX|tC] ^ HEAP[SBOX|t1] ^ HEAP[X2_SBOX|t6] ^ HEAP[X3_SBOX|tB] ^ R6E;
        sF = HEAP[X3_SBOX|tC] ^ HEAP[SBOX|t1] ^ HEAP[SBOX|t6] ^ HEAP[X2_SBOX|tB] ^ R6F;

        // round 7
        t0 = HEAP[X2_SBOX|s0] ^ HEAP[X3_SBOX|s5] ^ HEAP[SBOX|sA] ^ HEAP[SBOX|sF] ^ R70;
        t1 = HEAP[SBOX|s0] ^ HEAP[X2_SBOX|s5] ^ HEAP[X3_SBOX|sA] ^ HEAP[SBOX|sF] ^ R71;
        t2 = HEAP[SBOX|s0] ^ HEAP[SBOX|s5] ^ HEAP[X2_SBOX|sA] ^ HEAP[X3_SBOX|sF] ^ R72;
        t3 = HEAP[X3_SBOX|s0] ^ HEAP[SBOX|s5] ^ HEAP[SBOX|sA] ^ HEAP[X2_SBOX|sF] ^ R73;
        t4 = HEAP[X2_SBOX|s4] ^ HEAP[X3_SBOX|s9] ^ HEAP[SBOX|sE] ^ HEAP[SBOX|s3] ^ R74;
        t5 = HEAP[SBOX|s4] ^ HEAP[X2_SBOX|s9] ^ HEAP[X3_SBOX|sE] ^ HEAP[SBOX|s3] ^ R75;
        t6 = HEAP[SBOX|s4] ^ HEAP[SBOX|s9] ^ HEAP[X2_SBOX|sE] ^ HEAP[X3_SBOX|s3] ^ R76;
        t7 = HEAP[X3_SBOX|s4] ^ HEAP[SBOX|s9] ^ HEAP[SBOX|sE] ^ HEAP[X2_SBOX|s3] ^ R77;
        t8 = HEAP[X2_SBOX|s8] ^ HEAP[X3_SBOX|sD] ^ HEAP[SBOX|s2] ^ HEAP[SBOX|s7] ^ R78;
        t9 = HEAP[SBOX|s8] ^ HEAP[X2_SBOX|sD] ^ HEAP[X3_SBOX|s2] ^ HEAP[SBOX|s7] ^ R79;
        tA = HEAP[SBOX|s8] ^ HEAP[SBOX|sD] ^ HEAP[X2_SBOX|s2] ^ HEAP[X3_SBOX|s7] ^ R7A;
        tB = HEAP[X3_SBOX|s8] ^ HEAP[SBOX|sD] ^ HEAP[SBOX|s2] ^ HEAP[X2_SBOX|s7] ^ R7B;
        tC = HEAP[X2_SBOX|sC] ^ HEAP[X3_SBOX|s1] ^ HEAP[SBOX|s6] ^ HEAP[SBOX|sB] ^ R7C;
        tD = HEAP[SBOX|sC] ^ HEAP[X2_SBOX|s1] ^ HEAP[X3_SBOX|s6] ^ HEAP[SBOX|sB] ^ R7D;
        tE = HEAP[SBOX|sC] ^ HEAP[SBOX|s1] ^ HEAP[X2_SBOX|s6] ^ HEAP[X3_SBOX|sB] ^ R7E;
        tF = HEAP[X3_SBOX|sC] ^ HEAP[SBOX|s1] ^ HEAP[SBOX|s6] ^ HEAP[X2_SBOX|sB] ^ R7F;

        // round 8
        s0 = HEAP[X2_SBOX|t0] ^ HEAP[X3_SBOX|t5] ^ HEAP[SBOX|tA] ^ HEAP[SBOX|tF] ^ R80;
        s1 = HEAP[SBOX|t0] ^ HEAP[X2_SBOX|t5] ^ HEAP[X3_SBOX|tA] ^ HEAP[SBOX|tF] ^ R81;
        s2 = HEAP[SBOX|t0] ^ HEAP[SBOX|t5] ^ HEAP[X2_SBOX|tA] ^ HEAP[X3_SBOX|tF] ^ R82;
        s3 = HEAP[X3_SBOX|t0] ^ HEAP[SBOX|t5] ^ HEAP[SBOX|tA] ^ HEAP[X2_SBOX|tF] ^ R83;
        s4 = HEAP[X2_SBOX|t4] ^ HEAP[X3_SBOX|t9] ^ HEAP[SBOX|tE] ^ HEAP[SBOX|t3] ^ R84;
        s5 = HEAP[SBOX|t4] ^ HEAP[X2_SBOX|t9] ^ HEAP[X3_SBOX|tE] ^ HEAP[SBOX|t3] ^ R85;
        s6 = HEAP[SBOX|t4] ^ HEAP[SBOX|t9] ^ HEAP[X2_SBOX|tE] ^ HEAP[X3_SBOX|t3] ^ R86;
        s7 = HEAP[X3_SBOX|t4] ^ HEAP[SBOX|t9] ^ HEAP[SBOX|tE] ^ HEAP[X2_SBOX|t3] ^ R87;
        s8 = HEAP[X2_SBOX|t8] ^ HEAP[X3_SBOX|tD] ^ HEAP[SBOX|t2] ^ HEAP[SBOX|t7] ^ R88;
        s9 = HEAP[SBOX|t8] ^ HEAP[X2_SBOX|tD] ^ HEAP[X3_SBOX|t2] ^ HEAP[SBOX|t7] ^ R89;
        sA = HEAP[SBOX|t8] ^ HEAP[SBOX|tD] ^ HEAP[X2_SBOX|t2] ^ HEAP[X3_SBOX|t7] ^ R8A;
        sB = HEAP[X3_SBOX|t8] ^ HEAP[SBOX|tD] ^ HEAP[SBOX|t2] ^ HEAP[X2_SBOX|t7] ^ R8B;
        sC = HEAP[X2_SBOX|tC] ^ HEAP[X3_SBOX|t1] ^ HEAP[SBOX|t6] ^ HEAP[SBOX|tB] ^ R8C;
        sD = HEAP[SBOX|tC] ^ HEAP[X2_SBOX|t1] ^ HEAP[X3_SBOX|t6] ^ HEAP[SBOX|tB] ^ R8D;
        sE = HEAP[SBOX|tC] ^ HEAP[SBOX|t1] ^ HEAP[X2_SBOX|t6] ^ HEAP[X3_SBOX|tB] ^ R8E;
        sF = HEAP[X3_SBOX|tC] ^ HEAP[SBOX|t1] ^ HEAP[SBOX|t6] ^ HEAP[X2_SBOX|tB] ^ R8F;

        // round 9
        t0 = HEAP[X2_SBOX|s0] ^ HEAP[X3_SBOX|s5] ^ HEAP[SBOX|sA] ^ HEAP[SBOX|sF] ^ R90;
        t1 = HEAP[SBOX|s0] ^ HEAP[X2_SBOX|s5] ^ HEAP[X3_SBOX|sA] ^ HEAP[SBOX|sF] ^ R91;
        t2 = HEAP[SBOX|s0] ^ HEAP[SBOX|s5] ^ HEAP[X2_SBOX|sA] ^ HEAP[X3_SBOX|sF] ^ R92;
        t3 = HEAP[X3_SBOX|s0] ^ HEAP[SBOX|s5] ^ HEAP[SBOX|sA] ^ HEAP[X2_SBOX|sF] ^ R93;
        t4 = HEAP[X2_SBOX|s4] ^ HEAP[X3_SBOX|s9] ^ HEAP[SBOX|sE] ^ HEAP[SBOX|s3] ^ R94;
        t5 = HEAP[SBOX|s4] ^ HEAP[X2_SBOX|s9] ^ HEAP[X3_SBOX|sE] ^ HEAP[SBOX|s3] ^ R95;
        t6 = HEAP[SBOX|s4] ^ HEAP[SBOX|s9] ^ HEAP[X2_SBOX|sE] ^ HEAP[X3_SBOX|s3] ^ R96;
        t7 = HEAP[X3_SBOX|s4] ^ HEAP[SBOX|s9] ^ HEAP[SBOX|sE] ^ HEAP[X2_SBOX|s3] ^ R97;
        t8 = HEAP[X2_SBOX|s8] ^ HEAP[X3_SBOX|sD] ^ HEAP[SBOX|s2] ^ HEAP[SBOX|s7] ^ R98;
        t9 = HEAP[SBOX|s8] ^ HEAP[X2_SBOX|sD] ^ HEAP[X3_SBOX|s2] ^ HEAP[SBOX|s7] ^ R99;
        tA = HEAP[SBOX|s8] ^ HEAP[SBOX|sD] ^ HEAP[X2_SBOX|s2] ^ HEAP[X3_SBOX|s7] ^ R9A;
        tB = HEAP[X3_SBOX|s8] ^ HEAP[SBOX|sD] ^ HEAP[SBOX|s2] ^ HEAP[X2_SBOX|s7] ^ R9B;
        tC = HEAP[X2_SBOX|sC] ^ HEAP[X3_SBOX|s1] ^ HEAP[SBOX|s6] ^ HEAP[SBOX|sB] ^ R9C;
        tD = HEAP[SBOX|sC] ^ HEAP[X2_SBOX|s1] ^ HEAP[X3_SBOX|s6] ^ HEAP[SBOX|sB] ^ R9D;
        tE = HEAP[SBOX|sC] ^ HEAP[SBOX|s1] ^ HEAP[X2_SBOX|s6] ^ HEAP[X3_SBOX|sB] ^ R9E;
        tF = HEAP[X3_SBOX|sC] ^ HEAP[SBOX|s1] ^ HEAP[SBOX|s6] ^ HEAP[X2_SBOX|sB] ^ R9F;

        // round 10
        S0 = HEAP[SBOX|t0] ^ RA0;
        S1 = HEAP[SBOX|t5] ^ RA1;
        S2 = HEAP[SBOX|tA] ^ RA2;
        S3 = HEAP[SBOX|tF] ^ RA3;
        S4 = HEAP[SBOX|t4] ^ RA4;
        S5 = HEAP[SBOX|t9] ^ RA5;
        S6 = HEAP[SBOX|tE] ^ RA6;
        S7 = HEAP[SBOX|t3] ^ RA7;
        S8 = HEAP[SBOX|t8] ^ RA8;
        S9 = HEAP[SBOX|tD] ^ RA9;
        SA = HEAP[SBOX|t2] ^ RAA;
        SB = HEAP[SBOX|t7] ^ RAB;
        SC = HEAP[SBOX|tC] ^ RAC;
        SD = HEAP[SBOX|t1] ^ RAD;
        SE = HEAP[SBOX|t6] ^ RAE;
        SF = HEAP[SBOX|tB] ^ RAF;
    }

    function _decrypt_128 ( s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, sA, sB, sC, sD, sE, sF ) {
        s0 = s0|0;
        s1 = s1|0;
        s2 = s2|0;
        s3 = s3|0;
        s4 = s4|0;
        s5 = s5|0;
        s6 = s6|0;
        s7 = s7|0;
        s8 = s8|0;
        s9 = s9|0;
        sA = sA|0;
        sB = sB|0;
        sC = sC|0;
        sD = sD|0;
        sE = sE|0;
        sF = sF|0;

        var t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, t8 = 0, t9 = 0, tA = 0, tB = 0, tC = 0, tD = 0, tE = 0, tF = 0;

        // round 10+9
        t0 = HEAP[INV_SBOX|(s0 ^ RA0)] ^ R90;
        t1 = HEAP[INV_SBOX|(sD ^ RAD)] ^ R91;
        t2 = HEAP[INV_SBOX|(sA ^ RAA)] ^ R92;
        t3 = HEAP[INV_SBOX|(s7 ^ RA7)] ^ R93;
        t4 = HEAP[INV_SBOX|(s4 ^ RA4)] ^ R94;
        t5 = HEAP[INV_SBOX|(s1 ^ RA1)] ^ R95;
        t6 = HEAP[INV_SBOX|(sE ^ RAE)] ^ R96;
        t7 = HEAP[INV_SBOX|(sB ^ RAB)] ^ R97;
        t8 = HEAP[INV_SBOX|(s8 ^ RA8)] ^ R98;
        t9 = HEAP[INV_SBOX|(s5 ^ RA5)] ^ R99;
        tA = HEAP[INV_SBOX|(s2 ^ RA2)] ^ R9A;
        tB = HEAP[INV_SBOX|(sF ^ RAF)] ^ R9B;
        tC = HEAP[INV_SBOX|(sC ^ RAC)] ^ R9C;
        tD = HEAP[INV_SBOX|(s9 ^ RA9)] ^ R9D;
        tE = HEAP[INV_SBOX|(s6 ^ RA6)] ^ R9E;
        tF = HEAP[INV_SBOX|(s3 ^ RA3)] ^ R9F;
        s0 = HEAP[XE|t0] ^ HEAP[XB|t1] ^ HEAP[XD|t2] ^ HEAP[X9|t3];
        s1 = HEAP[X9|tC] ^ HEAP[XE|tD] ^ HEAP[XB|tE] ^ HEAP[XD|tF];
        s2 = HEAP[XD|t8] ^ HEAP[X9|t9] ^ HEAP[XE|tA] ^ HEAP[XB|tB];
        s3 = HEAP[XB|t4] ^ HEAP[XD|t5] ^ HEAP[X9|t6] ^ HEAP[XE|t7];
        s4 = HEAP[XE|t4] ^ HEAP[XB|t5] ^ HEAP[XD|t6] ^ HEAP[X9|t7];
        s5 = HEAP[X9|t0] ^ HEAP[XE|t1] ^ HEAP[XB|t2] ^ HEAP[XD|t3];
        s6 = HEAP[XD|tC] ^ HEAP[X9|tD] ^ HEAP[XE|tE] ^ HEAP[XB|tF];
        s7 = HEAP[XB|t8] ^ HEAP[XD|t9] ^ HEAP[X9|tA] ^ HEAP[XE|tB];
        s8 = HEAP[XE|t8] ^ HEAP[XB|t9] ^ HEAP[XD|tA] ^ HEAP[X9|tB];
        s9 = HEAP[X9|t4] ^ HEAP[XE|t5] ^ HEAP[XB|t6] ^ HEAP[XD|t7];
        sA = HEAP[XD|t0] ^ HEAP[X9|t1] ^ HEAP[XE|t2] ^ HEAP[XB|t3];
        sB = HEAP[XB|tC] ^ HEAP[XD|tD] ^ HEAP[X9|tE] ^ HEAP[XE|tF];
        sC = HEAP[XE|tC] ^ HEAP[XB|tD] ^ HEAP[XD|tE] ^ HEAP[X9|tF];
        sD = HEAP[X9|t8] ^ HEAP[XE|t9] ^ HEAP[XB|tA] ^ HEAP[XD|tB];
        sE = HEAP[XD|t4] ^ HEAP[X9|t5] ^ HEAP[XE|t6] ^ HEAP[XB|t7];
        sF = HEAP[XB|t0] ^ HEAP[XD|t1] ^ HEAP[X9|t2] ^ HEAP[XE|t3];

        // round 8
        t0 = HEAP[INV_SBOX|s0] ^ R80;
        t1 = HEAP[INV_SBOX|s1] ^ R81;
        t2 = HEAP[INV_SBOX|s2] ^ R82;
        t3 = HEAP[INV_SBOX|s3] ^ R83;
        t4 = HEAP[INV_SBOX|s4] ^ R84;
        t5 = HEAP[INV_SBOX|s5] ^ R85;
        t6 = HEAP[INV_SBOX|s6] ^ R86;
        t7 = HEAP[INV_SBOX|s7] ^ R87;
        t8 = HEAP[INV_SBOX|s8] ^ R88;
        t9 = HEAP[INV_SBOX|s9] ^ R89;
        tA = HEAP[INV_SBOX|sA] ^ R8A;
        tB = HEAP[INV_SBOX|sB] ^ R8B;
        tC = HEAP[INV_SBOX|sC] ^ R8C;
        tD = HEAP[INV_SBOX|sD] ^ R8D;
        tE = HEAP[INV_SBOX|sE] ^ R8E;
        tF = HEAP[INV_SBOX|sF] ^ R8F;
        s0 = HEAP[XE|t0] ^ HEAP[XB|t1] ^ HEAP[XD|t2] ^ HEAP[X9|t3];
        s1 = HEAP[X9|tC] ^ HEAP[XE|tD] ^ HEAP[XB|tE] ^ HEAP[XD|tF];
        s2 = HEAP[XD|t8] ^ HEAP[X9|t9] ^ HEAP[XE|tA] ^ HEAP[XB|tB];
        s3 = HEAP[XB|t4] ^ HEAP[XD|t5] ^ HEAP[X9|t6] ^ HEAP[XE|t7];
        s4 = HEAP[XE|t4] ^ HEAP[XB|t5] ^ HEAP[XD|t6] ^ HEAP[X9|t7];
        s5 = HEAP[X9|t0] ^ HEAP[XE|t1] ^ HEAP[XB|t2] ^ HEAP[XD|t3];
        s6 = HEAP[XD|tC] ^ HEAP[X9|tD] ^ HEAP[XE|tE] ^ HEAP[XB|tF];
        s7 = HEAP[XB|t8] ^ HEAP[XD|t9] ^ HEAP[X9|tA] ^ HEAP[XE|tB];
        s8 = HEAP[XE|t8] ^ HEAP[XB|t9] ^ HEAP[XD|tA] ^ HEAP[X9|tB];
        s9 = HEAP[X9|t4] ^ HEAP[XE|t5] ^ HEAP[XB|t6] ^ HEAP[XD|t7];
        sA = HEAP[XD|t0] ^ HEAP[X9|t1] ^ HEAP[XE|t2] ^ HEAP[XB|t3];
        sB = HEAP[XB|tC] ^ HEAP[XD|tD] ^ HEAP[X9|tE] ^ HEAP[XE|tF];
        sC = HEAP[XE|tC] ^ HEAP[XB|tD] ^ HEAP[XD|tE] ^ HEAP[X9|tF];
        sD = HEAP[X9|t8] ^ HEAP[XE|t9] ^ HEAP[XB|tA] ^ HEAP[XD|tB];
        sE = HEAP[XD|t4] ^ HEAP[X9|t5] ^ HEAP[XE|t6] ^ HEAP[XB|t7];
        sF = HEAP[XB|t0] ^ HEAP[XD|t1] ^ HEAP[X9|t2] ^ HEAP[XE|t3];

        // round 7
        t0 = HEAP[INV_SBOX|s0] ^ R70;
        t1 = HEAP[INV_SBOX|s1] ^ R71;
        t2 = HEAP[INV_SBOX|s2] ^ R72;
        t3 = HEAP[INV_SBOX|s3] ^ R73;
        t4 = HEAP[INV_SBOX|s4] ^ R74;
        t5 = HEAP[INV_SBOX|s5] ^ R75;
        t6 = HEAP[INV_SBOX|s6] ^ R76;
        t7 = HEAP[INV_SBOX|s7] ^ R77;
        t8 = HEAP[INV_SBOX|s8] ^ R78;
        t9 = HEAP[INV_SBOX|s9] ^ R79;
        tA = HEAP[INV_SBOX|sA] ^ R7A;
        tB = HEAP[INV_SBOX|sB] ^ R7B;
        tC = HEAP[INV_SBOX|sC] ^ R7C;
        tD = HEAP[INV_SBOX|sD] ^ R7D;
        tE = HEAP[INV_SBOX|sE] ^ R7E;
        tF = HEAP[INV_SBOX|sF] ^ R7F;
        s0 = HEAP[XE|t0] ^ HEAP[XB|t1] ^ HEAP[XD|t2] ^ HEAP[X9|t3];
        s1 = HEAP[X9|tC] ^ HEAP[XE|tD] ^ HEAP[XB|tE] ^ HEAP[XD|tF];
        s2 = HEAP[XD|t8] ^ HEAP[X9|t9] ^ HEAP[XE|tA] ^ HEAP[XB|tB];
        s3 = HEAP[XB|t4] ^ HEAP[XD|t5] ^ HEAP[X9|t6] ^ HEAP[XE|t7];
        s4 = HEAP[XE|t4] ^ HEAP[XB|t5] ^ HEAP[XD|t6] ^ HEAP[X9|t7];
        s5 = HEAP[X9|t0] ^ HEAP[XE|t1] ^ HEAP[XB|t2] ^ HEAP[XD|t3];
        s6 = HEAP[XD|tC] ^ HEAP[X9|tD] ^ HEAP[XE|tE] ^ HEAP[XB|tF];
        s7 = HEAP[XB|t8] ^ HEAP[XD|t9] ^ HEAP[X9|tA] ^ HEAP[XE|tB];
        s8 = HEAP[XE|t8] ^ HEAP[XB|t9] ^ HEAP[XD|tA] ^ HEAP[X9|tB];
        s9 = HEAP[X9|t4] ^ HEAP[XE|t5] ^ HEAP[XB|t6] ^ HEAP[XD|t7];
        sA = HEAP[XD|t0] ^ HEAP[X9|t1] ^ HEAP[XE|t2] ^ HEAP[XB|t3];
        sB = HEAP[XB|tC] ^ HEAP[XD|tD] ^ HEAP[X9|tE] ^ HEAP[XE|tF];
        sC = HEAP[XE|tC] ^ HEAP[XB|tD] ^ HEAP[XD|tE] ^ HEAP[X9|tF];
        sD = HEAP[X9|t8] ^ HEAP[XE|t9] ^ HEAP[XB|tA] ^ HEAP[XD|tB];
        sE = HEAP[XD|t4] ^ HEAP[X9|t5] ^ HEAP[XE|t6] ^ HEAP[XB|t7];
        sF = HEAP[XB|t0] ^ HEAP[XD|t1] ^ HEAP[X9|t2] ^ HEAP[XE|t3];

        // round 6
        t0 = HEAP[INV_SBOX|s0] ^ R60;
        t1 = HEAP[INV_SBOX|s1] ^ R61;
        t2 = HEAP[INV_SBOX|s2] ^ R62;
        t3 = HEAP[INV_SBOX|s3] ^ R63;
        t4 = HEAP[INV_SBOX|s4] ^ R64;
        t5 = HEAP[INV_SBOX|s5] ^ R65;
        t6 = HEAP[INV_SBOX|s6] ^ R66;
        t7 = HEAP[INV_SBOX|s7] ^ R67;
        t8 = HEAP[INV_SBOX|s8] ^ R68;
        t9 = HEAP[INV_SBOX|s9] ^ R69;
        tA = HEAP[INV_SBOX|sA] ^ R6A;
        tB = HEAP[INV_SBOX|sB] ^ R6B;
        tC = HEAP[INV_SBOX|sC] ^ R6C;
        tD = HEAP[INV_SBOX|sD] ^ R6D;
        tE = HEAP[INV_SBOX|sE] ^ R6E;
        tF = HEAP[INV_SBOX|sF] ^ R6F;
        s0 = HEAP[XE|t0] ^ HEAP[XB|t1] ^ HEAP[XD|t2] ^ HEAP[X9|t3];
        s1 = HEAP[X9|tC] ^ HEAP[XE|tD] ^ HEAP[XB|tE] ^ HEAP[XD|tF];
        s2 = HEAP[XD|t8] ^ HEAP[X9|t9] ^ HEAP[XE|tA] ^ HEAP[XB|tB];
        s3 = HEAP[XB|t4] ^ HEAP[XD|t5] ^ HEAP[X9|t6] ^ HEAP[XE|t7];
        s4 = HEAP[XE|t4] ^ HEAP[XB|t5] ^ HEAP[XD|t6] ^ HEAP[X9|t7];
        s5 = HEAP[X9|t0] ^ HEAP[XE|t1] ^ HEAP[XB|t2] ^ HEAP[XD|t3];
        s6 = HEAP[XD|tC] ^ HEAP[X9|tD] ^ HEAP[XE|tE] ^ HEAP[XB|tF];
        s7 = HEAP[XB|t8] ^ HEAP[XD|t9] ^ HEAP[X9|tA] ^ HEAP[XE|tB];
        s8 = HEAP[XE|t8] ^ HEAP[XB|t9] ^ HEAP[XD|tA] ^ HEAP[X9|tB];
        s9 = HEAP[X9|t4] ^ HEAP[XE|t5] ^ HEAP[XB|t6] ^ HEAP[XD|t7];
        sA = HEAP[XD|t0] ^ HEAP[X9|t1] ^ HEAP[XE|t2] ^ HEAP[XB|t3];
        sB = HEAP[XB|tC] ^ HEAP[XD|tD] ^ HEAP[X9|tE] ^ HEAP[XE|tF];
        sC = HEAP[XE|tC] ^ HEAP[XB|tD] ^ HEAP[XD|tE] ^ HEAP[X9|tF];
        sD = HEAP[X9|t8] ^ HEAP[XE|t9] ^ HEAP[XB|tA] ^ HEAP[XD|tB];
        sE = HEAP[XD|t4] ^ HEAP[X9|t5] ^ HEAP[XE|t6] ^ HEAP[XB|t7];
        sF = HEAP[XB|t0] ^ HEAP[XD|t1] ^ HEAP[X9|t2] ^ HEAP[XE|t3];

        // round 5
        t0 = HEAP[INV_SBOX|s0] ^ R50;
        t1 = HEAP[INV_SBOX|s1] ^ R51;
        t2 = HEAP[INV_SBOX|s2] ^ R52;
        t3 = HEAP[INV_SBOX|s3] ^ R53;
        t4 = HEAP[INV_SBOX|s4] ^ R54;
        t5 = HEAP[INV_SBOX|s5] ^ R55;
        t6 = HEAP[INV_SBOX|s6] ^ R56;
        t7 = HEAP[INV_SBOX|s7] ^ R57;
        t8 = HEAP[INV_SBOX|s8] ^ R58;
        t9 = HEAP[INV_SBOX|s9] ^ R59;
        tA = HEAP[INV_SBOX|sA] ^ R5A;
        tB = HEAP[INV_SBOX|sB] ^ R5B;
        tC = HEAP[INV_SBOX|sC] ^ R5C;
        tD = HEAP[INV_SBOX|sD] ^ R5D;
        tE = HEAP[INV_SBOX|sE] ^ R5E;
        tF = HEAP[INV_SBOX|sF] ^ R5F;
        s0 = HEAP[XE|t0] ^ HEAP[XB|t1] ^ HEAP[XD|t2] ^ HEAP[X9|t3];
        s1 = HEAP[X9|tC] ^ HEAP[XE|tD] ^ HEAP[XB|tE] ^ HEAP[XD|tF];
        s2 = HEAP[XD|t8] ^ HEAP[X9|t9] ^ HEAP[XE|tA] ^ HEAP[XB|tB];
        s3 = HEAP[XB|t4] ^ HEAP[XD|t5] ^ HEAP[X9|t6] ^ HEAP[XE|t7];
        s4 = HEAP[XE|t4] ^ HEAP[XB|t5] ^ HEAP[XD|t6] ^ HEAP[X9|t7];
        s5 = HEAP[X9|t0] ^ HEAP[XE|t1] ^ HEAP[XB|t2] ^ HEAP[XD|t3];
        s6 = HEAP[XD|tC] ^ HEAP[X9|tD] ^ HEAP[XE|tE] ^ HEAP[XB|tF];
        s7 = HEAP[XB|t8] ^ HEAP[XD|t9] ^ HEAP[X9|tA] ^ HEAP[XE|tB];
        s8 = HEAP[XE|t8] ^ HEAP[XB|t9] ^ HEAP[XD|tA] ^ HEAP[X9|tB];
        s9 = HEAP[X9|t4] ^ HEAP[XE|t5] ^ HEAP[XB|t6] ^ HEAP[XD|t7];
        sA = HEAP[XD|t0] ^ HEAP[X9|t1] ^ HEAP[XE|t2] ^ HEAP[XB|t3];
        sB = HEAP[XB|tC] ^ HEAP[XD|tD] ^ HEAP[X9|tE] ^ HEAP[XE|tF];
        sC = HEAP[XE|tC] ^ HEAP[XB|tD] ^ HEAP[XD|tE] ^ HEAP[X9|tF];
        sD = HEAP[X9|t8] ^ HEAP[XE|t9] ^ HEAP[XB|tA] ^ HEAP[XD|tB];
        sE = HEAP[XD|t4] ^ HEAP[X9|t5] ^ HEAP[XE|t6] ^ HEAP[XB|t7];
        sF = HEAP[XB|t0] ^ HEAP[XD|t1] ^ HEAP[X9|t2] ^ HEAP[XE|t3];

        // round 4
        t0 = HEAP[INV_SBOX|s0] ^ R40;
        t1 = HEAP[INV_SBOX|s1] ^ R41;
        t2 = HEAP[INV_SBOX|s2] ^ R42;
        t3 = HEAP[INV_SBOX|s3] ^ R43;
        t4 = HEAP[INV_SBOX|s4] ^ R44;
        t5 = HEAP[INV_SBOX|s5] ^ R45;
        t6 = HEAP[INV_SBOX|s6] ^ R46;
        t7 = HEAP[INV_SBOX|s7] ^ R47;
        t8 = HEAP[INV_SBOX|s8] ^ R48;
        t9 = HEAP[INV_SBOX|s9] ^ R49;
        tA = HEAP[INV_SBOX|sA] ^ R4A;
        tB = HEAP[INV_SBOX|sB] ^ R4B;
        tC = HEAP[INV_SBOX|sC] ^ R4C;
        tD = HEAP[INV_SBOX|sD] ^ R4D;
        tE = HEAP[INV_SBOX|sE] ^ R4E;
        tF = HEAP[INV_SBOX|sF] ^ R4F;
        s0 = HEAP[XE|t0] ^ HEAP[XB|t1] ^ HEAP[XD|t2] ^ HEAP[X9|t3];
        s1 = HEAP[X9|tC] ^ HEAP[XE|tD] ^ HEAP[XB|tE] ^ HEAP[XD|tF];
        s2 = HEAP[XD|t8] ^ HEAP[X9|t9] ^ HEAP[XE|tA] ^ HEAP[XB|tB];
        s3 = HEAP[XB|t4] ^ HEAP[XD|t5] ^ HEAP[X9|t6] ^ HEAP[XE|t7];
        s4 = HEAP[XE|t4] ^ HEAP[XB|t5] ^ HEAP[XD|t6] ^ HEAP[X9|t7];
        s5 = HEAP[X9|t0] ^ HEAP[XE|t1] ^ HEAP[XB|t2] ^ HEAP[XD|t3];
        s6 = HEAP[XD|tC] ^ HEAP[X9|tD] ^ HEAP[XE|tE] ^ HEAP[XB|tF];
        s7 = HEAP[XB|t8] ^ HEAP[XD|t9] ^ HEAP[X9|tA] ^ HEAP[XE|tB];
        s8 = HEAP[XE|t8] ^ HEAP[XB|t9] ^ HEAP[XD|tA] ^ HEAP[X9|tB];
        s9 = HEAP[X9|t4] ^ HEAP[XE|t5] ^ HEAP[XB|t6] ^ HEAP[XD|t7];
        sA = HEAP[XD|t0] ^ HEAP[X9|t1] ^ HEAP[XE|t2] ^ HEAP[XB|t3];
        sB = HEAP[XB|tC] ^ HEAP[XD|tD] ^ HEAP[X9|tE] ^ HEAP[XE|tF];
        sC = HEAP[XE|tC] ^ HEAP[XB|tD] ^ HEAP[XD|tE] ^ HEAP[X9|tF];
        sD = HEAP[X9|t8] ^ HEAP[XE|t9] ^ HEAP[XB|tA] ^ HEAP[XD|tB];
        sE = HEAP[XD|t4] ^ HEAP[X9|t5] ^ HEAP[XE|t6] ^ HEAP[XB|t7];
        sF = HEAP[XB|t0] ^ HEAP[XD|t1] ^ HEAP[X9|t2] ^ HEAP[XE|t3];

        // round 3
        t0 = HEAP[INV_SBOX|s0] ^ R30;
        t1 = HEAP[INV_SBOX|s1] ^ R31;
        t2 = HEAP[INV_SBOX|s2] ^ R32;
        t3 = HEAP[INV_SBOX|s3] ^ R33;
        t4 = HEAP[INV_SBOX|s4] ^ R34;
        t5 = HEAP[INV_SBOX|s5] ^ R35;
        t6 = HEAP[INV_SBOX|s6] ^ R36;
        t7 = HEAP[INV_SBOX|s7] ^ R37;
        t8 = HEAP[INV_SBOX|s8] ^ R38;
        t9 = HEAP[INV_SBOX|s9] ^ R39;
        tA = HEAP[INV_SBOX|sA] ^ R3A;
        tB = HEAP[INV_SBOX|sB] ^ R3B;
        tC = HEAP[INV_SBOX|sC] ^ R3C;
        tD = HEAP[INV_SBOX|sD] ^ R3D;
        tE = HEAP[INV_SBOX|sE] ^ R3E;
        tF = HEAP[INV_SBOX|sF] ^ R3F;
        s0 = HEAP[XE|t0] ^ HEAP[XB|t1] ^ HEAP[XD|t2] ^ HEAP[X9|t3];
        s1 = HEAP[X9|tC] ^ HEAP[XE|tD] ^ HEAP[XB|tE] ^ HEAP[XD|tF];
        s2 = HEAP[XD|t8] ^ HEAP[X9|t9] ^ HEAP[XE|tA] ^ HEAP[XB|tB];
        s3 = HEAP[XB|t4] ^ HEAP[XD|t5] ^ HEAP[X9|t6] ^ HEAP[XE|t7];
        s4 = HEAP[XE|t4] ^ HEAP[XB|t5] ^ HEAP[XD|t6] ^ HEAP[X9|t7];
        s5 = HEAP[X9|t0] ^ HEAP[XE|t1] ^ HEAP[XB|t2] ^ HEAP[XD|t3];
        s6 = HEAP[XD|tC] ^ HEAP[X9|tD] ^ HEAP[XE|tE] ^ HEAP[XB|tF];
        s7 = HEAP[XB|t8] ^ HEAP[XD|t9] ^ HEAP[X9|tA] ^ HEAP[XE|tB];
        s8 = HEAP[XE|t8] ^ HEAP[XB|t9] ^ HEAP[XD|tA] ^ HEAP[X9|tB];
        s9 = HEAP[X9|t4] ^ HEAP[XE|t5] ^ HEAP[XB|t6] ^ HEAP[XD|t7];
        sA = HEAP[XD|t0] ^ HEAP[X9|t1] ^ HEAP[XE|t2] ^ HEAP[XB|t3];
        sB = HEAP[XB|tC] ^ HEAP[XD|tD] ^ HEAP[X9|tE] ^ HEAP[XE|tF];
        sC = HEAP[XE|tC] ^ HEAP[XB|tD] ^ HEAP[XD|tE] ^ HEAP[X9|tF];
        sD = HEAP[X9|t8] ^ HEAP[XE|t9] ^ HEAP[XB|tA] ^ HEAP[XD|tB];
        sE = HEAP[XD|t4] ^ HEAP[X9|t5] ^ HEAP[XE|t6] ^ HEAP[XB|t7];
        sF = HEAP[XB|t0] ^ HEAP[XD|t1] ^ HEAP[X9|t2] ^ HEAP[XE|t3];

        // round 2
        t0 = HEAP[INV_SBOX|s0] ^ R20;
        t1 = HEAP[INV_SBOX|s1] ^ R21;
        t2 = HEAP[INV_SBOX|s2] ^ R22;
        t3 = HEAP[INV_SBOX|s3] ^ R23;
        t4 = HEAP[INV_SBOX|s4] ^ R24;
        t5 = HEAP[INV_SBOX|s5] ^ R25;
        t6 = HEAP[INV_SBOX|s6] ^ R26;
        t7 = HEAP[INV_SBOX|s7] ^ R27;
        t8 = HEAP[INV_SBOX|s8] ^ R28;
        t9 = HEAP[INV_SBOX|s9] ^ R29;
        tA = HEAP[INV_SBOX|sA] ^ R2A;
        tB = HEAP[INV_SBOX|sB] ^ R2B;
        tC = HEAP[INV_SBOX|sC] ^ R2C;
        tD = HEAP[INV_SBOX|sD] ^ R2D;
        tE = HEAP[INV_SBOX|sE] ^ R2E;
        tF = HEAP[INV_SBOX|sF] ^ R2F;
        s0 = HEAP[XE|t0] ^ HEAP[XB|t1] ^ HEAP[XD|t2] ^ HEAP[X9|t3];
        s1 = HEAP[X9|tC] ^ HEAP[XE|tD] ^ HEAP[XB|tE] ^ HEAP[XD|tF];
        s2 = HEAP[XD|t8] ^ HEAP[X9|t9] ^ HEAP[XE|tA] ^ HEAP[XB|tB];
        s3 = HEAP[XB|t4] ^ HEAP[XD|t5] ^ HEAP[X9|t6] ^ HEAP[XE|t7];
        s4 = HEAP[XE|t4] ^ HEAP[XB|t5] ^ HEAP[XD|t6] ^ HEAP[X9|t7];
        s5 = HEAP[X9|t0] ^ HEAP[XE|t1] ^ HEAP[XB|t2] ^ HEAP[XD|t3];
        s6 = HEAP[XD|tC] ^ HEAP[X9|tD] ^ HEAP[XE|tE] ^ HEAP[XB|tF];
        s7 = HEAP[XB|t8] ^ HEAP[XD|t9] ^ HEAP[X9|tA] ^ HEAP[XE|tB];
        s8 = HEAP[XE|t8] ^ HEAP[XB|t9] ^ HEAP[XD|tA] ^ HEAP[X9|tB];
        s9 = HEAP[X9|t4] ^ HEAP[XE|t5] ^ HEAP[XB|t6] ^ HEAP[XD|t7];
        sA = HEAP[XD|t0] ^ HEAP[X9|t1] ^ HEAP[XE|t2] ^ HEAP[XB|t3];
        sB = HEAP[XB|tC] ^ HEAP[XD|tD] ^ HEAP[X9|tE] ^ HEAP[XE|tF];
        sC = HEAP[XE|tC] ^ HEAP[XB|tD] ^ HEAP[XD|tE] ^ HEAP[X9|tF];
        sD = HEAP[X9|t8] ^ HEAP[XE|t9] ^ HEAP[XB|tA] ^ HEAP[XD|tB];
        sE = HEAP[XD|t4] ^ HEAP[X9|t5] ^ HEAP[XE|t6] ^ HEAP[XB|t7];
        sF = HEAP[XB|t0] ^ HEAP[XD|t1] ^ HEAP[X9|t2] ^ HEAP[XE|t3];

        // round 1
        t0 = HEAP[INV_SBOX|s0] ^ R10;
        t1 = HEAP[INV_SBOX|s1] ^ R11;
        t2 = HEAP[INV_SBOX|s2] ^ R12;
        t3 = HEAP[INV_SBOX|s3] ^ R13;
        t4 = HEAP[INV_SBOX|s4] ^ R14;
        t5 = HEAP[INV_SBOX|s5] ^ R15;
        t6 = HEAP[INV_SBOX|s6] ^ R16;
        t7 = HEAP[INV_SBOX|s7] ^ R17;
        t8 = HEAP[INV_SBOX|s8] ^ R18;
        t9 = HEAP[INV_SBOX|s9] ^ R19;
        tA = HEAP[INV_SBOX|sA] ^ R1A;
        tB = HEAP[INV_SBOX|sB] ^ R1B;
        tC = HEAP[INV_SBOX|sC] ^ R1C;
        tD = HEAP[INV_SBOX|sD] ^ R1D;
        tE = HEAP[INV_SBOX|sE] ^ R1E;
        tF = HEAP[INV_SBOX|sF] ^ R1F;
        s0 = HEAP[XE|t0] ^ HEAP[XB|t1] ^ HEAP[XD|t2] ^ HEAP[X9|t3];
        s1 = HEAP[X9|tC] ^ HEAP[XE|tD] ^ HEAP[XB|tE] ^ HEAP[XD|tF];
        s2 = HEAP[XD|t8] ^ HEAP[X9|t9] ^ HEAP[XE|tA] ^ HEAP[XB|tB];
        s3 = HEAP[XB|t4] ^ HEAP[XD|t5] ^ HEAP[X9|t6] ^ HEAP[XE|t7];
        s4 = HEAP[XE|t4] ^ HEAP[XB|t5] ^ HEAP[XD|t6] ^ HEAP[X9|t7];
        s5 = HEAP[X9|t0] ^ HEAP[XE|t1] ^ HEAP[XB|t2] ^ HEAP[XD|t3];
        s6 = HEAP[XD|tC] ^ HEAP[X9|tD] ^ HEAP[XE|tE] ^ HEAP[XB|tF];
        s7 = HEAP[XB|t8] ^ HEAP[XD|t9] ^ HEAP[X9|tA] ^ HEAP[XE|tB];
        s8 = HEAP[XE|t8] ^ HEAP[XB|t9] ^ HEAP[XD|tA] ^ HEAP[X9|tB];
        s9 = HEAP[X9|t4] ^ HEAP[XE|t5] ^ HEAP[XB|t6] ^ HEAP[XD|t7];
        sA = HEAP[XD|t0] ^ HEAP[X9|t1] ^ HEAP[XE|t2] ^ HEAP[XB|t3];
        sB = HEAP[XB|tC] ^ HEAP[XD|tD] ^ HEAP[X9|tE] ^ HEAP[XE|tF];
        sC = HEAP[XE|tC] ^ HEAP[XB|tD] ^ HEAP[XD|tE] ^ HEAP[X9|tF];
        sD = HEAP[X9|t8] ^ HEAP[XE|t9] ^ HEAP[XB|tA] ^ HEAP[XD|tB];
        sE = HEAP[XD|t4] ^ HEAP[X9|t5] ^ HEAP[XE|t6] ^ HEAP[XB|t7];
        sF = HEAP[XB|t0] ^ HEAP[XD|t1] ^ HEAP[X9|t2] ^ HEAP[XE|t3];

        // round 0
        S0 = HEAP[INV_SBOX|s0] ^ R00;
        S1 = HEAP[INV_SBOX|s1] ^ R01;
        S2 = HEAP[INV_SBOX|s2] ^ R02;
        S3 = HEAP[INV_SBOX|s3] ^ R03;
        S4 = HEAP[INV_SBOX|s4] ^ R04;
        S5 = HEAP[INV_SBOX|s5] ^ R05;
        S6 = HEAP[INV_SBOX|s6] ^ R06;
        S7 = HEAP[INV_SBOX|s7] ^ R07;
        S8 = HEAP[INV_SBOX|s8] ^ R08;
        S9 = HEAP[INV_SBOX|s9] ^ R09;
        SA = HEAP[INV_SBOX|sA] ^ R0A;
        SB = HEAP[INV_SBOX|sB] ^ R0B;
        SC = HEAP[INV_SBOX|sC] ^ R0C;
        SD = HEAP[INV_SBOX|sD] ^ R0D;
        SE = HEAP[INV_SBOX|sE] ^ R0E;
        SF = HEAP[INV_SBOX|sF] ^ R0F;
    }

    function init_state ( s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, sA, sB, sC, sD, sE, sF ) {
        s0 = s0|0;
        s1 = s1|0;
        s2 = s2|0;
        s3 = s3|0;
        s4 = s4|0;
        s5 = s5|0;
        s6 = s6|0;
        s7 = s7|0;
        s8 = s8|0;
        s9 = s9|0;
        sA = sA|0;
        sB = sB|0;
        sC = sC|0;
        sD = sD|0;
        sE = sE|0;
        sF = sF|0;

        S0 = s0;
        S1 = s1;
        S2 = s2;
        S3 = s3;
        S4 = s4;
        S5 = s5;
        S6 = s6;
        S7 = s7;
        S8 = s8;
        S9 = s9;
        SA = sA;
        SB = sB;
        SC = sC;
        SD = sD;
        SE = sE;
        SF = sF;
    }

    // offset — multiple of 16
    function save_state ( offset ) {
        offset = offset|0;

        HEAP[offset] = S0;
        HEAP[offset|1] = S1;
        HEAP[offset|2] = S2;
        HEAP[offset|3] = S3;
        HEAP[offset|4] = S4;
        HEAP[offset|5] = S5;
        HEAP[offset|6] = S6;
        HEAP[offset|7] = S7;
        HEAP[offset|8] = S8;
        HEAP[offset|9] = S9;
        HEAP[offset|10] = SA;
        HEAP[offset|11] = SB;
        HEAP[offset|12] = SC;
        HEAP[offset|13] = SD;
        HEAP[offset|14] = SE;
        HEAP[offset|15] = SF;
    }

    function init_key_128 ( k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, kA, kB, kC, kD, kE, kF ) {
        k0 = k0|0;
        k1 = k1|0;
        k2 = k2|0;
        k3 = k3|0;
        k4 = k4|0;
        k5 = k5|0;
        k6 = k6|0;
        k7 = k7|0;
        k8 = k8|0;
        k9 = k9|0;
        kA = kA|0;
        kB = kB|0;
        kC = kC|0;
        kD = kD|0;
        kE = kE|0;
        kF = kF|0;

        R00 = k0;
        R01 = k1;
        R02 = k2;
        R03 = k3;
        R04 = k4;
        R05 = k5;
        R06 = k6;
        R07 = k7;
        R08 = k8;
        R09 = k9;
        R0A = kA;
        R0B = kB;
        R0C = kC;
        R0D = kD;
        R0E = kE;
        R0F = kF;

        _expand_key_128();
    }

    // offset, length — multiple of 16
    function cbc_encrypt ( offset, length ) {
        offset = offset|0;
        length = length|0;

        if ( (offset & 15) | (length & 15 ) )
            return -1;

        while ( (length|0) > 0 ) {
            _encrypt_128(
                S0 ^ HEAP[offset],
                S1 ^ HEAP[offset|1],
                S2 ^ HEAP[offset|2],
                S3 ^ HEAP[offset|3],
                S4 ^ HEAP[offset|4],
                S5 ^ HEAP[offset|5],
                S6 ^ HEAP[offset|6],
                S7 ^ HEAP[offset|7],
                S8 ^ HEAP[offset|8],
                S9 ^ HEAP[offset|9],
                SA ^ HEAP[offset|10],
                SB ^ HEAP[offset|11],
                SC ^ HEAP[offset|12],
                SD ^ HEAP[offset|13],
                SE ^ HEAP[offset|14],
                SF ^ HEAP[offset|15]
            );

            HEAP[offset] = S0;
            HEAP[offset|1] = S1;
            HEAP[offset|2] = S2;
            HEAP[offset|3] = S3;
            HEAP[offset|4] = S4;
            HEAP[offset|5] = S5;
            HEAP[offset|6] = S6;
            HEAP[offset|7] = S7;
            HEAP[offset|8] = S8;
            HEAP[offset|9] = S9;
            HEAP[offset|10] = SA;
            HEAP[offset|11] = SB;
            HEAP[offset|12] = SC;
            HEAP[offset|13] = SD;
            HEAP[offset|14] = SE;
            HEAP[offset|15] = SF;

            offset = (offset + 16)|0;
            length = (length - 16)|0;
        }
    }

    // offset, length — multiple of 16
    function cbc_decrypt ( offset, length ) {
        offset = offset|0;
        length = length|0;

        var iv0 = 0, iv1 = 0, iv2 = 0, iv3 = 0, iv4 = 0, iv5 = 0, iv6 = 0, iv7 = 0, iv8 = 0, iv9 = 0, ivA = 0, ivB = 0, ivC = 0, ivD = 0, ivE = 0, ivF = 0;

        if ( (offset & 15) | (length & 15 ) )
            return -1;

        iv0 = S0; iv1 = S1; iv2 = S2; iv3 = S3; iv4 = S4; iv5 = S5; iv6 = S6; iv7 = S7; iv8 = S8; iv9 = S9; ivA = SA; ivB = SB; ivC = SC; ivD = SD; ivE = SE; ivF = SF;

        while ( (length|0) > 0 ) {
            _decrypt_128(
                HEAP[offset]|0,
                HEAP[offset|1]|0,
                HEAP[offset|2]|0,
                HEAP[offset|3]|0,
                HEAP[offset|4]|0,
                HEAP[offset|5]|0,
                HEAP[offset|6]|0,
                HEAP[offset|7]|0,
                HEAP[offset|8]|0,
                HEAP[offset|9]|0,
                HEAP[offset|10]|0,
                HEAP[offset|11]|0,
                HEAP[offset|12]|0,
                HEAP[offset|13]|0,
                HEAP[offset|14]|0,
                HEAP[offset|15]|0
            );

            S0 = S0 ^ iv0; iv0 = HEAP[offset]|0;
            S1 = S1 ^ iv1; iv1 = HEAP[offset|1]|0;
            S2 = S2 ^ iv2; iv2 = HEAP[offset|2]|0;
            S3 = S3 ^ iv3; iv3 = HEAP[offset|3]|0;
            S4 = S4 ^ iv4; iv4 = HEAP[offset|4]|0;
            S5 = S5 ^ iv5; iv5 = HEAP[offset|5]|0;
            S6 = S6 ^ iv6; iv6 = HEAP[offset|6]|0;
            S7 = S7 ^ iv7; iv7 = HEAP[offset|7]|0;
            S8 = S8 ^ iv8; iv8 = HEAP[offset|8]|0;
            S9 = S9 ^ iv9; iv9 = HEAP[offset|9]|0;
            SA = SA ^ ivA; ivA = HEAP[offset|10]|0;
            SB = SB ^ ivB; ivB = HEAP[offset|11]|0;
            SC = SC ^ ivC; ivC = HEAP[offset|12]|0;
            SD = SD ^ ivD; ivD = HEAP[offset|13]|0;
            SE = SE ^ ivE; ivE = HEAP[offset|14]|0;
            SF = SF ^ ivF; ivF = HEAP[offset|15]|0;

            HEAP[offset] = S0;
            HEAP[offset|1] = S1;
            HEAP[offset|2] = S2;
            HEAP[offset|3] = S3;
            HEAP[offset|4] = S4;
            HEAP[offset|5] = S5;
            HEAP[offset|6] = S6;
            HEAP[offset|7] = S7;
            HEAP[offset|8] = S8;
            HEAP[offset|9] = S9;
            HEAP[offset|10] = SA;
            HEAP[offset|11] = SB;
            HEAP[offset|12] = SC;
            HEAP[offset|13] = SD;
            HEAP[offset|14] = SE;
            HEAP[offset|15] = SF;

            offset = (offset + 16)|0;
            length = (length - 16)|0;
        }

        S0 = iv0; S1 = iv1; S2 = iv2; S3 = iv3; S4 = iv4; S5 = iv5; S6 = iv6; S7 = iv7; S8 = iv8; S9 = iv9; SA = ivA; SB = ivB; SC = ivC; SD = ivD; SE = ivE; SF = ivF;
    }

    // offset, length, output — multiple of 16
    function cbc_mac ( offset, length, output ) {
        offset = offset|0;
        length = length|0;
        output = output|0;

        if ( offset & 15 )
            return -1;

        if ( ~output )
            if ( output & 31 )
                return -1;

        while ( (length|0) >= 16 ) {
            _encrypt_128(
                S0 ^ HEAP[offset],
                S1 ^ HEAP[offset|1],
                S2 ^ HEAP[offset|2],
                S3 ^ HEAP[offset|3],
                S4 ^ HEAP[offset|4],
                S5 ^ HEAP[offset|5],
                S6 ^ HEAP[offset|6],
                S7 ^ HEAP[offset|7],
                S8 ^ HEAP[offset|8],
                S9 ^ HEAP[offset|9],
                SA ^ HEAP[offset|10],
                SB ^ HEAP[offset|11],
                SC ^ HEAP[offset|12],
                SD ^ HEAP[offset|13],
                SE ^ HEAP[offset|14],
                SF ^ HEAP[offset|15]
            );

            offset = (offset + 16)|0;
            length = (length - 16)|0;
        }
        if ( (length|0) > 0 ) {
            S0 = S0 ^ HEAP[offset];
            if ( (length|0) > 1 ) S1 = S1 ^ HEAP[offset|1];
            if ( (length|0) > 2 ) S2 = S2 ^ HEAP[offset|2];
            if ( (length|0) > 3 ) S3 = S3 ^ HEAP[offset|3];
            if ( (length|0) > 4 ) S4 = S4 ^ HEAP[offset|4];
            if ( (length|0) > 5 ) S5 = S5 ^ HEAP[offset|5];
            if ( (length|0) > 6 ) S6 = S6 ^ HEAP[offset|6];
            if ( (length|0) > 7 ) S7 = S7 ^ HEAP[offset|7];
            if ( (length|0) > 8 ) S8 = S8 ^ HEAP[offset|8];
            if ( (length|0) > 9 ) S9 = S9 ^ HEAP[offset|9];
            if ( (length|0) > 10 ) SA = SA ^ HEAP[offset|10];
            if ( (length|0) > 11 ) SB = SB ^ HEAP[offset|11];
            if ( (length|0) > 12 ) SC = SC ^ HEAP[offset|12];
            if ( (length|0) > 13 ) SD = SD ^ HEAP[offset|13];
            if ( (length|0) > 14 ) SE = SE ^ HEAP[offset|14];

            _encrypt_128( S0, S1, S2, S3, S4, S5, S6, S7, S8, S9, SA, SB, SC, SD, SE, SF );

            offset = (offset + length)|0;
            length = 0;
        }

        if ( ~output ) {
            HEAP[output|0] = S0;
            HEAP[output|1] = S1;
            HEAP[output|2] = S2;
            HEAP[output|3] = S3;
            HEAP[output|4] = S4;
            HEAP[output|5] = S5;
            HEAP[output|6] = S6;
            HEAP[output|7] = S7;
            HEAP[output|8] = S8;
            HEAP[output|9] = S9;
            HEAP[output|10] = SA;
            HEAP[output|11] = SB;
            HEAP[output|12] = SC;
            HEAP[output|13] = SD;
            HEAP[output|14] = SE;
            HEAP[output|15] = SF;
        }
    }

    // offset, length, output — multiple of 16
    function ccm_encrypt ( offset, length, nonce0, nonce1, nonce2, nonce3, nonce4, nonce5, nonce6, nonce7, nonce8, nonce9, nonceA, nonceB, nonceC, nonceD, counter ) {
        offset = offset|0;
        length = length|0;
        nonce0 = nonce0|0;
        nonce1 = nonce1|0;
        nonce2 = nonce2|0;
        nonce3 = nonce3|0;
        nonce4 = nonce4|0;
        nonce5 = nonce5|0;
        nonce6 = nonce6|0;
        nonce7 = nonce7|0;
        nonce8 = nonce8|0;
        nonce9 = nonce9|0;
        nonceA = nonceA|0;
        nonceB = nonceB|0;
        nonceC = nonceC|0;
        nonceD = nonceD|0;
        counter = counter|0;

        var iv0 = 0, iv1 = 0, iv2 = 0, iv3 = 0, iv4 = 0, iv5 = 0, iv6 = 0, iv7 = 0, iv8 = 0, iv9 = 0, ivA = 0, ivB = 0, ivC = 0, ivD = 0, ivE = 0, ivF = 0,
            s0 = 0, s1 = 0, s2 = 0, s3 = 0, s4 = 0, s5 = 0, s6 = 0, s7 = 0, s8 = 0, s9 = 0, sA = 0, sB = 0, sC = 0, sD = 0, sE = 0, sF = 0;

        if ( offset & 15 )
            return -1;

        iv0 = S0, iv1 = S1, iv2 = S2, iv3 = S3, iv4 = S4, iv5 = S5, iv6 = S6, iv7 = S7, iv8 = S8, iv9 = S9, ivA = SA, ivB = SB, ivC = SC, ivD = SD, ivE = SE, ivF = SF;

        while ( (length|0) >= 16 ) {
            s0 = HEAP[offset]|0;
            s1 = HEAP[offset|1]|0;
            s2 = HEAP[offset|2]|0;
            s3 = HEAP[offset|3]|0;
            s4 = HEAP[offset|4]|0;
            s5 = HEAP[offset|5]|0;
            s6 = HEAP[offset|6]|0;
            s7 = HEAP[offset|7]|0;
            s8 = HEAP[offset|8]|0;
            s9 = HEAP[offset|9]|0;
            sA = HEAP[offset|10]|0;
            sB = HEAP[offset|11]|0;
            sC = HEAP[offset|12]|0;
            sD = HEAP[offset|13]|0;
            sE = HEAP[offset|14]|0;
            sF = HEAP[offset|15]|0;

            //
            // Cipher
            //

            _encrypt_128(
                nonce0,
                nonce1,
                nonce2,
                nonce3,
                nonce4,
                nonce5,
                nonce6,
                nonce7,
                nonce8,
                nonce9,
                nonceA,
                nonceB,
                nonceC ^ (counter>>>24),
                nonceD ^ (counter>>>16&255),
                counter>>>8&255,
                counter&255
            );

            HEAP[offset] = s0 ^ S0;
            HEAP[offset|1] = s1 ^ S1;
            HEAP[offset|2] = s2 ^ S2;
            HEAP[offset|3] = s3 ^ S3;
            HEAP[offset|4] = s4 ^ S4;
            HEAP[offset|5] = s5 ^ S5;
            HEAP[offset|6] = s6 ^ S6;
            HEAP[offset|7] = s7 ^ S7;
            HEAP[offset|8] = s8 ^ S8;
            HEAP[offset|9] = s9 ^ S9;
            HEAP[offset|10] = sA ^ SA;
            HEAP[offset|11] = sB ^ SB;
            HEAP[offset|12] = sC ^ SC;
            HEAP[offset|13] = sD ^ SD;
            HEAP[offset|14] = sE ^ SE;
            HEAP[offset|15] = sF ^ SF;

            //
            // MAC
            //

            _encrypt_128(
                s0 ^ iv0,
                s1 ^ iv1,
                s2 ^ iv2,
                s3 ^ iv3,
                s4 ^ iv4,
                s5 ^ iv5,
                s6 ^ iv6,
                s7 ^ iv7,
                s8 ^ iv8,
                s9 ^ iv9,
                sA ^ ivA,
                sB ^ ivB,
                sC ^ ivC,
                sD ^ ivD,
                sE ^ ivE,
                sF ^ ivF
            );

            iv0 = S0, iv1 = S1, iv2 = S2, iv3 = S3, iv4 = S4, iv5 = S5, iv6 = S6, iv7 = S7, iv8 = S8, iv9 = S9, ivA = SA, ivB = SB, ivC = SC, ivD = SD, ivE = SE, ivF = SF;

            offset = (offset + 16)|0;
            length = (length - 16)|0;
            counter = (counter + 1)|0;
        }
        if ( (length|0) > 0 ) {
            s0 = HEAP[offset]|0;
            s1 = (length|0) > 1 ? HEAP[offset|1]|0 : 0;
            s2 = (length|0) > 2 ? HEAP[offset|2]|0 : 0;
            s3 = (length|0) > 3 ? HEAP[offset|3]|0 : 0;
            s4 = (length|0) > 4 ? HEAP[offset|4]|0 : 0;
            s5 = (length|0) > 5 ? HEAP[offset|5]|0 : 0;
            s6 = (length|0) > 6 ? HEAP[offset|6]|0 : 0;
            s7 = (length|0) > 7 ? HEAP[offset|7]|0 : 0;
            s8 = (length|0) > 8 ? HEAP[offset|8]|0 : 0;
            s9 = (length|0) > 9 ? HEAP[offset|9]|0 : 0;
            sA = (length|0) > 10 ? HEAP[offset|10]|0 : 0;
            sB = (length|0) > 11 ? HEAP[offset|11]|0 : 0;
            sC = (length|0) > 12 ? HEAP[offset|12]|0 : 0;
            sD = (length|0) > 13 ? HEAP[offset|13]|0 : 0;
            sE = (length|0) > 14 ? HEAP[offset|14]|0 : 0;
            //sF = 0;

            //
            // Cipher
            //

            _encrypt_128(
                nonce0,
                nonce1,
                nonce2,
                nonce3,
                nonce4,
                nonce5,
                nonce6,
                nonce7,
                nonce8,
                nonce9,
                nonceA,
                nonceB,
                nonceC ^ (counter>>>24),
                nonceD ^ (counter>>>16&255),
                counter>>>8&255,
                counter&255
            );

            HEAP[offset] = s0 ^ S0;
            if ( (length|0) > 1 ) HEAP[offset|1] = s1 ^ S1;
            if ( (length|0) > 2 ) HEAP[offset|2] = s2 ^ S2;
            if ( (length|0) > 3 ) HEAP[offset|3] = s3 ^ S3;
            if ( (length|0) > 4 ) HEAP[offset|4] = s4 ^ S4;
            if ( (length|0) > 5 ) HEAP[offset|5] = s5 ^ S5;
            if ( (length|0) > 6 ) HEAP[offset|6] = s6 ^ S6;
            if ( (length|0) > 7 ) HEAP[offset|7] = s7 ^ S7;
            if ( (length|0) > 8 ) HEAP[offset|8] = s8 ^ S8;
            if ( (length|0) > 9 ) HEAP[offset|9] = s9 ^ S9;
            if ( (length|0) > 10 ) HEAP[offset|10] = sA ^ SA;
            if ( (length|0) > 11 ) HEAP[offset|11] = sB ^ SB;
            if ( (length|0) > 12 ) HEAP[offset|12] = sC ^ SC;
            if ( (length|0) > 13 ) HEAP[offset|13] = sD ^ SD;
            if ( (length|0) > 14 ) HEAP[offset|14] = sE ^ SE;
            //if ( 0 ) HEAP[offset|15] = sF ^ SF;

            //
            // MAC
            //

            _encrypt_128(
                s0 ^ iv0,
                s1 ^ iv1,
                s2 ^ iv2,
                s3 ^ iv3,
                s4 ^ iv4,
                s5 ^ iv5,
                s6 ^ iv6,
                s7 ^ iv7,
                s8 ^ iv8,
                s9 ^ iv9,
                sA ^ ivA,
                sB ^ ivB,
                sC ^ ivC,
                sD ^ ivD,
                sE ^ ivE,
                ivF // sF = 0
            );

            iv0 = S0, iv1 = S1, iv2 = S2, iv3 = S3, iv4 = S4, iv5 = S5, iv6 = S6, iv7 = S7, iv8 = S8, iv9 = S9, ivA = SA, ivB = SB, ivC = SC, ivD = SD, ivE = SE, ivF = SF;

            offset = (offset + length)|0;
            length = 0;
            counter = (counter + 1)|0;
        }
    }

    // offset, length, output — multiple of 16
    function ccm_decrypt ( offset, length, nonce0, nonce1, nonce2, nonce3, nonce4, nonce5, nonce6, nonce7, nonce8, nonce9, nonceA, nonceB, nonceC, nonceD, counter ) {
        offset = offset|0;
        length = length|0;
        nonce0 = nonce0|0;
        nonce1 = nonce1|0;
        nonce2 = nonce2|0;
        nonce3 = nonce3|0;
        nonce4 = nonce4|0;
        nonce5 = nonce5|0;
        nonce6 = nonce6|0;
        nonce7 = nonce7|0;
        nonce8 = nonce8|0;
        nonce9 = nonce9|0;
        nonceA = nonceA|0;
        nonceB = nonceB|0;
        nonceC = nonceC|0;
        nonceD = nonceD|0;
        counter = counter|0;

        var iv0 = 0, iv1 = 0, iv2 = 0, iv3 = 0, iv4 = 0, iv5 = 0, iv6 = 0, iv7 = 0, iv8 = 0, iv9 = 0, ivA = 0, ivB = 0, ivC = 0, ivD = 0, ivE = 0, ivF = 0,
            s0 = 0, s1 = 0, s2 = 0, s3 = 0, s4 = 0, s5 = 0, s6 = 0, s7 = 0, s8 = 0, s9 = 0, sA = 0, sB = 0, sC = 0, sD = 0, sE = 0, sF = 0;

        if ( offset & 15 )
            return -1;

        iv0 = S0, iv1 = S1, iv2 = S2, iv3 = S3, iv4 = S4, iv5 = S5, iv6 = S6, iv7 = S7, iv8 = S8, iv9 = S9, ivA = SA, ivB = SB, ivC = SC, ivD = SD, ivE = SE, ivF = SF;

        while ( (length|0) >= 16 ) {
            //
            // Cipher
            //

            _encrypt_128(
                nonce0,
                nonce1,
                nonce2,
                nonce3,
                nonce4,
                nonce5,
                nonce6,
                nonce7,
                nonce8,
                nonce9,
                nonceA,
                nonceB,
                nonceC ^ (counter>>>24),
                nonceD ^ (counter>>>16&255),
                counter>>>8&255,
                counter&255
            );

            HEAP[offset] = s0 = HEAP[offset] ^ S0;
            HEAP[offset|1] = s1 = HEAP[offset|1] ^ S1;
            HEAP[offset|2] = s2 = HEAP[offset|2] ^ S2;
            HEAP[offset|3] = s3 = HEAP[offset|3] ^ S3;
            HEAP[offset|4] = s4 = HEAP[offset|4] ^ S4;
            HEAP[offset|5] = s5 = HEAP[offset|5] ^ S5;
            HEAP[offset|6] = s6 = HEAP[offset|6] ^ S6;
            HEAP[offset|7] = s7 = HEAP[offset|7] ^ S7;
            HEAP[offset|8] = s8 = HEAP[offset|8] ^ S8;
            HEAP[offset|9] = s9 = HEAP[offset|9] ^ S9;
            HEAP[offset|10] = sA = HEAP[offset|10] ^ SA;
            HEAP[offset|11] = sB = HEAP[offset|11] ^ SB;
            HEAP[offset|12] = sC = HEAP[offset|12] ^ SC;
            HEAP[offset|13] = sD = HEAP[offset|13] ^ SD;
            HEAP[offset|14] = sE = HEAP[offset|14] ^ SE;
            HEAP[offset|15] = sF = HEAP[offset|15] ^ SF;

            //
            // MAC
            //

            _encrypt_128(
                s0 ^ iv0,
                s1 ^ iv1,
                s2 ^ iv2,
                s3 ^ iv3,
                s4 ^ iv4,
                s5 ^ iv5,
                s6 ^ iv6,
                s7 ^ iv7,
                s8 ^ iv8,
                s9 ^ iv9,
                sA ^ ivA,
                sB ^ ivB,
                sC ^ ivC,
                sD ^ ivD,
                sE ^ ivE,
                sF ^ ivF
            );

            iv0 = S0, iv1 = S1, iv2 = S2, iv3 = S3, iv4 = S4, iv5 = S5, iv6 = S6, iv7 = S7, iv8 = S8, iv9 = S9, ivA = SA, ivB = SB, ivC = SC, ivD = SD, ivE = SE, ivF = SF;

            offset = (offset + 16)|0;
            length = (length - 16)|0;
            counter = (counter + 1)|0;
        }
        if ( (length|0) > 0 ) {
            //
            // Cipher
            //

            _encrypt_128(
                nonce0,
                nonce1,
                nonce2,
                nonce3,
                nonce4,
                nonce5,
                nonce6,
                nonce7,
                nonce8,
                nonce9,
                nonceA,
                nonceB,
                nonceC ^ (counter>>>24),
                nonceD ^ (counter>>>16&255),
                counter>>>8&255,
                counter&255
            );

            s0 = HEAP[offset] ^ S0;
            s1 = (length|0) > 1 ? HEAP[offset|1] ^ S1 : 0;
            s2 = (length|0) > 2 ? HEAP[offset|2] ^ S2 : 0;
            s3 = (length|0) > 3 ? HEAP[offset|3] ^ S3 : 0;
            s4 = (length|0) > 4 ? HEAP[offset|4] ^ S4 : 0;
            s5 = (length|0) > 5 ? HEAP[offset|5] ^ S5 : 0;
            s6 = (length|0) > 6 ? HEAP[offset|6] ^ S6 : 0;
            s7 = (length|0) > 7 ? HEAP[offset|7] ^ S7 : 0;
            s8 = (length|0) > 8 ? HEAP[offset|8] ^ S8 : 0;
            s9 = (length|0) > 9 ? HEAP[offset|9] ^ S9 : 0;
            sA = (length|0) > 10 ? HEAP[offset|10] ^ SA : 0;
            sB = (length|0) > 11 ? HEAP[offset|11] ^ SB : 0;
            sC = (length|0) > 12 ? HEAP[offset|12] ^ SC : 0;
            sD = (length|0) > 13 ? HEAP[offset|13] ^ SD : 0;
            sE = (length|0) > 14 ? HEAP[offset|14] ^ SE : 0;
            sF = (length|0) > 15 ? HEAP[offset|15] ^ SF : 0;

            HEAP[offset] = s0;
            if ( (length|0) > 1 ) HEAP[offset|1] = s1;
            if ( (length|0) > 2 ) HEAP[offset|2] = s2;
            if ( (length|0) > 3 ) HEAP[offset|3] = s3;
            if ( (length|0) > 4 ) HEAP[offset|4] = s4;
            if ( (length|0) > 5 ) HEAP[offset|5] = s5;
            if ( (length|0) > 6 ) HEAP[offset|6] = s6;
            if ( (length|0) > 7 ) HEAP[offset|7] = s7;
            if ( (length|0) > 8 ) HEAP[offset|8] = s8;
            if ( (length|0) > 9 ) HEAP[offset|9] = s9;
            if ( (length|0) > 10 ) HEAP[offset|10] = sA;
            if ( (length|0) > 11 ) HEAP[offset|11] = sB;
            if ( (length|0) > 12 ) HEAP[offset|12] = sC;
            if ( (length|0) > 13 ) HEAP[offset|13] = sD;
            if ( (length|0) > 14 ) HEAP[offset|14] = sE;
            //if ( (length|0) > 15 ) HEAP[offset|15] = sF;

            //
            // MAC
            //

            _encrypt_128(
                s0 ^ iv0,
                s1 ^ iv1,
                s2 ^ iv2,
                s3 ^ iv3,
                s4 ^ iv4,
                s5 ^ iv5,
                s6 ^ iv6,
                s7 ^ iv7,
                s8 ^ iv8,
                s9 ^ iv9,
                sA ^ ivA,
                sB ^ ivB,
                sC ^ ivC,
                sD ^ ivD,
                sE ^ ivE,
                sF ^ ivF
            );

            iv0 = S0, iv1 = S1, iv2 = S2, iv3 = S3, iv4 = S4, iv5 = S5, iv6 = S6, iv7 = S7, iv8 = S8, iv9 = S9, ivA = SA, ivB = SB, ivC = SC, ivD = SD, ivE = SE, ivF = SF;

            offset = (offset + 16)|0;
            length = (length - 16)|0;
            counter = (counter + 1)|0;
        }
    }

    return {
        init_state: init_state,
        save_state: save_state,

        init_key_128: init_key_128,

        cbc_encrypt: cbc_encrypt,
        cbc_decrypt: cbc_decrypt,
        cbc_mac: cbc_mac,

        ccm_encrypt: ccm_encrypt,
        ccm_decrypt: ccm_decrypt
    };
}
*/
// Workaround Firefox bug, uglified from aes_asm above with little manual changes
function aes_asm ( stdlib, foreign, buffer ) {
    return (new Function('e,t,n','"use asm";var r=0,i=256,s=512,o=768,u=1024,a=1280,f=1536,l=1792,c=0,h=0,p=0,d=0,v=0,m=0,g=0,y=0,b=0,w=0,E=0,S=0,x=0,T=0,N=0,C=0,k=0,L=0,A=0,O=0,M=0,_=0,D=0,P=0,H=0,B=0,j=0,F=0,I=0,q=0,R=0,U=0,z=0,W=0,X=0,V=0,$=0,J=0,K=0,Q=0,G=0,Y=0,Z=0,et=0,tt=0,nt=0,rt=0,it=0,st=0,ot=0,ut=0,at=0,ft=0,lt=0,ct=0,ht=0,pt=0,dt=0,vt=0,mt=0,gt=0,yt=0,bt=0,wt=0,Et=0,St=0,xt=0,Tt=0,Nt=0,Ct=0,kt=0,Lt=0,At=0,Ot=0,Mt=0,_t=0,Dt=0,Pt=0,Ht=0,Bt=0,jt=0,Ft=0,It=0,qt=0,Rt=0,Ut=0,zt=0,Wt=0,Xt=0,Vt=0,$t=0,Jt=0,Kt=0,Qt=0,Gt=0,Yt=0,Zt=0,en=0,tn=0,nn=0,rn=0,sn=0,on=0,un=0,an=0,fn=0,ln=0,cn=0,hn=0,pn=0,dn=0,vn=0,mn=0,gn=0,yn=0,bn=0,wn=0,En=0,Sn=0,xn=0,Tn=0,Nn=0,Cn=0,kn=0,Ln=0,An=0,On=0,Mn=0,_n=0,Dn=0,Pn=0,Hn=0,Bn=0,jn=0,Fn=0,In=0,qn=0,Rn=0,Un=0,zn=0,Wn=0,Xn=0,Vn=0,$n=0,Jn=0,Kn=0,Qn=0,Gn=0,Yn=0,Zn=0,er=0,tr=0,nr=0,rr=0,ir=0,sr=0,or=0,ur=0,ar=0,fr=0,lr=0,cr=0,hr=0,pr=0,dr=0,vr=0,mr=0,gr=0,yr=0,br=0,wr=0,Er=0,Sr=0,xr=0,Tr=0,Nr=0,Cr=0,kr=0,Lr=0,Ar=0,Or=0,Mr=0,_r=0,Dr=0,Pr=0,Hr=0,Br=0,jr=0,Fr=0,Ir=0,qr=0,Rr=0;var Ur=new e.Uint8Array(n);function zr(){z=k^Ur[r|q]^1;W=L^Ur[r|R];X=A^Ur[r|U];V=O^Ur[r|I];$=M^z;J=_^W;K=D^X;Q=P^V;G=H^$;Y=B^J;Z=j^K;et=F^Q;tt=I^G;nt=q^Y;rt=R^Z;it=U^et;st=z^Ur[r|nt]^2;ot=W^Ur[r|rt];ut=X^Ur[r|it];at=V^Ur[r|tt];ft=$^st;lt=J^ot;ct=K^ut;ht=Q^at;pt=G^ft;dt=Y^lt;vt=Z^ct;mt=et^ht;gt=tt^pt;yt=nt^dt;bt=rt^vt;wt=it^mt;Et=st^Ur[r|yt]^4;St=ot^Ur[r|bt];xt=ut^Ur[r|wt];Tt=at^Ur[r|gt];Nt=ft^Et;Ct=lt^St;kt=ct^xt;Lt=ht^Tt;At=pt^Nt;Ot=dt^Ct;Mt=vt^kt;_t=mt^Lt;Dt=gt^At;Pt=yt^Ot;Ht=bt^Mt;Bt=wt^_t;jt=Et^Ur[r|Pt]^8;Ft=St^Ur[r|Ht];It=xt^Ur[r|Bt];qt=Tt^Ur[r|Dt];Rt=Nt^jt;Ut=Ct^Ft;zt=kt^It;Wt=Lt^qt;Xt=At^Rt;Vt=Ot^Ut;$t=Mt^zt;Jt=_t^Wt;Kt=Dt^Xt;Qt=Pt^Vt;Gt=Ht^$t;Yt=Bt^Jt;Zt=jt^Ur[r|Qt]^16;en=Ft^Ur[r|Gt];tn=It^Ur[r|Yt];nn=qt^Ur[r|Kt];rn=Rt^Zt;sn=Ut^en;on=zt^tn;un=Wt^nn;an=Xt^rn;fn=Vt^sn;ln=$t^on;cn=Jt^un;hn=Kt^an;pn=Qt^fn;dn=Gt^ln;vn=Yt^cn;mn=Zt^Ur[r|pn]^32;gn=en^Ur[r|dn];yn=tn^Ur[r|vn];bn=nn^Ur[r|hn];wn=rn^mn;En=sn^gn;Sn=on^yn;xn=un^bn;Tn=an^wn;Nn=fn^En;Cn=ln^Sn;kn=cn^xn;Ln=hn^Tn;An=pn^Nn;On=dn^Cn;Mn=vn^kn;_n=mn^Ur[r|An]^64;Dn=gn^Ur[r|On];Pn=yn^Ur[r|Mn];Hn=bn^Ur[r|Ln];Bn=wn^_n;jn=En^Dn;Fn=Sn^Pn;In=xn^Hn;qn=Tn^Bn;Rn=Nn^jn;Un=Cn^Fn;zn=kn^In;Wn=Ln^qn;Xn=An^Rn;Vn=On^Un;$n=Mn^zn;Jn=_n^Ur[r|Xn]^128;Kn=Dn^Ur[r|Vn];Qn=Pn^Ur[r|$n];Gn=Hn^Ur[r|Wn];Yn=Bn^Jn;Zn=jn^Kn;er=Fn^Qn;tr=In^Gn;nr=qn^Yn;rr=Rn^Zn;ir=Un^er;sr=zn^tr;or=Wn^nr;ur=Xn^rr;ar=Vn^ir;fr=$n^sr;lr=Jn^Ur[r|ur]^27;cr=Kn^Ur[r|ar];hr=Qn^Ur[r|fr];pr=Gn^Ur[r|or];dr=Yn^lr;vr=Zn^cr;mr=er^hr;gr=tr^pr;yr=nr^dr;br=rr^vr;wr=ir^mr;Er=sr^gr;Sr=or^yr;xr=ur^br;Tr=ar^wr;Nr=fr^Er;Cr=lr^Ur[r|xr]^54;kr=cr^Ur[r|Tr];Lr=hr^Ur[r|Nr];Ar=pr^Ur[r|Sr];Or=dr^Cr;Mr=vr^kr;_r=mr^Lr;Dr=gr^Ar;Pr=yr^Or;Hr=br^Mr;Br=wr^_r;jr=Er^Dr;Fr=Sr^Pr;Ir=xr^Hr;qr=Tr^Br;Rr=Nr^jr}function Wr(e,t,n,i,u,a,f,l,zr,Wr,Xr,Vr,$r,Jr,Kr,Qr){e=e|0;t=t|0;n=n|0;i=i|0;u=u|0;a=a|0;f=f|0;l=l|0;zr=zr|0;Wr=Wr|0;Xr=Xr|0;Vr=Vr|0;$r=$r|0;Jr=Jr|0;Kr=Kr|0;Qr=Qr|0;var Gr=0,Yr=0,Zr=0,ei=0,ti=0,ni=0,ri=0,ii=0,si=0,oi=0,ui=0,ai=0,fi=0,li=0,ci=0,hi=0;e=e^k;t=t^L;n=n^A;i=i^O;u=u^M;a=a^_;f=f^D;l=l^P;zr=zr^H;Wr=Wr^B;Xr=Xr^j;Vr=Vr^F;$r=$r^I;Jr=Jr^q;Kr=Kr^R;Qr=Qr^U;Gr=Ur[s|e]^Ur[o|a]^Ur[r|Xr]^Ur[r|Qr]^z;Yr=Ur[r|e]^Ur[s|a]^Ur[o|Xr]^Ur[r|Qr]^W;Zr=Ur[r|e]^Ur[r|a]^Ur[s|Xr]^Ur[o|Qr]^X;ei=Ur[o|e]^Ur[r|a]^Ur[r|Xr]^Ur[s|Qr]^V;ti=Ur[s|u]^Ur[o|Wr]^Ur[r|Kr]^Ur[r|i]^$;ni=Ur[r|u]^Ur[s|Wr]^Ur[o|Kr]^Ur[r|i]^J;ri=Ur[r|u]^Ur[r|Wr]^Ur[s|Kr]^Ur[o|i]^K;ii=Ur[o|u]^Ur[r|Wr]^Ur[r|Kr]^Ur[s|i]^Q;si=Ur[s|zr]^Ur[o|Jr]^Ur[r|n]^Ur[r|l]^G;oi=Ur[r|zr]^Ur[s|Jr]^Ur[o|n]^Ur[r|l]^Y;ui=Ur[r|zr]^Ur[r|Jr]^Ur[s|n]^Ur[o|l]^Z;ai=Ur[o|zr]^Ur[r|Jr]^Ur[r|n]^Ur[s|l]^et;fi=Ur[s|$r]^Ur[o|t]^Ur[r|f]^Ur[r|Vr]^tt;li=Ur[r|$r]^Ur[s|t]^Ur[o|f]^Ur[r|Vr]^nt;ci=Ur[r|$r]^Ur[r|t]^Ur[s|f]^Ur[o|Vr]^rt;hi=Ur[o|$r]^Ur[r|t]^Ur[r|f]^Ur[s|Vr]^it;e=Ur[s|Gr]^Ur[o|ni]^Ur[r|ui]^Ur[r|hi]^st;t=Ur[r|Gr]^Ur[s|ni]^Ur[o|ui]^Ur[r|hi]^ot;n=Ur[r|Gr]^Ur[r|ni]^Ur[s|ui]^Ur[o|hi]^ut;i=Ur[o|Gr]^Ur[r|ni]^Ur[r|ui]^Ur[s|hi]^at;u=Ur[s|ti]^Ur[o|oi]^Ur[r|ci]^Ur[r|ei]^ft;a=Ur[r|ti]^Ur[s|oi]^Ur[o|ci]^Ur[r|ei]^lt;f=Ur[r|ti]^Ur[r|oi]^Ur[s|ci]^Ur[o|ei]^ct;l=Ur[o|ti]^Ur[r|oi]^Ur[r|ci]^Ur[s|ei]^ht;zr=Ur[s|si]^Ur[o|li]^Ur[r|Zr]^Ur[r|ii]^pt;Wr=Ur[r|si]^Ur[s|li]^Ur[o|Zr]^Ur[r|ii]^dt;Xr=Ur[r|si]^Ur[r|li]^Ur[s|Zr]^Ur[o|ii]^vt;Vr=Ur[o|si]^Ur[r|li]^Ur[r|Zr]^Ur[s|ii]^mt;$r=Ur[s|fi]^Ur[o|Yr]^Ur[r|ri]^Ur[r|ai]^gt;Jr=Ur[r|fi]^Ur[s|Yr]^Ur[o|ri]^Ur[r|ai]^yt;Kr=Ur[r|fi]^Ur[r|Yr]^Ur[s|ri]^Ur[o|ai]^bt;Qr=Ur[o|fi]^Ur[r|Yr]^Ur[r|ri]^Ur[s|ai]^wt;Gr=Ur[s|e]^Ur[o|a]^Ur[r|Xr]^Ur[r|Qr]^Et;Yr=Ur[r|e]^Ur[s|a]^Ur[o|Xr]^Ur[r|Qr]^St;Zr=Ur[r|e]^Ur[r|a]^Ur[s|Xr]^Ur[o|Qr]^xt;ei=Ur[o|e]^Ur[r|a]^Ur[r|Xr]^Ur[s|Qr]^Tt;ti=Ur[s|u]^Ur[o|Wr]^Ur[r|Kr]^Ur[r|i]^Nt;ni=Ur[r|u]^Ur[s|Wr]^Ur[o|Kr]^Ur[r|i]^Ct;ri=Ur[r|u]^Ur[r|Wr]^Ur[s|Kr]^Ur[o|i]^kt;ii=Ur[o|u]^Ur[r|Wr]^Ur[r|Kr]^Ur[s|i]^Lt;si=Ur[s|zr]^Ur[o|Jr]^Ur[r|n]^Ur[r|l]^At;oi=Ur[r|zr]^Ur[s|Jr]^Ur[o|n]^Ur[r|l]^Ot;ui=Ur[r|zr]^Ur[r|Jr]^Ur[s|n]^Ur[o|l]^Mt;ai=Ur[o|zr]^Ur[r|Jr]^Ur[r|n]^Ur[s|l]^_t;fi=Ur[s|$r]^Ur[o|t]^Ur[r|f]^Ur[r|Vr]^Dt;li=Ur[r|$r]^Ur[s|t]^Ur[o|f]^Ur[r|Vr]^Pt;ci=Ur[r|$r]^Ur[r|t]^Ur[s|f]^Ur[o|Vr]^Ht;hi=Ur[o|$r]^Ur[r|t]^Ur[r|f]^Ur[s|Vr]^Bt;e=Ur[s|Gr]^Ur[o|ni]^Ur[r|ui]^Ur[r|hi]^jt;t=Ur[r|Gr]^Ur[s|ni]^Ur[o|ui]^Ur[r|hi]^Ft;n=Ur[r|Gr]^Ur[r|ni]^Ur[s|ui]^Ur[o|hi]^It;i=Ur[o|Gr]^Ur[r|ni]^Ur[r|ui]^Ur[s|hi]^qt;u=Ur[s|ti]^Ur[o|oi]^Ur[r|ci]^Ur[r|ei]^Rt;a=Ur[r|ti]^Ur[s|oi]^Ur[o|ci]^Ur[r|ei]^Ut;f=Ur[r|ti]^Ur[r|oi]^Ur[s|ci]^Ur[o|ei]^zt;l=Ur[o|ti]^Ur[r|oi]^Ur[r|ci]^Ur[s|ei]^Wt;zr=Ur[s|si]^Ur[o|li]^Ur[r|Zr]^Ur[r|ii]^Xt;Wr=Ur[r|si]^Ur[s|li]^Ur[o|Zr]^Ur[r|ii]^Vt;Xr=Ur[r|si]^Ur[r|li]^Ur[s|Zr]^Ur[o|ii]^$t;Vr=Ur[o|si]^Ur[r|li]^Ur[r|Zr]^Ur[s|ii]^Jt;$r=Ur[s|fi]^Ur[o|Yr]^Ur[r|ri]^Ur[r|ai]^Kt;Jr=Ur[r|fi]^Ur[s|Yr]^Ur[o|ri]^Ur[r|ai]^Qt;Kr=Ur[r|fi]^Ur[r|Yr]^Ur[s|ri]^Ur[o|ai]^Gt;Qr=Ur[o|fi]^Ur[r|Yr]^Ur[r|ri]^Ur[s|ai]^Yt;Gr=Ur[s|e]^Ur[o|a]^Ur[r|Xr]^Ur[r|Qr]^Zt;Yr=Ur[r|e]^Ur[s|a]^Ur[o|Xr]^Ur[r|Qr]^en;Zr=Ur[r|e]^Ur[r|a]^Ur[s|Xr]^Ur[o|Qr]^tn;ei=Ur[o|e]^Ur[r|a]^Ur[r|Xr]^Ur[s|Qr]^nn;ti=Ur[s|u]^Ur[o|Wr]^Ur[r|Kr]^Ur[r|i]^rn;ni=Ur[r|u]^Ur[s|Wr]^Ur[o|Kr]^Ur[r|i]^sn;ri=Ur[r|u]^Ur[r|Wr]^Ur[s|Kr]^Ur[o|i]^on;ii=Ur[o|u]^Ur[r|Wr]^Ur[r|Kr]^Ur[s|i]^un;si=Ur[s|zr]^Ur[o|Jr]^Ur[r|n]^Ur[r|l]^an;oi=Ur[r|zr]^Ur[s|Jr]^Ur[o|n]^Ur[r|l]^fn;ui=Ur[r|zr]^Ur[r|Jr]^Ur[s|n]^Ur[o|l]^ln;ai=Ur[o|zr]^Ur[r|Jr]^Ur[r|n]^Ur[s|l]^cn;fi=Ur[s|$r]^Ur[o|t]^Ur[r|f]^Ur[r|Vr]^hn;li=Ur[r|$r]^Ur[s|t]^Ur[o|f]^Ur[r|Vr]^pn;ci=Ur[r|$r]^Ur[r|t]^Ur[s|f]^Ur[o|Vr]^dn;hi=Ur[o|$r]^Ur[r|t]^Ur[r|f]^Ur[s|Vr]^vn;e=Ur[s|Gr]^Ur[o|ni]^Ur[r|ui]^Ur[r|hi]^mn;t=Ur[r|Gr]^Ur[s|ni]^Ur[o|ui]^Ur[r|hi]^gn;n=Ur[r|Gr]^Ur[r|ni]^Ur[s|ui]^Ur[o|hi]^yn;i=Ur[o|Gr]^Ur[r|ni]^Ur[r|ui]^Ur[s|hi]^bn;u=Ur[s|ti]^Ur[o|oi]^Ur[r|ci]^Ur[r|ei]^wn;a=Ur[r|ti]^Ur[s|oi]^Ur[o|ci]^Ur[r|ei]^En;f=Ur[r|ti]^Ur[r|oi]^Ur[s|ci]^Ur[o|ei]^Sn;l=Ur[o|ti]^Ur[r|oi]^Ur[r|ci]^Ur[s|ei]^xn;zr=Ur[s|si]^Ur[o|li]^Ur[r|Zr]^Ur[r|ii]^Tn;Wr=Ur[r|si]^Ur[s|li]^Ur[o|Zr]^Ur[r|ii]^Nn;Xr=Ur[r|si]^Ur[r|li]^Ur[s|Zr]^Ur[o|ii]^Cn;Vr=Ur[o|si]^Ur[r|li]^Ur[r|Zr]^Ur[s|ii]^kn;$r=Ur[s|fi]^Ur[o|Yr]^Ur[r|ri]^Ur[r|ai]^Ln;Jr=Ur[r|fi]^Ur[s|Yr]^Ur[o|ri]^Ur[r|ai]^An;Kr=Ur[r|fi]^Ur[r|Yr]^Ur[s|ri]^Ur[o|ai]^On;Qr=Ur[o|fi]^Ur[r|Yr]^Ur[r|ri]^Ur[s|ai]^Mn;Gr=Ur[s|e]^Ur[o|a]^Ur[r|Xr]^Ur[r|Qr]^_n;Yr=Ur[r|e]^Ur[s|a]^Ur[o|Xr]^Ur[r|Qr]^Dn;Zr=Ur[r|e]^Ur[r|a]^Ur[s|Xr]^Ur[o|Qr]^Pn;ei=Ur[o|e]^Ur[r|a]^Ur[r|Xr]^Ur[s|Qr]^Hn;ti=Ur[s|u]^Ur[o|Wr]^Ur[r|Kr]^Ur[r|i]^Bn;ni=Ur[r|u]^Ur[s|Wr]^Ur[o|Kr]^Ur[r|i]^jn;ri=Ur[r|u]^Ur[r|Wr]^Ur[s|Kr]^Ur[o|i]^Fn;ii=Ur[o|u]^Ur[r|Wr]^Ur[r|Kr]^Ur[s|i]^In;si=Ur[s|zr]^Ur[o|Jr]^Ur[r|n]^Ur[r|l]^qn;oi=Ur[r|zr]^Ur[s|Jr]^Ur[o|n]^Ur[r|l]^Rn;ui=Ur[r|zr]^Ur[r|Jr]^Ur[s|n]^Ur[o|l]^Un;ai=Ur[o|zr]^Ur[r|Jr]^Ur[r|n]^Ur[s|l]^zn;fi=Ur[s|$r]^Ur[o|t]^Ur[r|f]^Ur[r|Vr]^Wn;li=Ur[r|$r]^Ur[s|t]^Ur[o|f]^Ur[r|Vr]^Xn;ci=Ur[r|$r]^Ur[r|t]^Ur[s|f]^Ur[o|Vr]^Vn;hi=Ur[o|$r]^Ur[r|t]^Ur[r|f]^Ur[s|Vr]^$n;e=Ur[s|Gr]^Ur[o|ni]^Ur[r|ui]^Ur[r|hi]^Jn;t=Ur[r|Gr]^Ur[s|ni]^Ur[o|ui]^Ur[r|hi]^Kn;n=Ur[r|Gr]^Ur[r|ni]^Ur[s|ui]^Ur[o|hi]^Qn;i=Ur[o|Gr]^Ur[r|ni]^Ur[r|ui]^Ur[s|hi]^Gn;u=Ur[s|ti]^Ur[o|oi]^Ur[r|ci]^Ur[r|ei]^Yn;a=Ur[r|ti]^Ur[s|oi]^Ur[o|ci]^Ur[r|ei]^Zn;f=Ur[r|ti]^Ur[r|oi]^Ur[s|ci]^Ur[o|ei]^er;l=Ur[o|ti]^Ur[r|oi]^Ur[r|ci]^Ur[s|ei]^tr;zr=Ur[s|si]^Ur[o|li]^Ur[r|Zr]^Ur[r|ii]^nr;Wr=Ur[r|si]^Ur[s|li]^Ur[o|Zr]^Ur[r|ii]^rr;Xr=Ur[r|si]^Ur[r|li]^Ur[s|Zr]^Ur[o|ii]^ir;Vr=Ur[o|si]^Ur[r|li]^Ur[r|Zr]^Ur[s|ii]^sr;$r=Ur[s|fi]^Ur[o|Yr]^Ur[r|ri]^Ur[r|ai]^or;Jr=Ur[r|fi]^Ur[s|Yr]^Ur[o|ri]^Ur[r|ai]^ur;Kr=Ur[r|fi]^Ur[r|Yr]^Ur[s|ri]^Ur[o|ai]^ar;Qr=Ur[o|fi]^Ur[r|Yr]^Ur[r|ri]^Ur[s|ai]^fr;Gr=Ur[s|e]^Ur[o|a]^Ur[r|Xr]^Ur[r|Qr]^lr;Yr=Ur[r|e]^Ur[s|a]^Ur[o|Xr]^Ur[r|Qr]^cr;Zr=Ur[r|e]^Ur[r|a]^Ur[s|Xr]^Ur[o|Qr]^hr;ei=Ur[o|e]^Ur[r|a]^Ur[r|Xr]^Ur[s|Qr]^pr;ti=Ur[s|u]^Ur[o|Wr]^Ur[r|Kr]^Ur[r|i]^dr;ni=Ur[r|u]^Ur[s|Wr]^Ur[o|Kr]^Ur[r|i]^vr;ri=Ur[r|u]^Ur[r|Wr]^Ur[s|Kr]^Ur[o|i]^mr;ii=Ur[o|u]^Ur[r|Wr]^Ur[r|Kr]^Ur[s|i]^gr;si=Ur[s|zr]^Ur[o|Jr]^Ur[r|n]^Ur[r|l]^yr;oi=Ur[r|zr]^Ur[s|Jr]^Ur[o|n]^Ur[r|l]^br;ui=Ur[r|zr]^Ur[r|Jr]^Ur[s|n]^Ur[o|l]^wr;ai=Ur[o|zr]^Ur[r|Jr]^Ur[r|n]^Ur[s|l]^Er;fi=Ur[s|$r]^Ur[o|t]^Ur[r|f]^Ur[r|Vr]^Sr;li=Ur[r|$r]^Ur[s|t]^Ur[o|f]^Ur[r|Vr]^xr;ci=Ur[r|$r]^Ur[r|t]^Ur[s|f]^Ur[o|Vr]^Tr;hi=Ur[o|$r]^Ur[r|t]^Ur[r|f]^Ur[s|Vr]^Nr;c=Ur[r|Gr]^Cr;h=Ur[r|ni]^kr;p=Ur[r|ui]^Lr;d=Ur[r|hi]^Ar;v=Ur[r|ti]^Or;m=Ur[r|oi]^Mr;g=Ur[r|ci]^_r;y=Ur[r|ei]^Dr;b=Ur[r|si]^Pr;w=Ur[r|li]^Hr;E=Ur[r|Zr]^Br;S=Ur[r|ii]^jr;x=Ur[r|fi]^Fr;T=Ur[r|Yr]^Ir;N=Ur[r|ri]^qr;C=Ur[r|ai]^Rr}function Xr(e,t,n,r,s,o,zr,Wr,Xr,Vr,$r,Jr,Kr,Qr,Gr,Yr){e=e|0;t=t|0;n=n|0;r=r|0;s=s|0;o=o|0;zr=zr|0;Wr=Wr|0;Xr=Xr|0;Vr=Vr|0;$r=$r|0;Jr=Jr|0;Kr=Kr|0;Qr=Qr|0;Gr=Gr|0;Yr=Yr|0;var Zr=0,ei=0,ti=0,ni=0,ri=0,ii=0,si=0,oi=0,ui=0,ai=0,fi=0,li=0,ci=0,hi=0,pi=0,di=0;Zr=Ur[i|e^Cr]^lr;ei=Ur[i|Qr^Ir]^cr;ti=Ur[i|$r^Br]^hr;ni=Ur[i|Wr^Dr]^pr;ri=Ur[i|s^Or]^dr;ii=Ur[i|t^kr]^vr;si=Ur[i|Gr^qr]^mr;oi=Ur[i|Jr^jr]^gr;ui=Ur[i|Xr^Pr]^yr;ai=Ur[i|o^Mr]^br;fi=Ur[i|n^Lr]^wr;li=Ur[i|Yr^Rr]^Er;ci=Ur[i|Kr^Fr]^Sr;hi=Ur[i|Vr^Hr]^xr;pi=Ur[i|zr^_r]^Tr;di=Ur[i|r^Ar]^Nr;e=Ur[l|Zr]^Ur[a|ei]^Ur[f|ti]^Ur[u|ni];t=Ur[u|ci]^Ur[l|hi]^Ur[a|pi]^Ur[f|di];n=Ur[f|ui]^Ur[u|ai]^Ur[l|fi]^Ur[a|li];r=Ur[a|ri]^Ur[f|ii]^Ur[u|si]^Ur[l|oi];s=Ur[l|ri]^Ur[a|ii]^Ur[f|si]^Ur[u|oi];o=Ur[u|Zr]^Ur[l|ei]^Ur[a|ti]^Ur[f|ni];zr=Ur[f|ci]^Ur[u|hi]^Ur[l|pi]^Ur[a|di];Wr=Ur[a|ui]^Ur[f|ai]^Ur[u|fi]^Ur[l|li];Xr=Ur[l|ui]^Ur[a|ai]^Ur[f|fi]^Ur[u|li];Vr=Ur[u|ri]^Ur[l|ii]^Ur[a|si]^Ur[f|oi];$r=Ur[f|Zr]^Ur[u|ei]^Ur[l|ti]^Ur[a|ni];Jr=Ur[a|ci]^Ur[f|hi]^Ur[u|pi]^Ur[l|di];Kr=Ur[l|ci]^Ur[a|hi]^Ur[f|pi]^Ur[u|di];Qr=Ur[u|ui]^Ur[l|ai]^Ur[a|fi]^Ur[f|li];Gr=Ur[f|ri]^Ur[u|ii]^Ur[l|si]^Ur[a|oi];Yr=Ur[a|Zr]^Ur[f|ei]^Ur[u|ti]^Ur[l|ni];Zr=Ur[i|e]^Jn;ei=Ur[i|t]^Kn;ti=Ur[i|n]^Qn;ni=Ur[i|r]^Gn;ri=Ur[i|s]^Yn;ii=Ur[i|o]^Zn;si=Ur[i|zr]^er;oi=Ur[i|Wr]^tr;ui=Ur[i|Xr]^nr;ai=Ur[i|Vr]^rr;fi=Ur[i|$r]^ir;li=Ur[i|Jr]^sr;ci=Ur[i|Kr]^or;hi=Ur[i|Qr]^ur;pi=Ur[i|Gr]^ar;di=Ur[i|Yr]^fr;e=Ur[l|Zr]^Ur[a|ei]^Ur[f|ti]^Ur[u|ni];t=Ur[u|ci]^Ur[l|hi]^Ur[a|pi]^Ur[f|di];n=Ur[f|ui]^Ur[u|ai]^Ur[l|fi]^Ur[a|li];r=Ur[a|ri]^Ur[f|ii]^Ur[u|si]^Ur[l|oi];s=Ur[l|ri]^Ur[a|ii]^Ur[f|si]^Ur[u|oi];o=Ur[u|Zr]^Ur[l|ei]^Ur[a|ti]^Ur[f|ni];zr=Ur[f|ci]^Ur[u|hi]^Ur[l|pi]^Ur[a|di];Wr=Ur[a|ui]^Ur[f|ai]^Ur[u|fi]^Ur[l|li];Xr=Ur[l|ui]^Ur[a|ai]^Ur[f|fi]^Ur[u|li];Vr=Ur[u|ri]^Ur[l|ii]^Ur[a|si]^Ur[f|oi];$r=Ur[f|Zr]^Ur[u|ei]^Ur[l|ti]^Ur[a|ni];Jr=Ur[a|ci]^Ur[f|hi]^Ur[u|pi]^Ur[l|di];Kr=Ur[l|ci]^Ur[a|hi]^Ur[f|pi]^Ur[u|di];Qr=Ur[u|ui]^Ur[l|ai]^Ur[a|fi]^Ur[f|li];Gr=Ur[f|ri]^Ur[u|ii]^Ur[l|si]^Ur[a|oi];Yr=Ur[a|Zr]^Ur[f|ei]^Ur[u|ti]^Ur[l|ni];Zr=Ur[i|e]^_n;ei=Ur[i|t]^Dn;ti=Ur[i|n]^Pn;ni=Ur[i|r]^Hn;ri=Ur[i|s]^Bn;ii=Ur[i|o]^jn;si=Ur[i|zr]^Fn;oi=Ur[i|Wr]^In;ui=Ur[i|Xr]^qn;ai=Ur[i|Vr]^Rn;fi=Ur[i|$r]^Un;li=Ur[i|Jr]^zn;ci=Ur[i|Kr]^Wn;hi=Ur[i|Qr]^Xn;pi=Ur[i|Gr]^Vn;di=Ur[i|Yr]^$n;e=Ur[l|Zr]^Ur[a|ei]^Ur[f|ti]^Ur[u|ni];t=Ur[u|ci]^Ur[l|hi]^Ur[a|pi]^Ur[f|di];n=Ur[f|ui]^Ur[u|ai]^Ur[l|fi]^Ur[a|li];r=Ur[a|ri]^Ur[f|ii]^Ur[u|si]^Ur[l|oi];s=Ur[l|ri]^Ur[a|ii]^Ur[f|si]^Ur[u|oi];o=Ur[u|Zr]^Ur[l|ei]^Ur[a|ti]^Ur[f|ni];zr=Ur[f|ci]^Ur[u|hi]^Ur[l|pi]^Ur[a|di];Wr=Ur[a|ui]^Ur[f|ai]^Ur[u|fi]^Ur[l|li];Xr=Ur[l|ui]^Ur[a|ai]^Ur[f|fi]^Ur[u|li];Vr=Ur[u|ri]^Ur[l|ii]^Ur[a|si]^Ur[f|oi];$r=Ur[f|Zr]^Ur[u|ei]^Ur[l|ti]^Ur[a|ni];Jr=Ur[a|ci]^Ur[f|hi]^Ur[u|pi]^Ur[l|di];Kr=Ur[l|ci]^Ur[a|hi]^Ur[f|pi]^Ur[u|di];Qr=Ur[u|ui]^Ur[l|ai]^Ur[a|fi]^Ur[f|li];Gr=Ur[f|ri]^Ur[u|ii]^Ur[l|si]^Ur[a|oi];Yr=Ur[a|Zr]^Ur[f|ei]^Ur[u|ti]^Ur[l|ni];Zr=Ur[i|e]^mn;ei=Ur[i|t]^gn;ti=Ur[i|n]^yn;ni=Ur[i|r]^bn;ri=Ur[i|s]^wn;ii=Ur[i|o]^En;si=Ur[i|zr]^Sn;oi=Ur[i|Wr]^xn;ui=Ur[i|Xr]^Tn;ai=Ur[i|Vr]^Nn;fi=Ur[i|$r]^Cn;li=Ur[i|Jr]^kn;ci=Ur[i|Kr]^Ln;hi=Ur[i|Qr]^An;pi=Ur[i|Gr]^On;di=Ur[i|Yr]^Mn;e=Ur[l|Zr]^Ur[a|ei]^Ur[f|ti]^Ur[u|ni];t=Ur[u|ci]^Ur[l|hi]^Ur[a|pi]^Ur[f|di];n=Ur[f|ui]^Ur[u|ai]^Ur[l|fi]^Ur[a|li];r=Ur[a|ri]^Ur[f|ii]^Ur[u|si]^Ur[l|oi];s=Ur[l|ri]^Ur[a|ii]^Ur[f|si]^Ur[u|oi];o=Ur[u|Zr]^Ur[l|ei]^Ur[a|ti]^Ur[f|ni];zr=Ur[f|ci]^Ur[u|hi]^Ur[l|pi]^Ur[a|di];Wr=Ur[a|ui]^Ur[f|ai]^Ur[u|fi]^Ur[l|li];Xr=Ur[l|ui]^Ur[a|ai]^Ur[f|fi]^Ur[u|li];Vr=Ur[u|ri]^Ur[l|ii]^Ur[a|si]^Ur[f|oi];$r=Ur[f|Zr]^Ur[u|ei]^Ur[l|ti]^Ur[a|ni];Jr=Ur[a|ci]^Ur[f|hi]^Ur[u|pi]^Ur[l|di];Kr=Ur[l|ci]^Ur[a|hi]^Ur[f|pi]^Ur[u|di];Qr=Ur[u|ui]^Ur[l|ai]^Ur[a|fi]^Ur[f|li];Gr=Ur[f|ri]^Ur[u|ii]^Ur[l|si]^Ur[a|oi];Yr=Ur[a|Zr]^Ur[f|ei]^Ur[u|ti]^Ur[l|ni];Zr=Ur[i|e]^Zt;ei=Ur[i|t]^en;ti=Ur[i|n]^tn;ni=Ur[i|r]^nn;ri=Ur[i|s]^rn;ii=Ur[i|o]^sn;si=Ur[i|zr]^on;oi=Ur[i|Wr]^un;ui=Ur[i|Xr]^an;ai=Ur[i|Vr]^fn;fi=Ur[i|$r]^ln;li=Ur[i|Jr]^cn;ci=Ur[i|Kr]^hn;hi=Ur[i|Qr]^pn;pi=Ur[i|Gr]^dn;di=Ur[i|Yr]^vn;e=Ur[l|Zr]^Ur[a|ei]^Ur[f|ti]^Ur[u|ni];t=Ur[u|ci]^Ur[l|hi]^Ur[a|pi]^Ur[f|di];n=Ur[f|ui]^Ur[u|ai]^Ur[l|fi]^Ur[a|li];r=Ur[a|ri]^Ur[f|ii]^Ur[u|si]^Ur[l|oi];s=Ur[l|ri]^Ur[a|ii]^Ur[f|si]^Ur[u|oi];o=Ur[u|Zr]^Ur[l|ei]^Ur[a|ti]^Ur[f|ni];zr=Ur[f|ci]^Ur[u|hi]^Ur[l|pi]^Ur[a|di];Wr=Ur[a|ui]^Ur[f|ai]^Ur[u|fi]^Ur[l|li];Xr=Ur[l|ui]^Ur[a|ai]^Ur[f|fi]^Ur[u|li];Vr=Ur[u|ri]^Ur[l|ii]^Ur[a|si]^Ur[f|oi];$r=Ur[f|Zr]^Ur[u|ei]^Ur[l|ti]^Ur[a|ni];Jr=Ur[a|ci]^Ur[f|hi]^Ur[u|pi]^Ur[l|di];Kr=Ur[l|ci]^Ur[a|hi]^Ur[f|pi]^Ur[u|di];Qr=Ur[u|ui]^Ur[l|ai]^Ur[a|fi]^Ur[f|li];Gr=Ur[f|ri]^Ur[u|ii]^Ur[l|si]^Ur[a|oi];Yr=Ur[a|Zr]^Ur[f|ei]^Ur[u|ti]^Ur[l|ni];Zr=Ur[i|e]^jt;ei=Ur[i|t]^Ft;ti=Ur[i|n]^It;ni=Ur[i|r]^qt;ri=Ur[i|s]^Rt;ii=Ur[i|o]^Ut;si=Ur[i|zr]^zt;oi=Ur[i|Wr]^Wt;ui=Ur[i|Xr]^Xt;ai=Ur[i|Vr]^Vt;fi=Ur[i|$r]^$t;li=Ur[i|Jr]^Jt;ci=Ur[i|Kr]^Kt;hi=Ur[i|Qr]^Qt;pi=Ur[i|Gr]^Gt;di=Ur[i|Yr]^Yt;e=Ur[l|Zr]^Ur[a|ei]^Ur[f|ti]^Ur[u|ni];t=Ur[u|ci]^Ur[l|hi]^Ur[a|pi]^Ur[f|di];n=Ur[f|ui]^Ur[u|ai]^Ur[l|fi]^Ur[a|li];r=Ur[a|ri]^Ur[f|ii]^Ur[u|si]^Ur[l|oi];s=Ur[l|ri]^Ur[a|ii]^Ur[f|si]^Ur[u|oi];o=Ur[u|Zr]^Ur[l|ei]^Ur[a|ti]^Ur[f|ni];zr=Ur[f|ci]^Ur[u|hi]^Ur[l|pi]^Ur[a|di];Wr=Ur[a|ui]^Ur[f|ai]^Ur[u|fi]^Ur[l|li];Xr=Ur[l|ui]^Ur[a|ai]^Ur[f|fi]^Ur[u|li];Vr=Ur[u|ri]^Ur[l|ii]^Ur[a|si]^Ur[f|oi];$r=Ur[f|Zr]^Ur[u|ei]^Ur[l|ti]^Ur[a|ni];Jr=Ur[a|ci]^Ur[f|hi]^Ur[u|pi]^Ur[l|di];Kr=Ur[l|ci]^Ur[a|hi]^Ur[f|pi]^Ur[u|di];Qr=Ur[u|ui]^Ur[l|ai]^Ur[a|fi]^Ur[f|li];Gr=Ur[f|ri]^Ur[u|ii]^Ur[l|si]^Ur[a|oi];Yr=Ur[a|Zr]^Ur[f|ei]^Ur[u|ti]^Ur[l|ni];Zr=Ur[i|e]^Et;ei=Ur[i|t]^St;ti=Ur[i|n]^xt;ni=Ur[i|r]^Tt;ri=Ur[i|s]^Nt;ii=Ur[i|o]^Ct;si=Ur[i|zr]^kt;oi=Ur[i|Wr]^Lt;ui=Ur[i|Xr]^At;ai=Ur[i|Vr]^Ot;fi=Ur[i|$r]^Mt;li=Ur[i|Jr]^_t;ci=Ur[i|Kr]^Dt;hi=Ur[i|Qr]^Pt;pi=Ur[i|Gr]^Ht;di=Ur[i|Yr]^Bt;e=Ur[l|Zr]^Ur[a|ei]^Ur[f|ti]^Ur[u|ni];t=Ur[u|ci]^Ur[l|hi]^Ur[a|pi]^Ur[f|di];n=Ur[f|ui]^Ur[u|ai]^Ur[l|fi]^Ur[a|li];r=Ur[a|ri]^Ur[f|ii]^Ur[u|si]^Ur[l|oi];s=Ur[l|ri]^Ur[a|ii]^Ur[f|si]^Ur[u|oi];o=Ur[u|Zr]^Ur[l|ei]^Ur[a|ti]^Ur[f|ni];zr=Ur[f|ci]^Ur[u|hi]^Ur[l|pi]^Ur[a|di];Wr=Ur[a|ui]^Ur[f|ai]^Ur[u|fi]^Ur[l|li];Xr=Ur[l|ui]^Ur[a|ai]^Ur[f|fi]^Ur[u|li];Vr=Ur[u|ri]^Ur[l|ii]^Ur[a|si]^Ur[f|oi];$r=Ur[f|Zr]^Ur[u|ei]^Ur[l|ti]^Ur[a|ni];Jr=Ur[a|ci]^Ur[f|hi]^Ur[u|pi]^Ur[l|di];Kr=Ur[l|ci]^Ur[a|hi]^Ur[f|pi]^Ur[u|di];Qr=Ur[u|ui]^Ur[l|ai]^Ur[a|fi]^Ur[f|li];Gr=Ur[f|ri]^Ur[u|ii]^Ur[l|si]^Ur[a|oi];Yr=Ur[a|Zr]^Ur[f|ei]^Ur[u|ti]^Ur[l|ni];Zr=Ur[i|e]^st;ei=Ur[i|t]^ot;ti=Ur[i|n]^ut;ni=Ur[i|r]^at;ri=Ur[i|s]^ft;ii=Ur[i|o]^lt;si=Ur[i|zr]^ct;oi=Ur[i|Wr]^ht;ui=Ur[i|Xr]^pt;ai=Ur[i|Vr]^dt;fi=Ur[i|$r]^vt;li=Ur[i|Jr]^mt;ci=Ur[i|Kr]^gt;hi=Ur[i|Qr]^yt;pi=Ur[i|Gr]^bt;di=Ur[i|Yr]^wt;e=Ur[l|Zr]^Ur[a|ei]^Ur[f|ti]^Ur[u|ni];t=Ur[u|ci]^Ur[l|hi]^Ur[a|pi]^Ur[f|di];n=Ur[f|ui]^Ur[u|ai]^Ur[l|fi]^Ur[a|li];r=Ur[a|ri]^Ur[f|ii]^Ur[u|si]^Ur[l|oi];s=Ur[l|ri]^Ur[a|ii]^Ur[f|si]^Ur[u|oi];o=Ur[u|Zr]^Ur[l|ei]^Ur[a|ti]^Ur[f|ni];zr=Ur[f|ci]^Ur[u|hi]^Ur[l|pi]^Ur[a|di];Wr=Ur[a|ui]^Ur[f|ai]^Ur[u|fi]^Ur[l|li];Xr=Ur[l|ui]^Ur[a|ai]^Ur[f|fi]^Ur[u|li];Vr=Ur[u|ri]^Ur[l|ii]^Ur[a|si]^Ur[f|oi];$r=Ur[f|Zr]^Ur[u|ei]^Ur[l|ti]^Ur[a|ni];Jr=Ur[a|ci]^Ur[f|hi]^Ur[u|pi]^Ur[l|di];Kr=Ur[l|ci]^Ur[a|hi]^Ur[f|pi]^Ur[u|di];Qr=Ur[u|ui]^Ur[l|ai]^Ur[a|fi]^Ur[f|li];Gr=Ur[f|ri]^Ur[u|ii]^Ur[l|si]^Ur[a|oi];Yr=Ur[a|Zr]^Ur[f|ei]^Ur[u|ti]^Ur[l|ni];Zr=Ur[i|e]^z;ei=Ur[i|t]^W;ti=Ur[i|n]^X;ni=Ur[i|r]^V;ri=Ur[i|s]^$;ii=Ur[i|o]^J;si=Ur[i|zr]^K;oi=Ur[i|Wr]^Q;ui=Ur[i|Xr]^G;ai=Ur[i|Vr]^Y;fi=Ur[i|$r]^Z;li=Ur[i|Jr]^et;ci=Ur[i|Kr]^tt;hi=Ur[i|Qr]^nt;pi=Ur[i|Gr]^rt;di=Ur[i|Yr]^it;e=Ur[l|Zr]^Ur[a|ei]^Ur[f|ti]^Ur[u|ni];t=Ur[u|ci]^Ur[l|hi]^Ur[a|pi]^Ur[f|di];n=Ur[f|ui]^Ur[u|ai]^Ur[l|fi]^Ur[a|li];r=Ur[a|ri]^Ur[f|ii]^Ur[u|si]^Ur[l|oi];s=Ur[l|ri]^Ur[a|ii]^Ur[f|si]^Ur[u|oi];o=Ur[u|Zr]^Ur[l|ei]^Ur[a|ti]^Ur[f|ni];zr=Ur[f|ci]^Ur[u|hi]^Ur[l|pi]^Ur[a|di];Wr=Ur[a|ui]^Ur[f|ai]^Ur[u|fi]^Ur[l|li];Xr=Ur[l|ui]^Ur[a|ai]^Ur[f|fi]^Ur[u|li];Vr=Ur[u|ri]^Ur[l|ii]^Ur[a|si]^Ur[f|oi];$r=Ur[f|Zr]^Ur[u|ei]^Ur[l|ti]^Ur[a|ni];Jr=Ur[a|ci]^Ur[f|hi]^Ur[u|pi]^Ur[l|di];Kr=Ur[l|ci]^Ur[a|hi]^Ur[f|pi]^Ur[u|di];Qr=Ur[u|ui]^Ur[l|ai]^Ur[a|fi]^Ur[f|li];Gr=Ur[f|ri]^Ur[u|ii]^Ur[l|si]^Ur[a|oi];Yr=Ur[a|Zr]^Ur[f|ei]^Ur[u|ti]^Ur[l|ni];c=Ur[i|e]^k;h=Ur[i|t]^L;p=Ur[i|n]^A;d=Ur[i|r]^O;v=Ur[i|s]^M;m=Ur[i|o]^_;g=Ur[i|zr]^D;y=Ur[i|Wr]^P;b=Ur[i|Xr]^H;w=Ur[i|Vr]^B;E=Ur[i|$r]^j;S=Ur[i|Jr]^F;x=Ur[i|Kr]^I;T=Ur[i|Qr]^q;N=Ur[i|Gr]^R;C=Ur[i|Yr]^U}function Vr(e,t,n,r,i,s,o,u,a,f,l,k,L,A,O,M){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;s=s|0;o=o|0;u=u|0;a=a|0;f=f|0;l=l|0;k=k|0;L=L|0;A=A|0;O=O|0;M=M|0;c=e;h=t;p=n;d=r;v=i;m=s;g=o;y=u;b=a;w=f;E=l;S=k;x=L;T=A;N=O;C=M}function $r(e){e=e|0;Ur[e]=c;Ur[e|1]=h;Ur[e|2]=p;Ur[e|3]=d;Ur[e|4]=v;Ur[e|5]=m;Ur[e|6]=g;Ur[e|7]=y;Ur[e|8]=b;Ur[e|9]=w;Ur[e|10]=E;Ur[e|11]=S;Ur[e|12]=x;Ur[e|13]=T;Ur[e|14]=N;Ur[e|15]=C}function Jr(e,t,n,r,i,s,o,u,a,f,l,c,h,p,d,v){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;s=s|0;o=o|0;u=u|0;a=a|0;f=f|0;l=l|0;c=c|0;h=h|0;p=p|0;d=d|0;v=v|0;k=e;L=t;A=n;O=r;M=i;_=s;D=o;P=u;H=a;B=f;j=l;F=c;I=h;q=p;R=d;U=v;zr()}function Kr(e,t){e=e|0;t=t|0;if(e&15|t&15)return-1;while((t|0)>0){Wr(c^Ur[e],h^Ur[e|1],p^Ur[e|2],d^Ur[e|3],v^Ur[e|4],m^Ur[e|5],g^Ur[e|6],y^Ur[e|7],b^Ur[e|8],w^Ur[e|9],E^Ur[e|10],S^Ur[e|11],x^Ur[e|12],T^Ur[e|13],N^Ur[e|14],C^Ur[e|15]);Ur[e]=c;Ur[e|1]=h;Ur[e|2]=p;Ur[e|3]=d;Ur[e|4]=v;Ur[e|5]=m;Ur[e|6]=g;Ur[e|7]=y;Ur[e|8]=b;Ur[e|9]=w;Ur[e|10]=E;Ur[e|11]=S;Ur[e|12]=x;Ur[e|13]=T;Ur[e|14]=N;Ur[e|15]=C;e=e+16|0;t=t-16|0}}function Qr(e,t){e=e|0;t=t|0;var n=0,r=0,i=0,s=0,o=0,u=0,a=0,f=0,l=0,k=0,L=0,A=0,O=0,M=0,_=0,D=0;if(e&15|t&15)return-1;n=c;r=h;i=p;s=d;o=v;u=m;a=g;f=y;l=b;k=w;L=E;A=S;O=x;M=T;_=N;D=C;while((t|0)>0){Xr(Ur[e]|0,Ur[e|1]|0,Ur[e|2]|0,Ur[e|3]|0,Ur[e|4]|0,Ur[e|5]|0,Ur[e|6]|0,Ur[e|7]|0,Ur[e|8]|0,Ur[e|9]|0,Ur[e|10]|0,Ur[e|11]|0,Ur[e|12]|0,Ur[e|13]|0,Ur[e|14]|0,Ur[e|15]|0);c=c^n;n=Ur[e]|0;h=h^r;r=Ur[e|1]|0;p=p^i;i=Ur[e|2]|0;d=d^s;s=Ur[e|3]|0;v=v^o;o=Ur[e|4]|0;m=m^u;u=Ur[e|5]|0;g=g^a;a=Ur[e|6]|0;y=y^f;f=Ur[e|7]|0;b=b^l;l=Ur[e|8]|0;w=w^k;k=Ur[e|9]|0;E=E^L;L=Ur[e|10]|0;S=S^A;A=Ur[e|11]|0;x=x^O;O=Ur[e|12]|0;T=T^M;M=Ur[e|13]|0;N=N^_;_=Ur[e|14]|0;C=C^D;D=Ur[e|15]|0;Ur[e]=c;Ur[e|1]=h;Ur[e|2]=p;Ur[e|3]=d;Ur[e|4]=v;Ur[e|5]=m;Ur[e|6]=g;Ur[e|7]=y;Ur[e|8]=b;Ur[e|9]=w;Ur[e|10]=E;Ur[e|11]=S;Ur[e|12]=x;Ur[e|13]=T;Ur[e|14]=N;Ur[e|15]=C;e=e+16|0;t=t-16|0}c=n;h=r;p=i;d=s;v=o;m=u;g=a;y=f;b=l;w=k;E=L;S=A;x=O;T=M;N=_;C=D}function Gr(e,t,n){e=e|0;t=t|0;n=n|0;if(e&15)return-1;if(~n)if(n&31)return-1;while((t|0)>=16){Wr(c^Ur[e],h^Ur[e|1],p^Ur[e|2],d^Ur[e|3],v^Ur[e|4],m^Ur[e|5],g^Ur[e|6],y^Ur[e|7],b^Ur[e|8],w^Ur[e|9],E^Ur[e|10],S^Ur[e|11],x^Ur[e|12],T^Ur[e|13],N^Ur[e|14],C^Ur[e|15]);e=e+16|0;t=t-16|0}if((t|0)>0){c=c^Ur[e];if((t|0)>1)h=h^Ur[e|1];if((t|0)>2)p=p^Ur[e|2];if((t|0)>3)d=d^Ur[e|3];if((t|0)>4)v=v^Ur[e|4];if((t|0)>5)m=m^Ur[e|5];if((t|0)>6)g=g^Ur[e|6];if((t|0)>7)y=y^Ur[e|7];if((t|0)>8)b=b^Ur[e|8];if((t|0)>9)w=w^Ur[e|9];if((t|0)>10)E=E^Ur[e|10];if((t|0)>11)S=S^Ur[e|11];if((t|0)>12)x=x^Ur[e|12];if((t|0)>13)T=T^Ur[e|13];if((t|0)>14)N=N^Ur[e|14];Wr(c,h,p,d,v,m,g,y,b,w,E,S,x,T,N,C);e=e+t|0;t=0}if(~n){Ur[n|0]=c;Ur[n|1]=h;Ur[n|2]=p;Ur[n|3]=d;Ur[n|4]=v;Ur[n|5]=m;Ur[n|6]=g;Ur[n|7]=y;Ur[n|8]=b;Ur[n|9]=w;Ur[n|10]=E;Ur[n|11]=S;Ur[n|12]=x;Ur[n|13]=T;Ur[n|14]=N;Ur[n|15]=C}}function Yr(e,t,n,r,i,s,o,u,a,f,l,k,L,A,O,M,_){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;s=s|0;o=o|0;u=u|0;a=a|0;f=f|0;l=l|0;k=k|0;L=L|0;A=A|0;O=O|0;M=M|0;_=_|0;var D=0,P=0,H=0,B=0,j=0,F=0,I=0,q=0,R=0,U=0,z=0,W=0,X=0,V=0,$=0,J=0,K=0,Q=0,G=0,Y=0,Z=0,et=0,tt=0,nt=0,rt=0,it=0,st=0,ot=0,ut=0,at=0,ft=0,lt=0;if(e&15)return-1;D=c,P=h,H=p,B=d,j=v,F=m,I=g,q=y,R=b,U=w,z=E,W=S,X=x,V=T,$=N,J=C;while((t|0)>=16){K=Ur[e]|0;Q=Ur[e|1]|0;G=Ur[e|2]|0;Y=Ur[e|3]|0;Z=Ur[e|4]|0;et=Ur[e|5]|0;tt=Ur[e|6]|0;nt=Ur[e|7]|0;rt=Ur[e|8]|0;it=Ur[e|9]|0;st=Ur[e|10]|0;ot=Ur[e|11]|0;ut=Ur[e|12]|0;at=Ur[e|13]|0;ft=Ur[e|14]|0;lt=Ur[e|15]|0;Wr(n,r,i,s,o,u,a,f,l,k,L,A,O^_>>>24,M^_>>>16&255,_>>>8&255,_&255);Ur[e]=K^c;Ur[e|1]=Q^h;Ur[e|2]=G^p;Ur[e|3]=Y^d;Ur[e|4]=Z^v;Ur[e|5]=et^m;Ur[e|6]=tt^g;Ur[e|7]=nt^y;Ur[e|8]=rt^b;Ur[e|9]=it^w;Ur[e|10]=st^E;Ur[e|11]=ot^S;Ur[e|12]=ut^x;Ur[e|13]=at^T;Ur[e|14]=ft^N;Ur[e|15]=lt^C;Wr(K^D,Q^P,G^H,Y^B,Z^j,et^F,tt^I,nt^q,rt^R,it^U,st^z,ot^W,ut^X,at^V,ft^$,lt^J);D=c,P=h,H=p,B=d,j=v,F=m,I=g,q=y,R=b,U=w,z=E,W=S,X=x,V=T,$=N,J=C;e=e+16|0;t=t-16|0;_=_+1|0}if((t|0)>0){K=Ur[e]|0;Q=(t|0)>1?Ur[e|1]|0:0;G=(t|0)>2?Ur[e|2]|0:0;Y=(t|0)>3?Ur[e|3]|0:0;Z=(t|0)>4?Ur[e|4]|0:0;et=(t|0)>5?Ur[e|5]|0:0;tt=(t|0)>6?Ur[e|6]|0:0;nt=(t|0)>7?Ur[e|7]|0:0;rt=(t|0)>8?Ur[e|8]|0:0;it=(t|0)>9?Ur[e|9]|0:0;st=(t|0)>10?Ur[e|10]|0:0;ot=(t|0)>11?Ur[e|11]|0:0;ut=(t|0)>12?Ur[e|12]|0:0;at=(t|0)>13?Ur[e|13]|0:0;ft=(t|0)>14?Ur[e|14]|0:0;Wr(n,r,i,s,o,u,a,f,l,k,L,A,O^_>>>24,M^_>>>16&255,_>>>8&255,_&255);Ur[e]=K^c;if((t|0)>1)Ur[e|1]=Q^h;if((t|0)>2)Ur[e|2]=G^p;if((t|0)>3)Ur[e|3]=Y^d;if((t|0)>4)Ur[e|4]=Z^v;if((t|0)>5)Ur[e|5]=et^m;if((t|0)>6)Ur[e|6]=tt^g;if((t|0)>7)Ur[e|7]=nt^y;if((t|0)>8)Ur[e|8]=rt^b;if((t|0)>9)Ur[e|9]=it^w;if((t|0)>10)Ur[e|10]=st^E;if((t|0)>11)Ur[e|11]=ot^S;if((t|0)>12)Ur[e|12]=ut^x;if((t|0)>13)Ur[e|13]=at^T;if((t|0)>14)Ur[e|14]=ft^N;Wr(K^D,Q^P,G^H,Y^B,Z^j,et^F,tt^I,nt^q,rt^R,it^U,st^z,ot^W,ut^X,at^V,ft^$,J);D=c,P=h,H=p,B=d,j=v,F=m,I=g,q=y,R=b,U=w,z=E,W=S,X=x,V=T,$=N,J=C;e=e+t|0;t=0;_=_+1|0}}function Zr(e,t,n,r,i,s,o,u,a,f,l,k,L,A,O,M,_){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;s=s|0;o=o|0;u=u|0;a=a|0;f=f|0;l=l|0;k=k|0;L=L|0;A=A|0;O=O|0;M=M|0;_=_|0;var D=0,P=0,H=0,B=0,j=0,F=0,I=0,q=0,R=0,U=0,z=0,W=0,X=0,V=0,$=0,J=0,K=0,Q=0,G=0,Y=0,Z=0,et=0,tt=0,nt=0,rt=0,it=0,st=0,ot=0,ut=0,at=0,ft=0,lt=0;if(e&15)return-1;D=c,P=h,H=p,B=d,j=v,F=m,I=g,q=y,R=b,U=w,z=E,W=S,X=x,V=T,$=N,J=C;while((t|0)>=16){Wr(n,r,i,s,o,u,a,f,l,k,L,A,O^_>>>24,M^_>>>16&255,_>>>8&255,_&255);Ur[e]=K=Ur[e]^c;Ur[e|1]=Q=Ur[e|1]^h;Ur[e|2]=G=Ur[e|2]^p;Ur[e|3]=Y=Ur[e|3]^d;Ur[e|4]=Z=Ur[e|4]^v;Ur[e|5]=et=Ur[e|5]^m;Ur[e|6]=tt=Ur[e|6]^g;Ur[e|7]=nt=Ur[e|7]^y;Ur[e|8]=rt=Ur[e|8]^b;Ur[e|9]=it=Ur[e|9]^w;Ur[e|10]=st=Ur[e|10]^E;Ur[e|11]=ot=Ur[e|11]^S;Ur[e|12]=ut=Ur[e|12]^x;Ur[e|13]=at=Ur[e|13]^T;Ur[e|14]=ft=Ur[e|14]^N;Ur[e|15]=lt=Ur[e|15]^C;Wr(K^D,Q^P,G^H,Y^B,Z^j,et^F,tt^I,nt^q,rt^R,it^U,st^z,ot^W,ut^X,at^V,ft^$,lt^J);D=c,P=h,H=p,B=d,j=v,F=m,I=g,q=y,R=b,U=w,z=E,W=S,X=x,V=T,$=N,J=C;e=e+16|0;t=t-16|0;_=_+1|0}if((t|0)>0){Wr(n,r,i,s,o,u,a,f,l,k,L,A,O^_>>>24,M^_>>>16&255,_>>>8&255,_&255);K=Ur[e]^c;Q=(t|0)>1?Ur[e|1]^h:0;G=(t|0)>2?Ur[e|2]^p:0;Y=(t|0)>3?Ur[e|3]^d:0;Z=(t|0)>4?Ur[e|4]^v:0;et=(t|0)>5?Ur[e|5]^m:0;tt=(t|0)>6?Ur[e|6]^g:0;nt=(t|0)>7?Ur[e|7]^y:0;rt=(t|0)>8?Ur[e|8]^b:0;it=(t|0)>9?Ur[e|9]^w:0;st=(t|0)>10?Ur[e|10]^E:0;ot=(t|0)>11?Ur[e|11]^S:0;ut=(t|0)>12?Ur[e|12]^x:0;at=(t|0)>13?Ur[e|13]^T:0;ft=(t|0)>14?Ur[e|14]^N:0;lt=(t|0)>15?Ur[e|15]^C:0;Ur[e]=K;if((t|0)>1)Ur[e|1]=Q;if((t|0)>2)Ur[e|2]=G;if((t|0)>3)Ur[e|3]=Y;if((t|0)>4)Ur[e|4]=Z;if((t|0)>5)Ur[e|5]=et;if((t|0)>6)Ur[e|6]=tt;if((t|0)>7)Ur[e|7]=nt;if((t|0)>8)Ur[e|8]=rt;if((t|0)>9)Ur[e|9]=it;if((t|0)>10)Ur[e|10]=st;if((t|0)>11)Ur[e|11]=ot;if((t|0)>12)Ur[e|12]=ut;if((t|0)>13)Ur[e|13]=at;if((t|0)>14)Ur[e|14]=ft;Wr(K^D,Q^P,G^H,Y^B,Z^j,et^F,tt^I,nt^q,rt^R,it^U,st^z,ot^W,ut^X,at^V,ft^$,lt^J);D=c,P=h,H=p,B=d,j=v,F=m,I=g,q=y,R=b,U=w,z=E,W=S,X=x,V=T,$=N,J=C;e=e+16|0;t=t-16|0;_=_+1|0}}return{init_state:Vr,save_state:$r,init_key_128:Jr,cbc_encrypt:Kr,cbc_decrypt:Qr,cbc_mac:Gr,ccm_encrypt:Yr,ccm_decrypt:Zr}'))( stdlib, foreign, buffer );
}
