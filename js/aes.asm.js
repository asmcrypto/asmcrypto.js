/*
function aes_asm ( stdlib, foreign, buffer ) {
    "use asm";

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
        var sbox = 0;

        // key 1
        R10 = R00 ^ HEAP[sbox|R0D] ^ 0x01;
        R11 = R01 ^ HEAP[sbox|R0E];
        R12 = R02 ^ HEAP[sbox|R0F];
        R13 = R03 ^ HEAP[sbox|R0C];
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
        R20 = R10 ^ HEAP[sbox|R1D] ^ 0x02;
        R21 = R11 ^ HEAP[sbox|R1E];
        R22 = R12 ^ HEAP[sbox|R1F];
        R23 = R13 ^ HEAP[sbox|R1C];
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
        R30 = R20 ^ HEAP[sbox|R2D] ^ 0x04;
        R31 = R21 ^ HEAP[sbox|R2E];
        R32 = R22 ^ HEAP[sbox|R2F];
        R33 = R23 ^ HEAP[sbox|R2C];
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
        R40 = R30 ^ HEAP[sbox|R3D] ^ 0x08;
        R41 = R31 ^ HEAP[sbox|R3E];
        R42 = R32 ^ HEAP[sbox|R3F];
        R43 = R33 ^ HEAP[sbox|R3C];
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
        R50 = R40 ^ HEAP[sbox|R4D] ^ 0x10;
        R51 = R41 ^ HEAP[sbox|R4E];
        R52 = R42 ^ HEAP[sbox|R4F];
        R53 = R43 ^ HEAP[sbox|R4C];
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
        R60 = R50 ^ HEAP[sbox|R5D] ^ 0x20;
        R61 = R51 ^ HEAP[sbox|R5E];
        R62 = R52 ^ HEAP[sbox|R5F];
        R63 = R53 ^ HEAP[sbox|R5C];
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
        R70 = R60 ^ HEAP[sbox|R6D] ^ 0x40;
        R71 = R61 ^ HEAP[sbox|R6E];
        R72 = R62 ^ HEAP[sbox|R6F];
        R73 = R63 ^ HEAP[sbox|R6C];
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
        R80 = R70 ^ HEAP[sbox|R7D] ^ 0x80;
        R81 = R71 ^ HEAP[sbox|R7E];
        R82 = R72 ^ HEAP[sbox|R7F];
        R83 = R73 ^ HEAP[sbox|R7C];
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
        R90 = R80 ^ HEAP[sbox|R8D] ^ 0x1b;
        R91 = R81 ^ HEAP[sbox|R8E];
        R92 = R82 ^ HEAP[sbox|R8F];
        R93 = R83 ^ HEAP[sbox|R8C];
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
        RA0 = R90 ^ HEAP[sbox|R9D] ^ 0x36;
        RA1 = R91 ^ HEAP[sbox|R9E];
        RA2 = R92 ^ HEAP[sbox|R9F];
        RA3 = R93 ^ HEAP[sbox|R9C];
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

        var t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, t8 = 0, t9 = 0, tA = 0, tB = 0, tC = 0, tD = 0, tE = 0, tF = 0,
            sbox = 0, x2_sbox = 0x200, x3_sbox = 0x300;

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
        t0 = HEAP[x2_sbox|s0] ^ HEAP[x3_sbox|s5] ^ HEAP[sbox|sA] ^ HEAP[sbox|sF] ^ R10;
        t1 = HEAP[sbox|s0] ^ HEAP[x2_sbox|s5] ^ HEAP[x3_sbox|sA] ^ HEAP[sbox|sF] ^ R11;
        t2 = HEAP[sbox|s0] ^ HEAP[sbox|s5] ^ HEAP[x2_sbox|sA] ^ HEAP[x3_sbox|sF] ^ R12;
        t3 = HEAP[x3_sbox|s0] ^ HEAP[sbox|s5] ^ HEAP[sbox|sA] ^ HEAP[x2_sbox|sF] ^ R13;
        t4 = HEAP[x2_sbox|s4] ^ HEAP[x3_sbox|s9] ^ HEAP[sbox|sE] ^ HEAP[sbox|s3] ^ R14;
        t5 = HEAP[sbox|s4] ^ HEAP[x2_sbox|s9] ^ HEAP[x3_sbox|sE] ^ HEAP[sbox|s3] ^ R15;
        t6 = HEAP[sbox|s4] ^ HEAP[sbox|s9] ^ HEAP[x2_sbox|sE] ^ HEAP[x3_sbox|s3] ^ R16;
        t7 = HEAP[x3_sbox|s4] ^ HEAP[sbox|s9] ^ HEAP[sbox|sE] ^ HEAP[x2_sbox|s3] ^ R17;
        t8 = HEAP[x2_sbox|s8] ^ HEAP[x3_sbox|sD] ^ HEAP[sbox|s2] ^ HEAP[sbox|s7] ^ R18;
        t9 = HEAP[sbox|s8] ^ HEAP[x2_sbox|sD] ^ HEAP[x3_sbox|s2] ^ HEAP[sbox|s7] ^ R19;
        tA = HEAP[sbox|s8] ^ HEAP[sbox|sD] ^ HEAP[x2_sbox|s2] ^ HEAP[x3_sbox|s7] ^ R1A;
        tB = HEAP[x3_sbox|s8] ^ HEAP[sbox|sD] ^ HEAP[sbox|s2] ^ HEAP[x2_sbox|s7] ^ R1B;
        tC = HEAP[x2_sbox|sC] ^ HEAP[x3_sbox|s1] ^ HEAP[sbox|s6] ^ HEAP[sbox|sB] ^ R1C;
        tD = HEAP[sbox|sC] ^ HEAP[x2_sbox|s1] ^ HEAP[x3_sbox|s6] ^ HEAP[sbox|sB] ^ R1D;
        tE = HEAP[sbox|sC] ^ HEAP[sbox|s1] ^ HEAP[x2_sbox|s6] ^ HEAP[x3_sbox|sB] ^ R1E;
        tF = HEAP[x3_sbox|sC] ^ HEAP[sbox|s1] ^ HEAP[sbox|s6] ^ HEAP[x2_sbox|sB] ^ R1F;

        // round 2
        s0 = HEAP[x2_sbox|t0] ^ HEAP[x3_sbox|t5] ^ HEAP[sbox|tA] ^ HEAP[sbox|tF] ^ R20;
        s1 = HEAP[sbox|t0] ^ HEAP[x2_sbox|t5] ^ HEAP[x3_sbox|tA] ^ HEAP[sbox|tF] ^ R21;
        s2 = HEAP[sbox|t0] ^ HEAP[sbox|t5] ^ HEAP[x2_sbox|tA] ^ HEAP[x3_sbox|tF] ^ R22;
        s3 = HEAP[x3_sbox|t0] ^ HEAP[sbox|t5] ^ HEAP[sbox|tA] ^ HEAP[x2_sbox|tF] ^ R23;
        s4 = HEAP[x2_sbox|t4] ^ HEAP[x3_sbox|t9] ^ HEAP[sbox|tE] ^ HEAP[sbox|t3] ^ R24;
        s5 = HEAP[sbox|t4] ^ HEAP[x2_sbox|t9] ^ HEAP[x3_sbox|tE] ^ HEAP[sbox|t3] ^ R25;
        s6 = HEAP[sbox|t4] ^ HEAP[sbox|t9] ^ HEAP[x2_sbox|tE] ^ HEAP[x3_sbox|t3] ^ R26;
        s7 = HEAP[x3_sbox|t4] ^ HEAP[sbox|t9] ^ HEAP[sbox|tE] ^ HEAP[x2_sbox|t3] ^ R27;
        s8 = HEAP[x2_sbox|t8] ^ HEAP[x3_sbox|tD] ^ HEAP[sbox|t2] ^ HEAP[sbox|t7] ^ R28;
        s9 = HEAP[sbox|t8] ^ HEAP[x2_sbox|tD] ^ HEAP[x3_sbox|t2] ^ HEAP[sbox|t7] ^ R29;
        sA = HEAP[sbox|t8] ^ HEAP[sbox|tD] ^ HEAP[x2_sbox|t2] ^ HEAP[x3_sbox|t7] ^ R2A;
        sB = HEAP[x3_sbox|t8] ^ HEAP[sbox|tD] ^ HEAP[sbox|t2] ^ HEAP[x2_sbox|t7] ^ R2B;
        sC = HEAP[x2_sbox|tC] ^ HEAP[x3_sbox|t1] ^ HEAP[sbox|t6] ^ HEAP[sbox|tB] ^ R2C;
        sD = HEAP[sbox|tC] ^ HEAP[x2_sbox|t1] ^ HEAP[x3_sbox|t6] ^ HEAP[sbox|tB] ^ R2D;
        sE = HEAP[sbox|tC] ^ HEAP[sbox|t1] ^ HEAP[x2_sbox|t6] ^ HEAP[x3_sbox|tB] ^ R2E;
        sF = HEAP[x3_sbox|tC] ^ HEAP[sbox|t1] ^ HEAP[sbox|t6] ^ HEAP[x2_sbox|tB] ^ R2F;

        // round 3
        t0 = HEAP[x2_sbox|s0] ^ HEAP[x3_sbox|s5] ^ HEAP[sbox|sA] ^ HEAP[sbox|sF] ^ R30;
        t1 = HEAP[sbox|s0] ^ HEAP[x2_sbox|s5] ^ HEAP[x3_sbox|sA] ^ HEAP[sbox|sF] ^ R31;
        t2 = HEAP[sbox|s0] ^ HEAP[sbox|s5] ^ HEAP[x2_sbox|sA] ^ HEAP[x3_sbox|sF] ^ R32;
        t3 = HEAP[x3_sbox|s0] ^ HEAP[sbox|s5] ^ HEAP[sbox|sA] ^ HEAP[x2_sbox|sF] ^ R33;
        t4 = HEAP[x2_sbox|s4] ^ HEAP[x3_sbox|s9] ^ HEAP[sbox|sE] ^ HEAP[sbox|s3] ^ R34;
        t5 = HEAP[sbox|s4] ^ HEAP[x2_sbox|s9] ^ HEAP[x3_sbox|sE] ^ HEAP[sbox|s3] ^ R35;
        t6 = HEAP[sbox|s4] ^ HEAP[sbox|s9] ^ HEAP[x2_sbox|sE] ^ HEAP[x3_sbox|s3] ^ R36;
        t7 = HEAP[x3_sbox|s4] ^ HEAP[sbox|s9] ^ HEAP[sbox|sE] ^ HEAP[x2_sbox|s3] ^ R37;
        t8 = HEAP[x2_sbox|s8] ^ HEAP[x3_sbox|sD] ^ HEAP[sbox|s2] ^ HEAP[sbox|s7] ^ R38;
        t9 = HEAP[sbox|s8] ^ HEAP[x2_sbox|sD] ^ HEAP[x3_sbox|s2] ^ HEAP[sbox|s7] ^ R39;
        tA = HEAP[sbox|s8] ^ HEAP[sbox|sD] ^ HEAP[x2_sbox|s2] ^ HEAP[x3_sbox|s7] ^ R3A;
        tB = HEAP[x3_sbox|s8] ^ HEAP[sbox|sD] ^ HEAP[sbox|s2] ^ HEAP[x2_sbox|s7] ^ R3B;
        tC = HEAP[x2_sbox|sC] ^ HEAP[x3_sbox|s1] ^ HEAP[sbox|s6] ^ HEAP[sbox|sB] ^ R3C;
        tD = HEAP[sbox|sC] ^ HEAP[x2_sbox|s1] ^ HEAP[x3_sbox|s6] ^ HEAP[sbox|sB] ^ R3D;
        tE = HEAP[sbox|sC] ^ HEAP[sbox|s1] ^ HEAP[x2_sbox|s6] ^ HEAP[x3_sbox|sB] ^ R3E;
        tF = HEAP[x3_sbox|sC] ^ HEAP[sbox|s1] ^ HEAP[sbox|s6] ^ HEAP[x2_sbox|sB] ^ R3F;

        // round 4
        s0 = HEAP[x2_sbox|t0] ^ HEAP[x3_sbox|t5] ^ HEAP[sbox|tA] ^ HEAP[sbox|tF] ^ R40;
        s1 = HEAP[sbox|t0] ^ HEAP[x2_sbox|t5] ^ HEAP[x3_sbox|tA] ^ HEAP[sbox|tF] ^ R41;
        s2 = HEAP[sbox|t0] ^ HEAP[sbox|t5] ^ HEAP[x2_sbox|tA] ^ HEAP[x3_sbox|tF] ^ R42;
        s3 = HEAP[x3_sbox|t0] ^ HEAP[sbox|t5] ^ HEAP[sbox|tA] ^ HEAP[x2_sbox|tF] ^ R43;
        s4 = HEAP[x2_sbox|t4] ^ HEAP[x3_sbox|t9] ^ HEAP[sbox|tE] ^ HEAP[sbox|t3] ^ R44;
        s5 = HEAP[sbox|t4] ^ HEAP[x2_sbox|t9] ^ HEAP[x3_sbox|tE] ^ HEAP[sbox|t3] ^ R45;
        s6 = HEAP[sbox|t4] ^ HEAP[sbox|t9] ^ HEAP[x2_sbox|tE] ^ HEAP[x3_sbox|t3] ^ R46;
        s7 = HEAP[x3_sbox|t4] ^ HEAP[sbox|t9] ^ HEAP[sbox|tE] ^ HEAP[x2_sbox|t3] ^ R47;
        s8 = HEAP[x2_sbox|t8] ^ HEAP[x3_sbox|tD] ^ HEAP[sbox|t2] ^ HEAP[sbox|t7] ^ R48;
        s9 = HEAP[sbox|t8] ^ HEAP[x2_sbox|tD] ^ HEAP[x3_sbox|t2] ^ HEAP[sbox|t7] ^ R49;
        sA = HEAP[sbox|t8] ^ HEAP[sbox|tD] ^ HEAP[x2_sbox|t2] ^ HEAP[x3_sbox|t7] ^ R4A;
        sB = HEAP[x3_sbox|t8] ^ HEAP[sbox|tD] ^ HEAP[sbox|t2] ^ HEAP[x2_sbox|t7] ^ R4B;
        sC = HEAP[x2_sbox|tC] ^ HEAP[x3_sbox|t1] ^ HEAP[sbox|t6] ^ HEAP[sbox|tB] ^ R4C;
        sD = HEAP[sbox|tC] ^ HEAP[x2_sbox|t1] ^ HEAP[x3_sbox|t6] ^ HEAP[sbox|tB] ^ R4D;
        sE = HEAP[sbox|tC] ^ HEAP[sbox|t1] ^ HEAP[x2_sbox|t6] ^ HEAP[x3_sbox|tB] ^ R4E;
        sF = HEAP[x3_sbox|tC] ^ HEAP[sbox|t1] ^ HEAP[sbox|t6] ^ HEAP[x2_sbox|tB] ^ R4F;

        // round 5
        t0 = HEAP[x2_sbox|s0] ^ HEAP[x3_sbox|s5] ^ HEAP[sbox|sA] ^ HEAP[sbox|sF] ^ R50;
        t1 = HEAP[sbox|s0] ^ HEAP[x2_sbox|s5] ^ HEAP[x3_sbox|sA] ^ HEAP[sbox|sF] ^ R51;
        t2 = HEAP[sbox|s0] ^ HEAP[sbox|s5] ^ HEAP[x2_sbox|sA] ^ HEAP[x3_sbox|sF] ^ R52;
        t3 = HEAP[x3_sbox|s0] ^ HEAP[sbox|s5] ^ HEAP[sbox|sA] ^ HEAP[x2_sbox|sF] ^ R53;
        t4 = HEAP[x2_sbox|s4] ^ HEAP[x3_sbox|s9] ^ HEAP[sbox|sE] ^ HEAP[sbox|s3] ^ R54;
        t5 = HEAP[sbox|s4] ^ HEAP[x2_sbox|s9] ^ HEAP[x3_sbox|sE] ^ HEAP[sbox|s3] ^ R55;
        t6 = HEAP[sbox|s4] ^ HEAP[sbox|s9] ^ HEAP[x2_sbox|sE] ^ HEAP[x3_sbox|s3] ^ R56;
        t7 = HEAP[x3_sbox|s4] ^ HEAP[sbox|s9] ^ HEAP[sbox|sE] ^ HEAP[x2_sbox|s3] ^ R57;
        t8 = HEAP[x2_sbox|s8] ^ HEAP[x3_sbox|sD] ^ HEAP[sbox|s2] ^ HEAP[sbox|s7] ^ R58;
        t9 = HEAP[sbox|s8] ^ HEAP[x2_sbox|sD] ^ HEAP[x3_sbox|s2] ^ HEAP[sbox|s7] ^ R59;
        tA = HEAP[sbox|s8] ^ HEAP[sbox|sD] ^ HEAP[x2_sbox|s2] ^ HEAP[x3_sbox|s7] ^ R5A;
        tB = HEAP[x3_sbox|s8] ^ HEAP[sbox|sD] ^ HEAP[sbox|s2] ^ HEAP[x2_sbox|s7] ^ R5B;
        tC = HEAP[x2_sbox|sC] ^ HEAP[x3_sbox|s1] ^ HEAP[sbox|s6] ^ HEAP[sbox|sB] ^ R5C;
        tD = HEAP[sbox|sC] ^ HEAP[x2_sbox|s1] ^ HEAP[x3_sbox|s6] ^ HEAP[sbox|sB] ^ R5D;
        tE = HEAP[sbox|sC] ^ HEAP[sbox|s1] ^ HEAP[x2_sbox|s6] ^ HEAP[x3_sbox|sB] ^ R5E;
        tF = HEAP[x3_sbox|sC] ^ HEAP[sbox|s1] ^ HEAP[sbox|s6] ^ HEAP[x2_sbox|sB] ^ R5F;

        // round 6
        s0 = HEAP[x2_sbox|t0] ^ HEAP[x3_sbox|t5] ^ HEAP[sbox|tA] ^ HEAP[sbox|tF] ^ R60;
        s1 = HEAP[sbox|t0] ^ HEAP[x2_sbox|t5] ^ HEAP[x3_sbox|tA] ^ HEAP[sbox|tF] ^ R61;
        s2 = HEAP[sbox|t0] ^ HEAP[sbox|t5] ^ HEAP[x2_sbox|tA] ^ HEAP[x3_sbox|tF] ^ R62;
        s3 = HEAP[x3_sbox|t0] ^ HEAP[sbox|t5] ^ HEAP[sbox|tA] ^ HEAP[x2_sbox|tF] ^ R63;
        s4 = HEAP[x2_sbox|t4] ^ HEAP[x3_sbox|t9] ^ HEAP[sbox|tE] ^ HEAP[sbox|t3] ^ R64;
        s5 = HEAP[sbox|t4] ^ HEAP[x2_sbox|t9] ^ HEAP[x3_sbox|tE] ^ HEAP[sbox|t3] ^ R65;
        s6 = HEAP[sbox|t4] ^ HEAP[sbox|t9] ^ HEAP[x2_sbox|tE] ^ HEAP[x3_sbox|t3] ^ R66;
        s7 = HEAP[x3_sbox|t4] ^ HEAP[sbox|t9] ^ HEAP[sbox|tE] ^ HEAP[x2_sbox|t3] ^ R67;
        s8 = HEAP[x2_sbox|t8] ^ HEAP[x3_sbox|tD] ^ HEAP[sbox|t2] ^ HEAP[sbox|t7] ^ R68;
        s9 = HEAP[sbox|t8] ^ HEAP[x2_sbox|tD] ^ HEAP[x3_sbox|t2] ^ HEAP[sbox|t7] ^ R69;
        sA = HEAP[sbox|t8] ^ HEAP[sbox|tD] ^ HEAP[x2_sbox|t2] ^ HEAP[x3_sbox|t7] ^ R6A;
        sB = HEAP[x3_sbox|t8] ^ HEAP[sbox|tD] ^ HEAP[sbox|t2] ^ HEAP[x2_sbox|t7] ^ R6B;
        sC = HEAP[x2_sbox|tC] ^ HEAP[x3_sbox|t1] ^ HEAP[sbox|t6] ^ HEAP[sbox|tB] ^ R6C;
        sD = HEAP[sbox|tC] ^ HEAP[x2_sbox|t1] ^ HEAP[x3_sbox|t6] ^ HEAP[sbox|tB] ^ R6D;
        sE = HEAP[sbox|tC] ^ HEAP[sbox|t1] ^ HEAP[x2_sbox|t6] ^ HEAP[x3_sbox|tB] ^ R6E;
        sF = HEAP[x3_sbox|tC] ^ HEAP[sbox|t1] ^ HEAP[sbox|t6] ^ HEAP[x2_sbox|tB] ^ R6F;

        // round 7
        t0 = HEAP[x2_sbox|s0] ^ HEAP[x3_sbox|s5] ^ HEAP[sbox|sA] ^ HEAP[sbox|sF] ^ R70;
        t1 = HEAP[sbox|s0] ^ HEAP[x2_sbox|s5] ^ HEAP[x3_sbox|sA] ^ HEAP[sbox|sF] ^ R71;
        t2 = HEAP[sbox|s0] ^ HEAP[sbox|s5] ^ HEAP[x2_sbox|sA] ^ HEAP[x3_sbox|sF] ^ R72;
        t3 = HEAP[x3_sbox|s0] ^ HEAP[sbox|s5] ^ HEAP[sbox|sA] ^ HEAP[x2_sbox|sF] ^ R73;
        t4 = HEAP[x2_sbox|s4] ^ HEAP[x3_sbox|s9] ^ HEAP[sbox|sE] ^ HEAP[sbox|s3] ^ R74;
        t5 = HEAP[sbox|s4] ^ HEAP[x2_sbox|s9] ^ HEAP[x3_sbox|sE] ^ HEAP[sbox|s3] ^ R75;
        t6 = HEAP[sbox|s4] ^ HEAP[sbox|s9] ^ HEAP[x2_sbox|sE] ^ HEAP[x3_sbox|s3] ^ R76;
        t7 = HEAP[x3_sbox|s4] ^ HEAP[sbox|s9] ^ HEAP[sbox|sE] ^ HEAP[x2_sbox|s3] ^ R77;
        t8 = HEAP[x2_sbox|s8] ^ HEAP[x3_sbox|sD] ^ HEAP[sbox|s2] ^ HEAP[sbox|s7] ^ R78;
        t9 = HEAP[sbox|s8] ^ HEAP[x2_sbox|sD] ^ HEAP[x3_sbox|s2] ^ HEAP[sbox|s7] ^ R79;
        tA = HEAP[sbox|s8] ^ HEAP[sbox|sD] ^ HEAP[x2_sbox|s2] ^ HEAP[x3_sbox|s7] ^ R7A;
        tB = HEAP[x3_sbox|s8] ^ HEAP[sbox|sD] ^ HEAP[sbox|s2] ^ HEAP[x2_sbox|s7] ^ R7B;
        tC = HEAP[x2_sbox|sC] ^ HEAP[x3_sbox|s1] ^ HEAP[sbox|s6] ^ HEAP[sbox|sB] ^ R7C;
        tD = HEAP[sbox|sC] ^ HEAP[x2_sbox|s1] ^ HEAP[x3_sbox|s6] ^ HEAP[sbox|sB] ^ R7D;
        tE = HEAP[sbox|sC] ^ HEAP[sbox|s1] ^ HEAP[x2_sbox|s6] ^ HEAP[x3_sbox|sB] ^ R7E;
        tF = HEAP[x3_sbox|sC] ^ HEAP[sbox|s1] ^ HEAP[sbox|s6] ^ HEAP[x2_sbox|sB] ^ R7F;

        // round 8
        s0 = HEAP[x2_sbox|t0] ^ HEAP[x3_sbox|t5] ^ HEAP[sbox|tA] ^ HEAP[sbox|tF] ^ R80;
        s1 = HEAP[sbox|t0] ^ HEAP[x2_sbox|t5] ^ HEAP[x3_sbox|tA] ^ HEAP[sbox|tF] ^ R81;
        s2 = HEAP[sbox|t0] ^ HEAP[sbox|t5] ^ HEAP[x2_sbox|tA] ^ HEAP[x3_sbox|tF] ^ R82;
        s3 = HEAP[x3_sbox|t0] ^ HEAP[sbox|t5] ^ HEAP[sbox|tA] ^ HEAP[x2_sbox|tF] ^ R83;
        s4 = HEAP[x2_sbox|t4] ^ HEAP[x3_sbox|t9] ^ HEAP[sbox|tE] ^ HEAP[sbox|t3] ^ R84;
        s5 = HEAP[sbox|t4] ^ HEAP[x2_sbox|t9] ^ HEAP[x3_sbox|tE] ^ HEAP[sbox|t3] ^ R85;
        s6 = HEAP[sbox|t4] ^ HEAP[sbox|t9] ^ HEAP[x2_sbox|tE] ^ HEAP[x3_sbox|t3] ^ R86;
        s7 = HEAP[x3_sbox|t4] ^ HEAP[sbox|t9] ^ HEAP[sbox|tE] ^ HEAP[x2_sbox|t3] ^ R87;
        s8 = HEAP[x2_sbox|t8] ^ HEAP[x3_sbox|tD] ^ HEAP[sbox|t2] ^ HEAP[sbox|t7] ^ R88;
        s9 = HEAP[sbox|t8] ^ HEAP[x2_sbox|tD] ^ HEAP[x3_sbox|t2] ^ HEAP[sbox|t7] ^ R89;
        sA = HEAP[sbox|t8] ^ HEAP[sbox|tD] ^ HEAP[x2_sbox|t2] ^ HEAP[x3_sbox|t7] ^ R8A;
        sB = HEAP[x3_sbox|t8] ^ HEAP[sbox|tD] ^ HEAP[sbox|t2] ^ HEAP[x2_sbox|t7] ^ R8B;
        sC = HEAP[x2_sbox|tC] ^ HEAP[x3_sbox|t1] ^ HEAP[sbox|t6] ^ HEAP[sbox|tB] ^ R8C;
        sD = HEAP[sbox|tC] ^ HEAP[x2_sbox|t1] ^ HEAP[x3_sbox|t6] ^ HEAP[sbox|tB] ^ R8D;
        sE = HEAP[sbox|tC] ^ HEAP[sbox|t1] ^ HEAP[x2_sbox|t6] ^ HEAP[x3_sbox|tB] ^ R8E;
        sF = HEAP[x3_sbox|tC] ^ HEAP[sbox|t1] ^ HEAP[sbox|t6] ^ HEAP[x2_sbox|tB] ^ R8F;

        // round 9
        t0 = HEAP[x2_sbox|s0] ^ HEAP[x3_sbox|s5] ^ HEAP[sbox|sA] ^ HEAP[sbox|sF] ^ R90;
        t1 = HEAP[sbox|s0] ^ HEAP[x2_sbox|s5] ^ HEAP[x3_sbox|sA] ^ HEAP[sbox|sF] ^ R91;
        t2 = HEAP[sbox|s0] ^ HEAP[sbox|s5] ^ HEAP[x2_sbox|sA] ^ HEAP[x3_sbox|sF] ^ R92;
        t3 = HEAP[x3_sbox|s0] ^ HEAP[sbox|s5] ^ HEAP[sbox|sA] ^ HEAP[x2_sbox|sF] ^ R93;
        t4 = HEAP[x2_sbox|s4] ^ HEAP[x3_sbox|s9] ^ HEAP[sbox|sE] ^ HEAP[sbox|s3] ^ R94;
        t5 = HEAP[sbox|s4] ^ HEAP[x2_sbox|s9] ^ HEAP[x3_sbox|sE] ^ HEAP[sbox|s3] ^ R95;
        t6 = HEAP[sbox|s4] ^ HEAP[sbox|s9] ^ HEAP[x2_sbox|sE] ^ HEAP[x3_sbox|s3] ^ R96;
        t7 = HEAP[x3_sbox|s4] ^ HEAP[sbox|s9] ^ HEAP[sbox|sE] ^ HEAP[x2_sbox|s3] ^ R97;
        t8 = HEAP[x2_sbox|s8] ^ HEAP[x3_sbox|sD] ^ HEAP[sbox|s2] ^ HEAP[sbox|s7] ^ R98;
        t9 = HEAP[sbox|s8] ^ HEAP[x2_sbox|sD] ^ HEAP[x3_sbox|s2] ^ HEAP[sbox|s7] ^ R99;
        tA = HEAP[sbox|s8] ^ HEAP[sbox|sD] ^ HEAP[x2_sbox|s2] ^ HEAP[x3_sbox|s7] ^ R9A;
        tB = HEAP[x3_sbox|s8] ^ HEAP[sbox|sD] ^ HEAP[sbox|s2] ^ HEAP[x2_sbox|s7] ^ R9B;
        tC = HEAP[x2_sbox|sC] ^ HEAP[x3_sbox|s1] ^ HEAP[sbox|s6] ^ HEAP[sbox|sB] ^ R9C;
        tD = HEAP[sbox|sC] ^ HEAP[x2_sbox|s1] ^ HEAP[x3_sbox|s6] ^ HEAP[sbox|sB] ^ R9D;
        tE = HEAP[sbox|sC] ^ HEAP[sbox|s1] ^ HEAP[x2_sbox|s6] ^ HEAP[x3_sbox|sB] ^ R9E;
        tF = HEAP[x3_sbox|sC] ^ HEAP[sbox|s1] ^ HEAP[sbox|s6] ^ HEAP[x2_sbox|sB] ^ R9F;

        // round 10
        S0 = HEAP[sbox|t0] ^ RA0;
        S1 = HEAP[sbox|t5] ^ RA1;
        S2 = HEAP[sbox|tA] ^ RA2;
        S3 = HEAP[sbox|tF] ^ RA3;
        S4 = HEAP[sbox|t4] ^ RA4;
        S5 = HEAP[sbox|t9] ^ RA5;
        S6 = HEAP[sbox|tE] ^ RA6;
        S7 = HEAP[sbox|t3] ^ RA7;
        S8 = HEAP[sbox|t8] ^ RA8;
        S9 = HEAP[sbox|tD] ^ RA9;
        SA = HEAP[sbox|t2] ^ RAA;
        SB = HEAP[sbox|t7] ^ RAB;
        SC = HEAP[sbox|tC] ^ RAC;
        SD = HEAP[sbox|t1] ^ RAD;
        SE = HEAP[sbox|t6] ^ RAE;
        SF = HEAP[sbox|tB] ^ RAF;
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

        var t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, t8 = 0, t9 = 0, tA = 0, tB = 0, tC = 0, tD = 0, tE = 0, tF = 0,
            inv_sbox = 0x100, x9 = 0x400, xB = 0x500, xD = 0x600, xE = 0x700;

        // round 10+9
        t0 = HEAP[inv_sbox|(s0 ^ RA0)] ^ R90;
        t1 = HEAP[inv_sbox|(sD ^ RAD)] ^ R91;
        t2 = HEAP[inv_sbox|(sA ^ RAA)] ^ R92;
        t3 = HEAP[inv_sbox|(s7 ^ RA7)] ^ R93;
        t4 = HEAP[inv_sbox|(s4 ^ RA4)] ^ R94;
        t5 = HEAP[inv_sbox|(s1 ^ RA1)] ^ R95;
        t6 = HEAP[inv_sbox|(sE ^ RAE)] ^ R96;
        t7 = HEAP[inv_sbox|(sB ^ RAB)] ^ R97;
        t8 = HEAP[inv_sbox|(s8 ^ RA8)] ^ R98;
        t9 = HEAP[inv_sbox|(s5 ^ RA5)] ^ R99;
        tA = HEAP[inv_sbox|(s2 ^ RA2)] ^ R9A;
        tB = HEAP[inv_sbox|(sF ^ RAF)] ^ R9B;
        tC = HEAP[inv_sbox|(sC ^ RAC)] ^ R9C;
        tD = HEAP[inv_sbox|(s9 ^ RA9)] ^ R9D;
        tE = HEAP[inv_sbox|(s6 ^ RA6)] ^ R9E;
        tF = HEAP[inv_sbox|(s3 ^ RA3)] ^ R9F;
        s0 = HEAP[xE|t0] ^ HEAP[xB|t1] ^ HEAP[xD|t2] ^ HEAP[x9|t3];
        s1 = HEAP[x9|tC] ^ HEAP[xE|tD] ^ HEAP[xB|tE] ^ HEAP[xD|tF];
        s2 = HEAP[xD|t8] ^ HEAP[x9|t9] ^ HEAP[xE|tA] ^ HEAP[xB|tB];
        s3 = HEAP[xB|t4] ^ HEAP[xD|t5] ^ HEAP[x9|t6] ^ HEAP[xE|t7];
        s4 = HEAP[xE|t4] ^ HEAP[xB|t5] ^ HEAP[xD|t6] ^ HEAP[x9|t7];
        s5 = HEAP[x9|t0] ^ HEAP[xE|t1] ^ HEAP[xB|t2] ^ HEAP[xD|t3];
        s6 = HEAP[xD|tC] ^ HEAP[x9|tD] ^ HEAP[xE|tE] ^ HEAP[xB|tF];
        s7 = HEAP[xB|t8] ^ HEAP[xD|t9] ^ HEAP[x9|tA] ^ HEAP[xE|tB];
        s8 = HEAP[xE|t8] ^ HEAP[xB|t9] ^ HEAP[xD|tA] ^ HEAP[x9|tB];
        s9 = HEAP[x9|t4] ^ HEAP[xE|t5] ^ HEAP[xB|t6] ^ HEAP[xD|t7];
        sA = HEAP[xD|t0] ^ HEAP[x9|t1] ^ HEAP[xE|t2] ^ HEAP[xB|t3];
        sB = HEAP[xB|tC] ^ HEAP[xD|tD] ^ HEAP[x9|tE] ^ HEAP[xE|tF];
        sC = HEAP[xE|tC] ^ HEAP[xB|tD] ^ HEAP[xD|tE] ^ HEAP[x9|tF];
        sD = HEAP[x9|t8] ^ HEAP[xE|t9] ^ HEAP[xB|tA] ^ HEAP[xD|tB];
        sE = HEAP[xD|t4] ^ HEAP[x9|t5] ^ HEAP[xE|t6] ^ HEAP[xB|t7];
        sF = HEAP[xB|t0] ^ HEAP[xD|t1] ^ HEAP[x9|t2] ^ HEAP[xE|t3];

        // round 8
        t0 = HEAP[inv_sbox|s0] ^ R80;
        t1 = HEAP[inv_sbox|s1] ^ R81;
        t2 = HEAP[inv_sbox|s2] ^ R82;
        t3 = HEAP[inv_sbox|s3] ^ R83;
        t4 = HEAP[inv_sbox|s4] ^ R84;
        t5 = HEAP[inv_sbox|s5] ^ R85;
        t6 = HEAP[inv_sbox|s6] ^ R86;
        t7 = HEAP[inv_sbox|s7] ^ R87;
        t8 = HEAP[inv_sbox|s8] ^ R88;
        t9 = HEAP[inv_sbox|s9] ^ R89;
        tA = HEAP[inv_sbox|sA] ^ R8A;
        tB = HEAP[inv_sbox|sB] ^ R8B;
        tC = HEAP[inv_sbox|sC] ^ R8C;
        tD = HEAP[inv_sbox|sD] ^ R8D;
        tE = HEAP[inv_sbox|sE] ^ R8E;
        tF = HEAP[inv_sbox|sF] ^ R8F;
        s0 = HEAP[xE|t0] ^ HEAP[xB|t1] ^ HEAP[xD|t2] ^ HEAP[x9|t3];
        s1 = HEAP[x9|tC] ^ HEAP[xE|tD] ^ HEAP[xB|tE] ^ HEAP[xD|tF];
        s2 = HEAP[xD|t8] ^ HEAP[x9|t9] ^ HEAP[xE|tA] ^ HEAP[xB|tB];
        s3 = HEAP[xB|t4] ^ HEAP[xD|t5] ^ HEAP[x9|t6] ^ HEAP[xE|t7];
        s4 = HEAP[xE|t4] ^ HEAP[xB|t5] ^ HEAP[xD|t6] ^ HEAP[x9|t7];
        s5 = HEAP[x9|t0] ^ HEAP[xE|t1] ^ HEAP[xB|t2] ^ HEAP[xD|t3];
        s6 = HEAP[xD|tC] ^ HEAP[x9|tD] ^ HEAP[xE|tE] ^ HEAP[xB|tF];
        s7 = HEAP[xB|t8] ^ HEAP[xD|t9] ^ HEAP[x9|tA] ^ HEAP[xE|tB];
        s8 = HEAP[xE|t8] ^ HEAP[xB|t9] ^ HEAP[xD|tA] ^ HEAP[x9|tB];
        s9 = HEAP[x9|t4] ^ HEAP[xE|t5] ^ HEAP[xB|t6] ^ HEAP[xD|t7];
        sA = HEAP[xD|t0] ^ HEAP[x9|t1] ^ HEAP[xE|t2] ^ HEAP[xB|t3];
        sB = HEAP[xB|tC] ^ HEAP[xD|tD] ^ HEAP[x9|tE] ^ HEAP[xE|tF];
        sC = HEAP[xE|tC] ^ HEAP[xB|tD] ^ HEAP[xD|tE] ^ HEAP[x9|tF];
        sD = HEAP[x9|t8] ^ HEAP[xE|t9] ^ HEAP[xB|tA] ^ HEAP[xD|tB];
        sE = HEAP[xD|t4] ^ HEAP[x9|t5] ^ HEAP[xE|t6] ^ HEAP[xB|t7];
        sF = HEAP[xB|t0] ^ HEAP[xD|t1] ^ HEAP[x9|t2] ^ HEAP[xE|t3];

        // round 7
        t0 = HEAP[inv_sbox|s0] ^ R70;
        t1 = HEAP[inv_sbox|s1] ^ R71;
        t2 = HEAP[inv_sbox|s2] ^ R72;
        t3 = HEAP[inv_sbox|s3] ^ R73;
        t4 = HEAP[inv_sbox|s4] ^ R74;
        t5 = HEAP[inv_sbox|s5] ^ R75;
        t6 = HEAP[inv_sbox|s6] ^ R76;
        t7 = HEAP[inv_sbox|s7] ^ R77;
        t8 = HEAP[inv_sbox|s8] ^ R78;
        t9 = HEAP[inv_sbox|s9] ^ R79;
        tA = HEAP[inv_sbox|sA] ^ R7A;
        tB = HEAP[inv_sbox|sB] ^ R7B;
        tC = HEAP[inv_sbox|sC] ^ R7C;
        tD = HEAP[inv_sbox|sD] ^ R7D;
        tE = HEAP[inv_sbox|sE] ^ R7E;
        tF = HEAP[inv_sbox|sF] ^ R7F;
        s0 = HEAP[xE|t0] ^ HEAP[xB|t1] ^ HEAP[xD|t2] ^ HEAP[x9|t3];
        s1 = HEAP[x9|tC] ^ HEAP[xE|tD] ^ HEAP[xB|tE] ^ HEAP[xD|tF];
        s2 = HEAP[xD|t8] ^ HEAP[x9|t9] ^ HEAP[xE|tA] ^ HEAP[xB|tB];
        s3 = HEAP[xB|t4] ^ HEAP[xD|t5] ^ HEAP[x9|t6] ^ HEAP[xE|t7];
        s4 = HEAP[xE|t4] ^ HEAP[xB|t5] ^ HEAP[xD|t6] ^ HEAP[x9|t7];
        s5 = HEAP[x9|t0] ^ HEAP[xE|t1] ^ HEAP[xB|t2] ^ HEAP[xD|t3];
        s6 = HEAP[xD|tC] ^ HEAP[x9|tD] ^ HEAP[xE|tE] ^ HEAP[xB|tF];
        s7 = HEAP[xB|t8] ^ HEAP[xD|t9] ^ HEAP[x9|tA] ^ HEAP[xE|tB];
        s8 = HEAP[xE|t8] ^ HEAP[xB|t9] ^ HEAP[xD|tA] ^ HEAP[x9|tB];
        s9 = HEAP[x9|t4] ^ HEAP[xE|t5] ^ HEAP[xB|t6] ^ HEAP[xD|t7];
        sA = HEAP[xD|t0] ^ HEAP[x9|t1] ^ HEAP[xE|t2] ^ HEAP[xB|t3];
        sB = HEAP[xB|tC] ^ HEAP[xD|tD] ^ HEAP[x9|tE] ^ HEAP[xE|tF];
        sC = HEAP[xE|tC] ^ HEAP[xB|tD] ^ HEAP[xD|tE] ^ HEAP[x9|tF];
        sD = HEAP[x9|t8] ^ HEAP[xE|t9] ^ HEAP[xB|tA] ^ HEAP[xD|tB];
        sE = HEAP[xD|t4] ^ HEAP[x9|t5] ^ HEAP[xE|t6] ^ HEAP[xB|t7];
        sF = HEAP[xB|t0] ^ HEAP[xD|t1] ^ HEAP[x9|t2] ^ HEAP[xE|t3];

        // round 6
        t0 = HEAP[inv_sbox|s0] ^ R60;
        t1 = HEAP[inv_sbox|s1] ^ R61;
        t2 = HEAP[inv_sbox|s2] ^ R62;
        t3 = HEAP[inv_sbox|s3] ^ R63;
        t4 = HEAP[inv_sbox|s4] ^ R64;
        t5 = HEAP[inv_sbox|s5] ^ R65;
        t6 = HEAP[inv_sbox|s6] ^ R66;
        t7 = HEAP[inv_sbox|s7] ^ R67;
        t8 = HEAP[inv_sbox|s8] ^ R68;
        t9 = HEAP[inv_sbox|s9] ^ R69;
        tA = HEAP[inv_sbox|sA] ^ R6A;
        tB = HEAP[inv_sbox|sB] ^ R6B;
        tC = HEAP[inv_sbox|sC] ^ R6C;
        tD = HEAP[inv_sbox|sD] ^ R6D;
        tE = HEAP[inv_sbox|sE] ^ R6E;
        tF = HEAP[inv_sbox|sF] ^ R6F;
        s0 = HEAP[xE|t0] ^ HEAP[xB|t1] ^ HEAP[xD|t2] ^ HEAP[x9|t3];
        s1 = HEAP[x9|tC] ^ HEAP[xE|tD] ^ HEAP[xB|tE] ^ HEAP[xD|tF];
        s2 = HEAP[xD|t8] ^ HEAP[x9|t9] ^ HEAP[xE|tA] ^ HEAP[xB|tB];
        s3 = HEAP[xB|t4] ^ HEAP[xD|t5] ^ HEAP[x9|t6] ^ HEAP[xE|t7];
        s4 = HEAP[xE|t4] ^ HEAP[xB|t5] ^ HEAP[xD|t6] ^ HEAP[x9|t7];
        s5 = HEAP[x9|t0] ^ HEAP[xE|t1] ^ HEAP[xB|t2] ^ HEAP[xD|t3];
        s6 = HEAP[xD|tC] ^ HEAP[x9|tD] ^ HEAP[xE|tE] ^ HEAP[xB|tF];
        s7 = HEAP[xB|t8] ^ HEAP[xD|t9] ^ HEAP[x9|tA] ^ HEAP[xE|tB];
        s8 = HEAP[xE|t8] ^ HEAP[xB|t9] ^ HEAP[xD|tA] ^ HEAP[x9|tB];
        s9 = HEAP[x9|t4] ^ HEAP[xE|t5] ^ HEAP[xB|t6] ^ HEAP[xD|t7];
        sA = HEAP[xD|t0] ^ HEAP[x9|t1] ^ HEAP[xE|t2] ^ HEAP[xB|t3];
        sB = HEAP[xB|tC] ^ HEAP[xD|tD] ^ HEAP[x9|tE] ^ HEAP[xE|tF];
        sC = HEAP[xE|tC] ^ HEAP[xB|tD] ^ HEAP[xD|tE] ^ HEAP[x9|tF];
        sD = HEAP[x9|t8] ^ HEAP[xE|t9] ^ HEAP[xB|tA] ^ HEAP[xD|tB];
        sE = HEAP[xD|t4] ^ HEAP[x9|t5] ^ HEAP[xE|t6] ^ HEAP[xB|t7];
        sF = HEAP[xB|t0] ^ HEAP[xD|t1] ^ HEAP[x9|t2] ^ HEAP[xE|t3];

        // round 5
        t0 = HEAP[inv_sbox|s0] ^ R50;
        t1 = HEAP[inv_sbox|s1] ^ R51;
        t2 = HEAP[inv_sbox|s2] ^ R52;
        t3 = HEAP[inv_sbox|s3] ^ R53;
        t4 = HEAP[inv_sbox|s4] ^ R54;
        t5 = HEAP[inv_sbox|s5] ^ R55;
        t6 = HEAP[inv_sbox|s6] ^ R56;
        t7 = HEAP[inv_sbox|s7] ^ R57;
        t8 = HEAP[inv_sbox|s8] ^ R58;
        t9 = HEAP[inv_sbox|s9] ^ R59;
        tA = HEAP[inv_sbox|sA] ^ R5A;
        tB = HEAP[inv_sbox|sB] ^ R5B;
        tC = HEAP[inv_sbox|sC] ^ R5C;
        tD = HEAP[inv_sbox|sD] ^ R5D;
        tE = HEAP[inv_sbox|sE] ^ R5E;
        tF = HEAP[inv_sbox|sF] ^ R5F;
        s0 = HEAP[xE|t0] ^ HEAP[xB|t1] ^ HEAP[xD|t2] ^ HEAP[x9|t3];
        s1 = HEAP[x9|tC] ^ HEAP[xE|tD] ^ HEAP[xB|tE] ^ HEAP[xD|tF];
        s2 = HEAP[xD|t8] ^ HEAP[x9|t9] ^ HEAP[xE|tA] ^ HEAP[xB|tB];
        s3 = HEAP[xB|t4] ^ HEAP[xD|t5] ^ HEAP[x9|t6] ^ HEAP[xE|t7];
        s4 = HEAP[xE|t4] ^ HEAP[xB|t5] ^ HEAP[xD|t6] ^ HEAP[x9|t7];
        s5 = HEAP[x9|t0] ^ HEAP[xE|t1] ^ HEAP[xB|t2] ^ HEAP[xD|t3];
        s6 = HEAP[xD|tC] ^ HEAP[x9|tD] ^ HEAP[xE|tE] ^ HEAP[xB|tF];
        s7 = HEAP[xB|t8] ^ HEAP[xD|t9] ^ HEAP[x9|tA] ^ HEAP[xE|tB];
        s8 = HEAP[xE|t8] ^ HEAP[xB|t9] ^ HEAP[xD|tA] ^ HEAP[x9|tB];
        s9 = HEAP[x9|t4] ^ HEAP[xE|t5] ^ HEAP[xB|t6] ^ HEAP[xD|t7];
        sA = HEAP[xD|t0] ^ HEAP[x9|t1] ^ HEAP[xE|t2] ^ HEAP[xB|t3];
        sB = HEAP[xB|tC] ^ HEAP[xD|tD] ^ HEAP[x9|tE] ^ HEAP[xE|tF];
        sC = HEAP[xE|tC] ^ HEAP[xB|tD] ^ HEAP[xD|tE] ^ HEAP[x9|tF];
        sD = HEAP[x9|t8] ^ HEAP[xE|t9] ^ HEAP[xB|tA] ^ HEAP[xD|tB];
        sE = HEAP[xD|t4] ^ HEAP[x9|t5] ^ HEAP[xE|t6] ^ HEAP[xB|t7];
        sF = HEAP[xB|t0] ^ HEAP[xD|t1] ^ HEAP[x9|t2] ^ HEAP[xE|t3];

        // round 4
        t0 = HEAP[inv_sbox|s0] ^ R40;
        t1 = HEAP[inv_sbox|s1] ^ R41;
        t2 = HEAP[inv_sbox|s2] ^ R42;
        t3 = HEAP[inv_sbox|s3] ^ R43;
        t4 = HEAP[inv_sbox|s4] ^ R44;
        t5 = HEAP[inv_sbox|s5] ^ R45;
        t6 = HEAP[inv_sbox|s6] ^ R46;
        t7 = HEAP[inv_sbox|s7] ^ R47;
        t8 = HEAP[inv_sbox|s8] ^ R48;
        t9 = HEAP[inv_sbox|s9] ^ R49;
        tA = HEAP[inv_sbox|sA] ^ R4A;
        tB = HEAP[inv_sbox|sB] ^ R4B;
        tC = HEAP[inv_sbox|sC] ^ R4C;
        tD = HEAP[inv_sbox|sD] ^ R4D;
        tE = HEAP[inv_sbox|sE] ^ R4E;
        tF = HEAP[inv_sbox|sF] ^ R4F;
        s0 = HEAP[xE|t0] ^ HEAP[xB|t1] ^ HEAP[xD|t2] ^ HEAP[x9|t3];
        s1 = HEAP[x9|tC] ^ HEAP[xE|tD] ^ HEAP[xB|tE] ^ HEAP[xD|tF];
        s2 = HEAP[xD|t8] ^ HEAP[x9|t9] ^ HEAP[xE|tA] ^ HEAP[xB|tB];
        s3 = HEAP[xB|t4] ^ HEAP[xD|t5] ^ HEAP[x9|t6] ^ HEAP[xE|t7];
        s4 = HEAP[xE|t4] ^ HEAP[xB|t5] ^ HEAP[xD|t6] ^ HEAP[x9|t7];
        s5 = HEAP[x9|t0] ^ HEAP[xE|t1] ^ HEAP[xB|t2] ^ HEAP[xD|t3];
        s6 = HEAP[xD|tC] ^ HEAP[x9|tD] ^ HEAP[xE|tE] ^ HEAP[xB|tF];
        s7 = HEAP[xB|t8] ^ HEAP[xD|t9] ^ HEAP[x9|tA] ^ HEAP[xE|tB];
        s8 = HEAP[xE|t8] ^ HEAP[xB|t9] ^ HEAP[xD|tA] ^ HEAP[x9|tB];
        s9 = HEAP[x9|t4] ^ HEAP[xE|t5] ^ HEAP[xB|t6] ^ HEAP[xD|t7];
        sA = HEAP[xD|t0] ^ HEAP[x9|t1] ^ HEAP[xE|t2] ^ HEAP[xB|t3];
        sB = HEAP[xB|tC] ^ HEAP[xD|tD] ^ HEAP[x9|tE] ^ HEAP[xE|tF];
        sC = HEAP[xE|tC] ^ HEAP[xB|tD] ^ HEAP[xD|tE] ^ HEAP[x9|tF];
        sD = HEAP[x9|t8] ^ HEAP[xE|t9] ^ HEAP[xB|tA] ^ HEAP[xD|tB];
        sE = HEAP[xD|t4] ^ HEAP[x9|t5] ^ HEAP[xE|t6] ^ HEAP[xB|t7];
        sF = HEAP[xB|t0] ^ HEAP[xD|t1] ^ HEAP[x9|t2] ^ HEAP[xE|t3];

        // round 3
        t0 = HEAP[inv_sbox|s0] ^ R30;
        t1 = HEAP[inv_sbox|s1] ^ R31;
        t2 = HEAP[inv_sbox|s2] ^ R32;
        t3 = HEAP[inv_sbox|s3] ^ R33;
        t4 = HEAP[inv_sbox|s4] ^ R34;
        t5 = HEAP[inv_sbox|s5] ^ R35;
        t6 = HEAP[inv_sbox|s6] ^ R36;
        t7 = HEAP[inv_sbox|s7] ^ R37;
        t8 = HEAP[inv_sbox|s8] ^ R38;
        t9 = HEAP[inv_sbox|s9] ^ R39;
        tA = HEAP[inv_sbox|sA] ^ R3A;
        tB = HEAP[inv_sbox|sB] ^ R3B;
        tC = HEAP[inv_sbox|sC] ^ R3C;
        tD = HEAP[inv_sbox|sD] ^ R3D;
        tE = HEAP[inv_sbox|sE] ^ R3E;
        tF = HEAP[inv_sbox|sF] ^ R3F;
        s0 = HEAP[xE|t0] ^ HEAP[xB|t1] ^ HEAP[xD|t2] ^ HEAP[x9|t3];
        s1 = HEAP[x9|tC] ^ HEAP[xE|tD] ^ HEAP[xB|tE] ^ HEAP[xD|tF];
        s2 = HEAP[xD|t8] ^ HEAP[x9|t9] ^ HEAP[xE|tA] ^ HEAP[xB|tB];
        s3 = HEAP[xB|t4] ^ HEAP[xD|t5] ^ HEAP[x9|t6] ^ HEAP[xE|t7];
        s4 = HEAP[xE|t4] ^ HEAP[xB|t5] ^ HEAP[xD|t6] ^ HEAP[x9|t7];
        s5 = HEAP[x9|t0] ^ HEAP[xE|t1] ^ HEAP[xB|t2] ^ HEAP[xD|t3];
        s6 = HEAP[xD|tC] ^ HEAP[x9|tD] ^ HEAP[xE|tE] ^ HEAP[xB|tF];
        s7 = HEAP[xB|t8] ^ HEAP[xD|t9] ^ HEAP[x9|tA] ^ HEAP[xE|tB];
        s8 = HEAP[xE|t8] ^ HEAP[xB|t9] ^ HEAP[xD|tA] ^ HEAP[x9|tB];
        s9 = HEAP[x9|t4] ^ HEAP[xE|t5] ^ HEAP[xB|t6] ^ HEAP[xD|t7];
        sA = HEAP[xD|t0] ^ HEAP[x9|t1] ^ HEAP[xE|t2] ^ HEAP[xB|t3];
        sB = HEAP[xB|tC] ^ HEAP[xD|tD] ^ HEAP[x9|tE] ^ HEAP[xE|tF];
        sC = HEAP[xE|tC] ^ HEAP[xB|tD] ^ HEAP[xD|tE] ^ HEAP[x9|tF];
        sD = HEAP[x9|t8] ^ HEAP[xE|t9] ^ HEAP[xB|tA] ^ HEAP[xD|tB];
        sE = HEAP[xD|t4] ^ HEAP[x9|t5] ^ HEAP[xE|t6] ^ HEAP[xB|t7];
        sF = HEAP[xB|t0] ^ HEAP[xD|t1] ^ HEAP[x9|t2] ^ HEAP[xE|t3];

        // round 2
        t0 = HEAP[inv_sbox|s0] ^ R20;
        t1 = HEAP[inv_sbox|s1] ^ R21;
        t2 = HEAP[inv_sbox|s2] ^ R22;
        t3 = HEAP[inv_sbox|s3] ^ R23;
        t4 = HEAP[inv_sbox|s4] ^ R24;
        t5 = HEAP[inv_sbox|s5] ^ R25;
        t6 = HEAP[inv_sbox|s6] ^ R26;
        t7 = HEAP[inv_sbox|s7] ^ R27;
        t8 = HEAP[inv_sbox|s8] ^ R28;
        t9 = HEAP[inv_sbox|s9] ^ R29;
        tA = HEAP[inv_sbox|sA] ^ R2A;
        tB = HEAP[inv_sbox|sB] ^ R2B;
        tC = HEAP[inv_sbox|sC] ^ R2C;
        tD = HEAP[inv_sbox|sD] ^ R2D;
        tE = HEAP[inv_sbox|sE] ^ R2E;
        tF = HEAP[inv_sbox|sF] ^ R2F;
        s0 = HEAP[xE|t0] ^ HEAP[xB|t1] ^ HEAP[xD|t2] ^ HEAP[x9|t3];
        s1 = HEAP[x9|tC] ^ HEAP[xE|tD] ^ HEAP[xB|tE] ^ HEAP[xD|tF];
        s2 = HEAP[xD|t8] ^ HEAP[x9|t9] ^ HEAP[xE|tA] ^ HEAP[xB|tB];
        s3 = HEAP[xB|t4] ^ HEAP[xD|t5] ^ HEAP[x9|t6] ^ HEAP[xE|t7];
        s4 = HEAP[xE|t4] ^ HEAP[xB|t5] ^ HEAP[xD|t6] ^ HEAP[x9|t7];
        s5 = HEAP[x9|t0] ^ HEAP[xE|t1] ^ HEAP[xB|t2] ^ HEAP[xD|t3];
        s6 = HEAP[xD|tC] ^ HEAP[x9|tD] ^ HEAP[xE|tE] ^ HEAP[xB|tF];
        s7 = HEAP[xB|t8] ^ HEAP[xD|t9] ^ HEAP[x9|tA] ^ HEAP[xE|tB];
        s8 = HEAP[xE|t8] ^ HEAP[xB|t9] ^ HEAP[xD|tA] ^ HEAP[x9|tB];
        s9 = HEAP[x9|t4] ^ HEAP[xE|t5] ^ HEAP[xB|t6] ^ HEAP[xD|t7];
        sA = HEAP[xD|t0] ^ HEAP[x9|t1] ^ HEAP[xE|t2] ^ HEAP[xB|t3];
        sB = HEAP[xB|tC] ^ HEAP[xD|tD] ^ HEAP[x9|tE] ^ HEAP[xE|tF];
        sC = HEAP[xE|tC] ^ HEAP[xB|tD] ^ HEAP[xD|tE] ^ HEAP[x9|tF];
        sD = HEAP[x9|t8] ^ HEAP[xE|t9] ^ HEAP[xB|tA] ^ HEAP[xD|tB];
        sE = HEAP[xD|t4] ^ HEAP[x9|t5] ^ HEAP[xE|t6] ^ HEAP[xB|t7];
        sF = HEAP[xB|t0] ^ HEAP[xD|t1] ^ HEAP[x9|t2] ^ HEAP[xE|t3];

        // round 1
        t0 = HEAP[inv_sbox|s0] ^ R10;
        t1 = HEAP[inv_sbox|s1] ^ R11;
        t2 = HEAP[inv_sbox|s2] ^ R12;
        t3 = HEAP[inv_sbox|s3] ^ R13;
        t4 = HEAP[inv_sbox|s4] ^ R14;
        t5 = HEAP[inv_sbox|s5] ^ R15;
        t6 = HEAP[inv_sbox|s6] ^ R16;
        t7 = HEAP[inv_sbox|s7] ^ R17;
        t8 = HEAP[inv_sbox|s8] ^ R18;
        t9 = HEAP[inv_sbox|s9] ^ R19;
        tA = HEAP[inv_sbox|sA] ^ R1A;
        tB = HEAP[inv_sbox|sB] ^ R1B;
        tC = HEAP[inv_sbox|sC] ^ R1C;
        tD = HEAP[inv_sbox|sD] ^ R1D;
        tE = HEAP[inv_sbox|sE] ^ R1E;
        tF = HEAP[inv_sbox|sF] ^ R1F;
        s0 = HEAP[xE|t0] ^ HEAP[xB|t1] ^ HEAP[xD|t2] ^ HEAP[x9|t3];
        s1 = HEAP[x9|tC] ^ HEAP[xE|tD] ^ HEAP[xB|tE] ^ HEAP[xD|tF];
        s2 = HEAP[xD|t8] ^ HEAP[x9|t9] ^ HEAP[xE|tA] ^ HEAP[xB|tB];
        s3 = HEAP[xB|t4] ^ HEAP[xD|t5] ^ HEAP[x9|t6] ^ HEAP[xE|t7];
        s4 = HEAP[xE|t4] ^ HEAP[xB|t5] ^ HEAP[xD|t6] ^ HEAP[x9|t7];
        s5 = HEAP[x9|t0] ^ HEAP[xE|t1] ^ HEAP[xB|t2] ^ HEAP[xD|t3];
        s6 = HEAP[xD|tC] ^ HEAP[x9|tD] ^ HEAP[xE|tE] ^ HEAP[xB|tF];
        s7 = HEAP[xB|t8] ^ HEAP[xD|t9] ^ HEAP[x9|tA] ^ HEAP[xE|tB];
        s8 = HEAP[xE|t8] ^ HEAP[xB|t9] ^ HEAP[xD|tA] ^ HEAP[x9|tB];
        s9 = HEAP[x9|t4] ^ HEAP[xE|t5] ^ HEAP[xB|t6] ^ HEAP[xD|t7];
        sA = HEAP[xD|t0] ^ HEAP[x9|t1] ^ HEAP[xE|t2] ^ HEAP[xB|t3];
        sB = HEAP[xB|tC] ^ HEAP[xD|tD] ^ HEAP[x9|tE] ^ HEAP[xE|tF];
        sC = HEAP[xE|tC] ^ HEAP[xB|tD] ^ HEAP[xD|tE] ^ HEAP[x9|tF];
        sD = HEAP[x9|t8] ^ HEAP[xE|t9] ^ HEAP[xB|tA] ^ HEAP[xD|tB];
        sE = HEAP[xD|t4] ^ HEAP[x9|t5] ^ HEAP[xE|t6] ^ HEAP[xB|t7];
        sF = HEAP[xB|t0] ^ HEAP[xD|t1] ^ HEAP[x9|t2] ^ HEAP[xE|t3];

        // round 0
        S0 = HEAP[inv_sbox|s0] ^ R00;
        S1 = HEAP[inv_sbox|s1] ^ R01;
        S2 = HEAP[inv_sbox|s2] ^ R02;
        S3 = HEAP[inv_sbox|s3] ^ R03;
        S4 = HEAP[inv_sbox|s4] ^ R04;
        S5 = HEAP[inv_sbox|s5] ^ R05;
        S6 = HEAP[inv_sbox|s6] ^ R06;
        S7 = HEAP[inv_sbox|s7] ^ R07;
        S8 = HEAP[inv_sbox|s8] ^ R08;
        S9 = HEAP[inv_sbox|s9] ^ R09;
        SA = HEAP[inv_sbox|sA] ^ R0A;
        SB = HEAP[inv_sbox|sB] ^ R0B;
        SC = HEAP[inv_sbox|sC] ^ R0C;
        SD = HEAP[inv_sbox|sD] ^ R0D;
        SE = HEAP[inv_sbox|sE] ^ R0E;
        SF = HEAP[inv_sbox|sF] ^ R0F;
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

        return 0;
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

        return 0;
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

        return 0;
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

        return 0;
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

        return 0;
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
    return (new Function('e,t,n','"use asm";var r=0,i=0,s=0,o=0,u=0,a=0,f=0,l=0,c=0,h=0,p=0,d=0,v=0,m=0,g=0,y=0,b=0,w=0,E=0,S=0,x=0,T=0,N=0,C=0,k=0,L=0,A=0,O=0,M=0,_=0,D=0,P=0,H=0,B=0,j=0,F=0,I=0,q=0,R=0,U=0,z=0,W=0,X=0,V=0,$=0,J=0,K=0,Q=0,G=0,Y=0,Z=0,et=0,tt=0,nt=0,rt=0,it=0,st=0,ot=0,ut=0,at=0,ft=0,lt=0,ct=0,ht=0,pt=0,dt=0,vt=0,mt=0,gt=0,yt=0,bt=0,wt=0,Et=0,St=0,xt=0,Tt=0,Nt=0,Ct=0,kt=0,Lt=0,At=0,Ot=0,Mt=0,_t=0,Dt=0,Pt=0,Ht=0,Bt=0,jt=0,Ft=0,It=0,qt=0,Rt=0,Ut=0,zt=0,Wt=0,Xt=0,Vt=0,$t=0,Jt=0,Kt=0,Qt=0,Gt=0,Yt=0,Zt=0,en=0,tn=0,nn=0,rn=0,sn=0,on=0,un=0,an=0,fn=0,ln=0,cn=0,hn=0,pn=0,dn=0,vn=0,mn=0,gn=0,yn=0,bn=0,wn=0,En=0,Sn=0,xn=0,Tn=0,Nn=0,Cn=0,kn=0,Ln=0,An=0,On=0,Mn=0,_n=0,Dn=0,Pn=0,Hn=0,Bn=0,jn=0,Fn=0,In=0,qn=0,Rn=0,Un=0,zn=0,Wn=0,Xn=0,Vn=0,$n=0,Jn=0,Kn=0,Qn=0,Gn=0,Yn=0,Zn=0,er=0,tr=0,nr=0,rr=0,ir=0,sr=0,or=0,ur=0,ar=0,fr=0,lr=0,cr=0,hr=0,pr=0,dr=0,vr=0,mr=0,gr=0,yr=0,br=0,wr=0,Er=0,Sr=0,xr=0,Tr=0,Nr=0,Cr=0,kr=0,Lr=0,Ar=0,Or=0,Mr=0,_r=0,Dr=0;var Pr=new e.Uint8Array(n);function Hr(){var e=0;H=b^Pr[e|_]^1;B=w^Pr[e|D];j=E^Pr[e|P];F=S^Pr[e|M];I=x^H;q=T^B;R=N^j;U=C^F;z=k^I;W=L^q;X=A^R;V=O^U;$=M^z;J=_^W;K=D^X;Q=P^V;G=H^Pr[e|J]^2;Y=B^Pr[e|K];Z=j^Pr[e|Q];et=F^Pr[e|$];tt=I^G;nt=q^Y;rt=R^Z;it=U^et;st=z^tt;ot=W^nt;ut=X^rt;at=V^it;ft=$^st;lt=J^ot;ct=K^ut;ht=Q^at;pt=G^Pr[e|lt]^4;dt=Y^Pr[e|ct];vt=Z^Pr[e|ht];mt=et^Pr[e|ft];gt=tt^pt;yt=nt^dt;bt=rt^vt;wt=it^mt;Et=st^gt;St=ot^yt;xt=ut^bt;Tt=at^wt;Nt=ft^Et;Ct=lt^St;kt=ct^xt;Lt=ht^Tt;At=pt^Pr[e|Ct]^8;Ot=dt^Pr[e|kt];Mt=vt^Pr[e|Lt];_t=mt^Pr[e|Nt];Dt=gt^At;Pt=yt^Ot;Ht=bt^Mt;Bt=wt^_t;jt=Et^Dt;Ft=St^Pt;It=xt^Ht;qt=Tt^Bt;Rt=Nt^jt;Ut=Ct^Ft;zt=kt^It;Wt=Lt^qt;Xt=At^Pr[e|Ut]^16;Vt=Ot^Pr[e|zt];$t=Mt^Pr[e|Wt];Jt=_t^Pr[e|Rt];Kt=Dt^Xt;Qt=Pt^Vt;Gt=Ht^$t;Yt=Bt^Jt;Zt=jt^Kt;en=Ft^Qt;tn=It^Gt;nn=qt^Yt;rn=Rt^Zt;sn=Ut^en;on=zt^tn;un=Wt^nn;an=Xt^Pr[e|sn]^32;fn=Vt^Pr[e|on];ln=$t^Pr[e|un];cn=Jt^Pr[e|rn];hn=Kt^an;pn=Qt^fn;dn=Gt^ln;vn=Yt^cn;mn=Zt^hn;gn=en^pn;yn=tn^dn;bn=nn^vn;wn=rn^mn;En=sn^gn;Sn=on^yn;xn=un^bn;Tn=an^Pr[e|En]^64;Nn=fn^Pr[e|Sn];Cn=ln^Pr[e|xn];kn=cn^Pr[e|wn];Ln=hn^Tn;An=pn^Nn;On=dn^Cn;Mn=vn^kn;_n=mn^Ln;Dn=gn^An;Pn=yn^On;Hn=bn^Mn;Bn=wn^_n;jn=En^Dn;Fn=Sn^Pn;In=xn^Hn;qn=Tn^Pr[e|jn]^128;Rn=Nn^Pr[e|Fn];Un=Cn^Pr[e|In];zn=kn^Pr[e|Bn];Wn=Ln^qn;Xn=An^Rn;Vn=On^Un;$n=Mn^zn;Jn=_n^Wn;Kn=Dn^Xn;Qn=Pn^Vn;Gn=Hn^$n;Yn=Bn^Jn;Zn=jn^Kn;er=Fn^Qn;tr=In^Gn;nr=qn^Pr[e|Zn]^27;rr=Rn^Pr[e|er];ir=Un^Pr[e|tr];sr=zn^Pr[e|Yn];or=Wn^nr;ur=Xn^rr;ar=Vn^ir;fr=$n^sr;lr=Jn^or;cr=Kn^ur;hr=Qn^ar;pr=Gn^fr;dr=Yn^lr;vr=Zn^cr;mr=er^hr;gr=tr^pr;yr=nr^Pr[e|vr]^54;br=rr^Pr[e|mr];wr=ir^Pr[e|gr];Er=sr^Pr[e|dr];Sr=or^yr;xr=ur^br;Tr=ar^wr;Nr=fr^Er;Cr=lr^Sr;kr=cr^xr;Lr=hr^Tr;Ar=pr^Nr;Or=dr^Cr;Mr=vr^kr;_r=mr^Lr;Dr=gr^Ar}function Br(e,t,n,Hr,Br,jr,Fr,Ir,qr,Rr,Ur,zr,Wr,Xr,Vr,$r){e=e|0;t=t|0;n=n|0;Hr=Hr|0;Br=Br|0;jr=jr|0;Fr=Fr|0;Ir=Ir|0;qr=qr|0;Rr=Rr|0;Ur=Ur|0;zr=zr|0;Wr=Wr|0;Xr=Xr|0;Vr=Vr|0;$r=$r|0;var Jr=0,Kr=0,Qr=0,Gr=0,Yr=0,Zr=0,ei=0,ti=0,ni=0,ri=0,ii=0,si=0,oi=0,ui=0,ai=0,fi=0,li=0,ci=512,hi=768;e=e^b;t=t^w;n=n^E;Hr=Hr^S;Br=Br^x;jr=jr^T;Fr=Fr^N;Ir=Ir^C;qr=qr^k;Rr=Rr^L;Ur=Ur^A;zr=zr^O;Wr=Wr^M;Xr=Xr^_;Vr=Vr^D;$r=$r^P;Jr=Pr[ci|e]^Pr[hi|jr]^Pr[li|Ur]^Pr[li|$r]^H;Kr=Pr[li|e]^Pr[ci|jr]^Pr[hi|Ur]^Pr[li|$r]^B;Qr=Pr[li|e]^Pr[li|jr]^Pr[ci|Ur]^Pr[hi|$r]^j;Gr=Pr[hi|e]^Pr[li|jr]^Pr[li|Ur]^Pr[ci|$r]^F;Yr=Pr[ci|Br]^Pr[hi|Rr]^Pr[li|Vr]^Pr[li|Hr]^I;Zr=Pr[li|Br]^Pr[ci|Rr]^Pr[hi|Vr]^Pr[li|Hr]^q;ei=Pr[li|Br]^Pr[li|Rr]^Pr[ci|Vr]^Pr[hi|Hr]^R;ti=Pr[hi|Br]^Pr[li|Rr]^Pr[li|Vr]^Pr[ci|Hr]^U;ni=Pr[ci|qr]^Pr[hi|Xr]^Pr[li|n]^Pr[li|Ir]^z;ri=Pr[li|qr]^Pr[ci|Xr]^Pr[hi|n]^Pr[li|Ir]^W;ii=Pr[li|qr]^Pr[li|Xr]^Pr[ci|n]^Pr[hi|Ir]^X;si=Pr[hi|qr]^Pr[li|Xr]^Pr[li|n]^Pr[ci|Ir]^V;oi=Pr[ci|Wr]^Pr[hi|t]^Pr[li|Fr]^Pr[li|zr]^$;ui=Pr[li|Wr]^Pr[ci|t]^Pr[hi|Fr]^Pr[li|zr]^J;ai=Pr[li|Wr]^Pr[li|t]^Pr[ci|Fr]^Pr[hi|zr]^K;fi=Pr[hi|Wr]^Pr[li|t]^Pr[li|Fr]^Pr[ci|zr]^Q;e=Pr[ci|Jr]^Pr[hi|Zr]^Pr[li|ii]^Pr[li|fi]^G;t=Pr[li|Jr]^Pr[ci|Zr]^Pr[hi|ii]^Pr[li|fi]^Y;n=Pr[li|Jr]^Pr[li|Zr]^Pr[ci|ii]^Pr[hi|fi]^Z;Hr=Pr[hi|Jr]^Pr[li|Zr]^Pr[li|ii]^Pr[ci|fi]^et;Br=Pr[ci|Yr]^Pr[hi|ri]^Pr[li|ai]^Pr[li|Gr]^tt;jr=Pr[li|Yr]^Pr[ci|ri]^Pr[hi|ai]^Pr[li|Gr]^nt;Fr=Pr[li|Yr]^Pr[li|ri]^Pr[ci|ai]^Pr[hi|Gr]^rt;Ir=Pr[hi|Yr]^Pr[li|ri]^Pr[li|ai]^Pr[ci|Gr]^it;qr=Pr[ci|ni]^Pr[hi|ui]^Pr[li|Qr]^Pr[li|ti]^st;Rr=Pr[li|ni]^Pr[ci|ui]^Pr[hi|Qr]^Pr[li|ti]^ot;Ur=Pr[li|ni]^Pr[li|ui]^Pr[ci|Qr]^Pr[hi|ti]^ut;zr=Pr[hi|ni]^Pr[li|ui]^Pr[li|Qr]^Pr[ci|ti]^at;Wr=Pr[ci|oi]^Pr[hi|Kr]^Pr[li|ei]^Pr[li|si]^ft;Xr=Pr[li|oi]^Pr[ci|Kr]^Pr[hi|ei]^Pr[li|si]^lt;Vr=Pr[li|oi]^Pr[li|Kr]^Pr[ci|ei]^Pr[hi|si]^ct;$r=Pr[hi|oi]^Pr[li|Kr]^Pr[li|ei]^Pr[ci|si]^ht;Jr=Pr[ci|e]^Pr[hi|jr]^Pr[li|Ur]^Pr[li|$r]^pt;Kr=Pr[li|e]^Pr[ci|jr]^Pr[hi|Ur]^Pr[li|$r]^dt;Qr=Pr[li|e]^Pr[li|jr]^Pr[ci|Ur]^Pr[hi|$r]^vt;Gr=Pr[hi|e]^Pr[li|jr]^Pr[li|Ur]^Pr[ci|$r]^mt;Yr=Pr[ci|Br]^Pr[hi|Rr]^Pr[li|Vr]^Pr[li|Hr]^gt;Zr=Pr[li|Br]^Pr[ci|Rr]^Pr[hi|Vr]^Pr[li|Hr]^yt;ei=Pr[li|Br]^Pr[li|Rr]^Pr[ci|Vr]^Pr[hi|Hr]^bt;ti=Pr[hi|Br]^Pr[li|Rr]^Pr[li|Vr]^Pr[ci|Hr]^wt;ni=Pr[ci|qr]^Pr[hi|Xr]^Pr[li|n]^Pr[li|Ir]^Et;ri=Pr[li|qr]^Pr[ci|Xr]^Pr[hi|n]^Pr[li|Ir]^St;ii=Pr[li|qr]^Pr[li|Xr]^Pr[ci|n]^Pr[hi|Ir]^xt;si=Pr[hi|qr]^Pr[li|Xr]^Pr[li|n]^Pr[ci|Ir]^Tt;oi=Pr[ci|Wr]^Pr[hi|t]^Pr[li|Fr]^Pr[li|zr]^Nt;ui=Pr[li|Wr]^Pr[ci|t]^Pr[hi|Fr]^Pr[li|zr]^Ct;ai=Pr[li|Wr]^Pr[li|t]^Pr[ci|Fr]^Pr[hi|zr]^kt;fi=Pr[hi|Wr]^Pr[li|t]^Pr[li|Fr]^Pr[ci|zr]^Lt;e=Pr[ci|Jr]^Pr[hi|Zr]^Pr[li|ii]^Pr[li|fi]^At;t=Pr[li|Jr]^Pr[ci|Zr]^Pr[hi|ii]^Pr[li|fi]^Ot;n=Pr[li|Jr]^Pr[li|Zr]^Pr[ci|ii]^Pr[hi|fi]^Mt;Hr=Pr[hi|Jr]^Pr[li|Zr]^Pr[li|ii]^Pr[ci|fi]^_t;Br=Pr[ci|Yr]^Pr[hi|ri]^Pr[li|ai]^Pr[li|Gr]^Dt;jr=Pr[li|Yr]^Pr[ci|ri]^Pr[hi|ai]^Pr[li|Gr]^Pt;Fr=Pr[li|Yr]^Pr[li|ri]^Pr[ci|ai]^Pr[hi|Gr]^Ht;Ir=Pr[hi|Yr]^Pr[li|ri]^Pr[li|ai]^Pr[ci|Gr]^Bt;qr=Pr[ci|ni]^Pr[hi|ui]^Pr[li|Qr]^Pr[li|ti]^jt;Rr=Pr[li|ni]^Pr[ci|ui]^Pr[hi|Qr]^Pr[li|ti]^Ft;Ur=Pr[li|ni]^Pr[li|ui]^Pr[ci|Qr]^Pr[hi|ti]^It;zr=Pr[hi|ni]^Pr[li|ui]^Pr[li|Qr]^Pr[ci|ti]^qt;Wr=Pr[ci|oi]^Pr[hi|Kr]^Pr[li|ei]^Pr[li|si]^Rt;Xr=Pr[li|oi]^Pr[ci|Kr]^Pr[hi|ei]^Pr[li|si]^Ut;Vr=Pr[li|oi]^Pr[li|Kr]^Pr[ci|ei]^Pr[hi|si]^zt;$r=Pr[hi|oi]^Pr[li|Kr]^Pr[li|ei]^Pr[ci|si]^Wt;Jr=Pr[ci|e]^Pr[hi|jr]^Pr[li|Ur]^Pr[li|$r]^Xt;Kr=Pr[li|e]^Pr[ci|jr]^Pr[hi|Ur]^Pr[li|$r]^Vt;Qr=Pr[li|e]^Pr[li|jr]^Pr[ci|Ur]^Pr[hi|$r]^$t;Gr=Pr[hi|e]^Pr[li|jr]^Pr[li|Ur]^Pr[ci|$r]^Jt;Yr=Pr[ci|Br]^Pr[hi|Rr]^Pr[li|Vr]^Pr[li|Hr]^Kt;Zr=Pr[li|Br]^Pr[ci|Rr]^Pr[hi|Vr]^Pr[li|Hr]^Qt;ei=Pr[li|Br]^Pr[li|Rr]^Pr[ci|Vr]^Pr[hi|Hr]^Gt;ti=Pr[hi|Br]^Pr[li|Rr]^Pr[li|Vr]^Pr[ci|Hr]^Yt;ni=Pr[ci|qr]^Pr[hi|Xr]^Pr[li|n]^Pr[li|Ir]^Zt;ri=Pr[li|qr]^Pr[ci|Xr]^Pr[hi|n]^Pr[li|Ir]^en;ii=Pr[li|qr]^Pr[li|Xr]^Pr[ci|n]^Pr[hi|Ir]^tn;si=Pr[hi|qr]^Pr[li|Xr]^Pr[li|n]^Pr[ci|Ir]^nn;oi=Pr[ci|Wr]^Pr[hi|t]^Pr[li|Fr]^Pr[li|zr]^rn;ui=Pr[li|Wr]^Pr[ci|t]^Pr[hi|Fr]^Pr[li|zr]^sn;ai=Pr[li|Wr]^Pr[li|t]^Pr[ci|Fr]^Pr[hi|zr]^on;fi=Pr[hi|Wr]^Pr[li|t]^Pr[li|Fr]^Pr[ci|zr]^un;e=Pr[ci|Jr]^Pr[hi|Zr]^Pr[li|ii]^Pr[li|fi]^an;t=Pr[li|Jr]^Pr[ci|Zr]^Pr[hi|ii]^Pr[li|fi]^fn;n=Pr[li|Jr]^Pr[li|Zr]^Pr[ci|ii]^Pr[hi|fi]^ln;Hr=Pr[hi|Jr]^Pr[li|Zr]^Pr[li|ii]^Pr[ci|fi]^cn;Br=Pr[ci|Yr]^Pr[hi|ri]^Pr[li|ai]^Pr[li|Gr]^hn;jr=Pr[li|Yr]^Pr[ci|ri]^Pr[hi|ai]^Pr[li|Gr]^pn;Fr=Pr[li|Yr]^Pr[li|ri]^Pr[ci|ai]^Pr[hi|Gr]^dn;Ir=Pr[hi|Yr]^Pr[li|ri]^Pr[li|ai]^Pr[ci|Gr]^vn;qr=Pr[ci|ni]^Pr[hi|ui]^Pr[li|Qr]^Pr[li|ti]^mn;Rr=Pr[li|ni]^Pr[ci|ui]^Pr[hi|Qr]^Pr[li|ti]^gn;Ur=Pr[li|ni]^Pr[li|ui]^Pr[ci|Qr]^Pr[hi|ti]^yn;zr=Pr[hi|ni]^Pr[li|ui]^Pr[li|Qr]^Pr[ci|ti]^bn;Wr=Pr[ci|oi]^Pr[hi|Kr]^Pr[li|ei]^Pr[li|si]^wn;Xr=Pr[li|oi]^Pr[ci|Kr]^Pr[hi|ei]^Pr[li|si]^En;Vr=Pr[li|oi]^Pr[li|Kr]^Pr[ci|ei]^Pr[hi|si]^Sn;$r=Pr[hi|oi]^Pr[li|Kr]^Pr[li|ei]^Pr[ci|si]^xn;Jr=Pr[ci|e]^Pr[hi|jr]^Pr[li|Ur]^Pr[li|$r]^Tn;Kr=Pr[li|e]^Pr[ci|jr]^Pr[hi|Ur]^Pr[li|$r]^Nn;Qr=Pr[li|e]^Pr[li|jr]^Pr[ci|Ur]^Pr[hi|$r]^Cn;Gr=Pr[hi|e]^Pr[li|jr]^Pr[li|Ur]^Pr[ci|$r]^kn;Yr=Pr[ci|Br]^Pr[hi|Rr]^Pr[li|Vr]^Pr[li|Hr]^Ln;Zr=Pr[li|Br]^Pr[ci|Rr]^Pr[hi|Vr]^Pr[li|Hr]^An;ei=Pr[li|Br]^Pr[li|Rr]^Pr[ci|Vr]^Pr[hi|Hr]^On;ti=Pr[hi|Br]^Pr[li|Rr]^Pr[li|Vr]^Pr[ci|Hr]^Mn;ni=Pr[ci|qr]^Pr[hi|Xr]^Pr[li|n]^Pr[li|Ir]^_n;ri=Pr[li|qr]^Pr[ci|Xr]^Pr[hi|n]^Pr[li|Ir]^Dn;ii=Pr[li|qr]^Pr[li|Xr]^Pr[ci|n]^Pr[hi|Ir]^Pn;si=Pr[hi|qr]^Pr[li|Xr]^Pr[li|n]^Pr[ci|Ir]^Hn;oi=Pr[ci|Wr]^Pr[hi|t]^Pr[li|Fr]^Pr[li|zr]^Bn;ui=Pr[li|Wr]^Pr[ci|t]^Pr[hi|Fr]^Pr[li|zr]^jn;ai=Pr[li|Wr]^Pr[li|t]^Pr[ci|Fr]^Pr[hi|zr]^Fn;fi=Pr[hi|Wr]^Pr[li|t]^Pr[li|Fr]^Pr[ci|zr]^In;e=Pr[ci|Jr]^Pr[hi|Zr]^Pr[li|ii]^Pr[li|fi]^qn;t=Pr[li|Jr]^Pr[ci|Zr]^Pr[hi|ii]^Pr[li|fi]^Rn;n=Pr[li|Jr]^Pr[li|Zr]^Pr[ci|ii]^Pr[hi|fi]^Un;Hr=Pr[hi|Jr]^Pr[li|Zr]^Pr[li|ii]^Pr[ci|fi]^zn;Br=Pr[ci|Yr]^Pr[hi|ri]^Pr[li|ai]^Pr[li|Gr]^Wn;jr=Pr[li|Yr]^Pr[ci|ri]^Pr[hi|ai]^Pr[li|Gr]^Xn;Fr=Pr[li|Yr]^Pr[li|ri]^Pr[ci|ai]^Pr[hi|Gr]^Vn;Ir=Pr[hi|Yr]^Pr[li|ri]^Pr[li|ai]^Pr[ci|Gr]^$n;qr=Pr[ci|ni]^Pr[hi|ui]^Pr[li|Qr]^Pr[li|ti]^Jn;Rr=Pr[li|ni]^Pr[ci|ui]^Pr[hi|Qr]^Pr[li|ti]^Kn;Ur=Pr[li|ni]^Pr[li|ui]^Pr[ci|Qr]^Pr[hi|ti]^Qn;zr=Pr[hi|ni]^Pr[li|ui]^Pr[li|Qr]^Pr[ci|ti]^Gn;Wr=Pr[ci|oi]^Pr[hi|Kr]^Pr[li|ei]^Pr[li|si]^Yn;Xr=Pr[li|oi]^Pr[ci|Kr]^Pr[hi|ei]^Pr[li|si]^Zn;Vr=Pr[li|oi]^Pr[li|Kr]^Pr[ci|ei]^Pr[hi|si]^er;$r=Pr[hi|oi]^Pr[li|Kr]^Pr[li|ei]^Pr[ci|si]^tr;Jr=Pr[ci|e]^Pr[hi|jr]^Pr[li|Ur]^Pr[li|$r]^nr;Kr=Pr[li|e]^Pr[ci|jr]^Pr[hi|Ur]^Pr[li|$r]^rr;Qr=Pr[li|e]^Pr[li|jr]^Pr[ci|Ur]^Pr[hi|$r]^ir;Gr=Pr[hi|e]^Pr[li|jr]^Pr[li|Ur]^Pr[ci|$r]^sr;Yr=Pr[ci|Br]^Pr[hi|Rr]^Pr[li|Vr]^Pr[li|Hr]^or;Zr=Pr[li|Br]^Pr[ci|Rr]^Pr[hi|Vr]^Pr[li|Hr]^ur;ei=Pr[li|Br]^Pr[li|Rr]^Pr[ci|Vr]^Pr[hi|Hr]^ar;ti=Pr[hi|Br]^Pr[li|Rr]^Pr[li|Vr]^Pr[ci|Hr]^fr;ni=Pr[ci|qr]^Pr[hi|Xr]^Pr[li|n]^Pr[li|Ir]^lr;ri=Pr[li|qr]^Pr[ci|Xr]^Pr[hi|n]^Pr[li|Ir]^cr;ii=Pr[li|qr]^Pr[li|Xr]^Pr[ci|n]^Pr[hi|Ir]^hr;si=Pr[hi|qr]^Pr[li|Xr]^Pr[li|n]^Pr[ci|Ir]^pr;oi=Pr[ci|Wr]^Pr[hi|t]^Pr[li|Fr]^Pr[li|zr]^dr;ui=Pr[li|Wr]^Pr[ci|t]^Pr[hi|Fr]^Pr[li|zr]^vr;ai=Pr[li|Wr]^Pr[li|t]^Pr[ci|Fr]^Pr[hi|zr]^mr;fi=Pr[hi|Wr]^Pr[li|t]^Pr[li|Fr]^Pr[ci|zr]^gr;r=Pr[li|Jr]^yr;i=Pr[li|Zr]^br;s=Pr[li|ii]^wr;o=Pr[li|fi]^Er;u=Pr[li|Yr]^Sr;a=Pr[li|ri]^xr;f=Pr[li|ai]^Tr;l=Pr[li|Gr]^Nr;c=Pr[li|ni]^Cr;h=Pr[li|ui]^kr;p=Pr[li|Qr]^Lr;d=Pr[li|ti]^Ar;v=Pr[li|oi]^Or;m=Pr[li|Kr]^Mr;g=Pr[li|ei]^_r;y=Pr[li|si]^Dr}function jr(e,t,n,Hr,Br,jr,Fr,Ir,qr,Rr,Ur,zr,Wr,Xr,Vr,$r){e=e|0;t=t|0;n=n|0;Hr=Hr|0;Br=Br|0;jr=jr|0;Fr=Fr|0;Ir=Ir|0;qr=qr|0;Rr=Rr|0;Ur=Ur|0;zr=zr|0;Wr=Wr|0;Xr=Xr|0;Vr=Vr|0;$r=$r|0;var Jr=0,Kr=0,Qr=0,Gr=0,Yr=0,Zr=0,ei=0,ti=0,ni=0,ri=0,ii=0,si=0,oi=0,ui=0,ai=0,fi=0,li=256,ci=1024,hi=1280,pi=1536,di=1792;Jr=Pr[li|e^yr]^nr;Kr=Pr[li|Xr^Mr]^rr;Qr=Pr[li|Ur^Lr]^ir;Gr=Pr[li|Ir^Nr]^sr;Yr=Pr[li|Br^Sr]^or;Zr=Pr[li|t^br]^ur;ei=Pr[li|Vr^_r]^ar;ti=Pr[li|zr^Ar]^fr;ni=Pr[li|qr^Cr]^lr;ri=Pr[li|jr^xr]^cr;ii=Pr[li|n^wr]^hr;si=Pr[li|$r^Dr]^pr;oi=Pr[li|Wr^Or]^dr;ui=Pr[li|Rr^kr]^vr;ai=Pr[li|Fr^Tr]^mr;fi=Pr[li|Hr^Er]^gr;e=Pr[di|Jr]^Pr[hi|Kr]^Pr[pi|Qr]^Pr[ci|Gr];t=Pr[ci|oi]^Pr[di|ui]^Pr[hi|ai]^Pr[pi|fi];n=Pr[pi|ni]^Pr[ci|ri]^Pr[di|ii]^Pr[hi|si];Hr=Pr[hi|Yr]^Pr[pi|Zr]^Pr[ci|ei]^Pr[di|ti];Br=Pr[di|Yr]^Pr[hi|Zr]^Pr[pi|ei]^Pr[ci|ti];jr=Pr[ci|Jr]^Pr[di|Kr]^Pr[hi|Qr]^Pr[pi|Gr];Fr=Pr[pi|oi]^Pr[ci|ui]^Pr[di|ai]^Pr[hi|fi];Ir=Pr[hi|ni]^Pr[pi|ri]^Pr[ci|ii]^Pr[di|si];qr=Pr[di|ni]^Pr[hi|ri]^Pr[pi|ii]^Pr[ci|si];Rr=Pr[ci|Yr]^Pr[di|Zr]^Pr[hi|ei]^Pr[pi|ti];Ur=Pr[pi|Jr]^Pr[ci|Kr]^Pr[di|Qr]^Pr[hi|Gr];zr=Pr[hi|oi]^Pr[pi|ui]^Pr[ci|ai]^Pr[di|fi];Wr=Pr[di|oi]^Pr[hi|ui]^Pr[pi|ai]^Pr[ci|fi];Xr=Pr[ci|ni]^Pr[di|ri]^Pr[hi|ii]^Pr[pi|si];Vr=Pr[pi|Yr]^Pr[ci|Zr]^Pr[di|ei]^Pr[hi|ti];$r=Pr[hi|Jr]^Pr[pi|Kr]^Pr[ci|Qr]^Pr[di|Gr];Jr=Pr[li|e]^qn;Kr=Pr[li|t]^Rn;Qr=Pr[li|n]^Un;Gr=Pr[li|Hr]^zn;Yr=Pr[li|Br]^Wn;Zr=Pr[li|jr]^Xn;ei=Pr[li|Fr]^Vn;ti=Pr[li|Ir]^$n;ni=Pr[li|qr]^Jn;ri=Pr[li|Rr]^Kn;ii=Pr[li|Ur]^Qn;si=Pr[li|zr]^Gn;oi=Pr[li|Wr]^Yn;ui=Pr[li|Xr]^Zn;ai=Pr[li|Vr]^er;fi=Pr[li|$r]^tr;e=Pr[di|Jr]^Pr[hi|Kr]^Pr[pi|Qr]^Pr[ci|Gr];t=Pr[ci|oi]^Pr[di|ui]^Pr[hi|ai]^Pr[pi|fi];n=Pr[pi|ni]^Pr[ci|ri]^Pr[di|ii]^Pr[hi|si];Hr=Pr[hi|Yr]^Pr[pi|Zr]^Pr[ci|ei]^Pr[di|ti];Br=Pr[di|Yr]^Pr[hi|Zr]^Pr[pi|ei]^Pr[ci|ti];jr=Pr[ci|Jr]^Pr[di|Kr]^Pr[hi|Qr]^Pr[pi|Gr];Fr=Pr[pi|oi]^Pr[ci|ui]^Pr[di|ai]^Pr[hi|fi];Ir=Pr[hi|ni]^Pr[pi|ri]^Pr[ci|ii]^Pr[di|si];qr=Pr[di|ni]^Pr[hi|ri]^Pr[pi|ii]^Pr[ci|si];Rr=Pr[ci|Yr]^Pr[di|Zr]^Pr[hi|ei]^Pr[pi|ti];Ur=Pr[pi|Jr]^Pr[ci|Kr]^Pr[di|Qr]^Pr[hi|Gr];zr=Pr[hi|oi]^Pr[pi|ui]^Pr[ci|ai]^Pr[di|fi];Wr=Pr[di|oi]^Pr[hi|ui]^Pr[pi|ai]^Pr[ci|fi];Xr=Pr[ci|ni]^Pr[di|ri]^Pr[hi|ii]^Pr[pi|si];Vr=Pr[pi|Yr]^Pr[ci|Zr]^Pr[di|ei]^Pr[hi|ti];$r=Pr[hi|Jr]^Pr[pi|Kr]^Pr[ci|Qr]^Pr[di|Gr];Jr=Pr[li|e]^Tn;Kr=Pr[li|t]^Nn;Qr=Pr[li|n]^Cn;Gr=Pr[li|Hr]^kn;Yr=Pr[li|Br]^Ln;Zr=Pr[li|jr]^An;ei=Pr[li|Fr]^On;ti=Pr[li|Ir]^Mn;ni=Pr[li|qr]^_n;ri=Pr[li|Rr]^Dn;ii=Pr[li|Ur]^Pn;si=Pr[li|zr]^Hn;oi=Pr[li|Wr]^Bn;ui=Pr[li|Xr]^jn;ai=Pr[li|Vr]^Fn;fi=Pr[li|$r]^In;e=Pr[di|Jr]^Pr[hi|Kr]^Pr[pi|Qr]^Pr[ci|Gr];t=Pr[ci|oi]^Pr[di|ui]^Pr[hi|ai]^Pr[pi|fi];n=Pr[pi|ni]^Pr[ci|ri]^Pr[di|ii]^Pr[hi|si];Hr=Pr[hi|Yr]^Pr[pi|Zr]^Pr[ci|ei]^Pr[di|ti];Br=Pr[di|Yr]^Pr[hi|Zr]^Pr[pi|ei]^Pr[ci|ti];jr=Pr[ci|Jr]^Pr[di|Kr]^Pr[hi|Qr]^Pr[pi|Gr];Fr=Pr[pi|oi]^Pr[ci|ui]^Pr[di|ai]^Pr[hi|fi];Ir=Pr[hi|ni]^Pr[pi|ri]^Pr[ci|ii]^Pr[di|si];qr=Pr[di|ni]^Pr[hi|ri]^Pr[pi|ii]^Pr[ci|si];Rr=Pr[ci|Yr]^Pr[di|Zr]^Pr[hi|ei]^Pr[pi|ti];Ur=Pr[pi|Jr]^Pr[ci|Kr]^Pr[di|Qr]^Pr[hi|Gr];zr=Pr[hi|oi]^Pr[pi|ui]^Pr[ci|ai]^Pr[di|fi];Wr=Pr[di|oi]^Pr[hi|ui]^Pr[pi|ai]^Pr[ci|fi];Xr=Pr[ci|ni]^Pr[di|ri]^Pr[hi|ii]^Pr[pi|si];Vr=Pr[pi|Yr]^Pr[ci|Zr]^Pr[di|ei]^Pr[hi|ti];$r=Pr[hi|Jr]^Pr[pi|Kr]^Pr[ci|Qr]^Pr[di|Gr];Jr=Pr[li|e]^an;Kr=Pr[li|t]^fn;Qr=Pr[li|n]^ln;Gr=Pr[li|Hr]^cn;Yr=Pr[li|Br]^hn;Zr=Pr[li|jr]^pn;ei=Pr[li|Fr]^dn;ti=Pr[li|Ir]^vn;ni=Pr[li|qr]^mn;ri=Pr[li|Rr]^gn;ii=Pr[li|Ur]^yn;si=Pr[li|zr]^bn;oi=Pr[li|Wr]^wn;ui=Pr[li|Xr]^En;ai=Pr[li|Vr]^Sn;fi=Pr[li|$r]^xn;e=Pr[di|Jr]^Pr[hi|Kr]^Pr[pi|Qr]^Pr[ci|Gr];t=Pr[ci|oi]^Pr[di|ui]^Pr[hi|ai]^Pr[pi|fi];n=Pr[pi|ni]^Pr[ci|ri]^Pr[di|ii]^Pr[hi|si];Hr=Pr[hi|Yr]^Pr[pi|Zr]^Pr[ci|ei]^Pr[di|ti];Br=Pr[di|Yr]^Pr[hi|Zr]^Pr[pi|ei]^Pr[ci|ti];jr=Pr[ci|Jr]^Pr[di|Kr]^Pr[hi|Qr]^Pr[pi|Gr];Fr=Pr[pi|oi]^Pr[ci|ui]^Pr[di|ai]^Pr[hi|fi];Ir=Pr[hi|ni]^Pr[pi|ri]^Pr[ci|ii]^Pr[di|si];qr=Pr[di|ni]^Pr[hi|ri]^Pr[pi|ii]^Pr[ci|si];Rr=Pr[ci|Yr]^Pr[di|Zr]^Pr[hi|ei]^Pr[pi|ti];Ur=Pr[pi|Jr]^Pr[ci|Kr]^Pr[di|Qr]^Pr[hi|Gr];zr=Pr[hi|oi]^Pr[pi|ui]^Pr[ci|ai]^Pr[di|fi];Wr=Pr[di|oi]^Pr[hi|ui]^Pr[pi|ai]^Pr[ci|fi];Xr=Pr[ci|ni]^Pr[di|ri]^Pr[hi|ii]^Pr[pi|si];Vr=Pr[pi|Yr]^Pr[ci|Zr]^Pr[di|ei]^Pr[hi|ti];$r=Pr[hi|Jr]^Pr[pi|Kr]^Pr[ci|Qr]^Pr[di|Gr];Jr=Pr[li|e]^Xt;Kr=Pr[li|t]^Vt;Qr=Pr[li|n]^$t;Gr=Pr[li|Hr]^Jt;Yr=Pr[li|Br]^Kt;Zr=Pr[li|jr]^Qt;ei=Pr[li|Fr]^Gt;ti=Pr[li|Ir]^Yt;ni=Pr[li|qr]^Zt;ri=Pr[li|Rr]^en;ii=Pr[li|Ur]^tn;si=Pr[li|zr]^nn;oi=Pr[li|Wr]^rn;ui=Pr[li|Xr]^sn;ai=Pr[li|Vr]^on;fi=Pr[li|$r]^un;e=Pr[di|Jr]^Pr[hi|Kr]^Pr[pi|Qr]^Pr[ci|Gr];t=Pr[ci|oi]^Pr[di|ui]^Pr[hi|ai]^Pr[pi|fi];n=Pr[pi|ni]^Pr[ci|ri]^Pr[di|ii]^Pr[hi|si];Hr=Pr[hi|Yr]^Pr[pi|Zr]^Pr[ci|ei]^Pr[di|ti];Br=Pr[di|Yr]^Pr[hi|Zr]^Pr[pi|ei]^Pr[ci|ti];jr=Pr[ci|Jr]^Pr[di|Kr]^Pr[hi|Qr]^Pr[pi|Gr];Fr=Pr[pi|oi]^Pr[ci|ui]^Pr[di|ai]^Pr[hi|fi];Ir=Pr[hi|ni]^Pr[pi|ri]^Pr[ci|ii]^Pr[di|si];qr=Pr[di|ni]^Pr[hi|ri]^Pr[pi|ii]^Pr[ci|si];Rr=Pr[ci|Yr]^Pr[di|Zr]^Pr[hi|ei]^Pr[pi|ti];Ur=Pr[pi|Jr]^Pr[ci|Kr]^Pr[di|Qr]^Pr[hi|Gr];zr=Pr[hi|oi]^Pr[pi|ui]^Pr[ci|ai]^Pr[di|fi];Wr=Pr[di|oi]^Pr[hi|ui]^Pr[pi|ai]^Pr[ci|fi];Xr=Pr[ci|ni]^Pr[di|ri]^Pr[hi|ii]^Pr[pi|si];Vr=Pr[pi|Yr]^Pr[ci|Zr]^Pr[di|ei]^Pr[hi|ti];$r=Pr[hi|Jr]^Pr[pi|Kr]^Pr[ci|Qr]^Pr[di|Gr];Jr=Pr[li|e]^At;Kr=Pr[li|t]^Ot;Qr=Pr[li|n]^Mt;Gr=Pr[li|Hr]^_t;Yr=Pr[li|Br]^Dt;Zr=Pr[li|jr]^Pt;ei=Pr[li|Fr]^Ht;ti=Pr[li|Ir]^Bt;ni=Pr[li|qr]^jt;ri=Pr[li|Rr]^Ft;ii=Pr[li|Ur]^It;si=Pr[li|zr]^qt;oi=Pr[li|Wr]^Rt;ui=Pr[li|Xr]^Ut;ai=Pr[li|Vr]^zt;fi=Pr[li|$r]^Wt;e=Pr[di|Jr]^Pr[hi|Kr]^Pr[pi|Qr]^Pr[ci|Gr];t=Pr[ci|oi]^Pr[di|ui]^Pr[hi|ai]^Pr[pi|fi];n=Pr[pi|ni]^Pr[ci|ri]^Pr[di|ii]^Pr[hi|si];Hr=Pr[hi|Yr]^Pr[pi|Zr]^Pr[ci|ei]^Pr[di|ti];Br=Pr[di|Yr]^Pr[hi|Zr]^Pr[pi|ei]^Pr[ci|ti];jr=Pr[ci|Jr]^Pr[di|Kr]^Pr[hi|Qr]^Pr[pi|Gr];Fr=Pr[pi|oi]^Pr[ci|ui]^Pr[di|ai]^Pr[hi|fi];Ir=Pr[hi|ni]^Pr[pi|ri]^Pr[ci|ii]^Pr[di|si];qr=Pr[di|ni]^Pr[hi|ri]^Pr[pi|ii]^Pr[ci|si];Rr=Pr[ci|Yr]^Pr[di|Zr]^Pr[hi|ei]^Pr[pi|ti];Ur=Pr[pi|Jr]^Pr[ci|Kr]^Pr[di|Qr]^Pr[hi|Gr];zr=Pr[hi|oi]^Pr[pi|ui]^Pr[ci|ai]^Pr[di|fi];Wr=Pr[di|oi]^Pr[hi|ui]^Pr[pi|ai]^Pr[ci|fi];Xr=Pr[ci|ni]^Pr[di|ri]^Pr[hi|ii]^Pr[pi|si];Vr=Pr[pi|Yr]^Pr[ci|Zr]^Pr[di|ei]^Pr[hi|ti];$r=Pr[hi|Jr]^Pr[pi|Kr]^Pr[ci|Qr]^Pr[di|Gr];Jr=Pr[li|e]^pt;Kr=Pr[li|t]^dt;Qr=Pr[li|n]^vt;Gr=Pr[li|Hr]^mt;Yr=Pr[li|Br]^gt;Zr=Pr[li|jr]^yt;ei=Pr[li|Fr]^bt;ti=Pr[li|Ir]^wt;ni=Pr[li|qr]^Et;ri=Pr[li|Rr]^St;ii=Pr[li|Ur]^xt;si=Pr[li|zr]^Tt;oi=Pr[li|Wr]^Nt;ui=Pr[li|Xr]^Ct;ai=Pr[li|Vr]^kt;fi=Pr[li|$r]^Lt;e=Pr[di|Jr]^Pr[hi|Kr]^Pr[pi|Qr]^Pr[ci|Gr];t=Pr[ci|oi]^Pr[di|ui]^Pr[hi|ai]^Pr[pi|fi];n=Pr[pi|ni]^Pr[ci|ri]^Pr[di|ii]^Pr[hi|si];Hr=Pr[hi|Yr]^Pr[pi|Zr]^Pr[ci|ei]^Pr[di|ti];Br=Pr[di|Yr]^Pr[hi|Zr]^Pr[pi|ei]^Pr[ci|ti];jr=Pr[ci|Jr]^Pr[di|Kr]^Pr[hi|Qr]^Pr[pi|Gr];Fr=Pr[pi|oi]^Pr[ci|ui]^Pr[di|ai]^Pr[hi|fi];Ir=Pr[hi|ni]^Pr[pi|ri]^Pr[ci|ii]^Pr[di|si];qr=Pr[di|ni]^Pr[hi|ri]^Pr[pi|ii]^Pr[ci|si];Rr=Pr[ci|Yr]^Pr[di|Zr]^Pr[hi|ei]^Pr[pi|ti];Ur=Pr[pi|Jr]^Pr[ci|Kr]^Pr[di|Qr]^Pr[hi|Gr];zr=Pr[hi|oi]^Pr[pi|ui]^Pr[ci|ai]^Pr[di|fi];Wr=Pr[di|oi]^Pr[hi|ui]^Pr[pi|ai]^Pr[ci|fi];Xr=Pr[ci|ni]^Pr[di|ri]^Pr[hi|ii]^Pr[pi|si];Vr=Pr[pi|Yr]^Pr[ci|Zr]^Pr[di|ei]^Pr[hi|ti];$r=Pr[hi|Jr]^Pr[pi|Kr]^Pr[ci|Qr]^Pr[di|Gr];Jr=Pr[li|e]^G;Kr=Pr[li|t]^Y;Qr=Pr[li|n]^Z;Gr=Pr[li|Hr]^et;Yr=Pr[li|Br]^tt;Zr=Pr[li|jr]^nt;ei=Pr[li|Fr]^rt;ti=Pr[li|Ir]^it;ni=Pr[li|qr]^st;ri=Pr[li|Rr]^ot;ii=Pr[li|Ur]^ut;si=Pr[li|zr]^at;oi=Pr[li|Wr]^ft;ui=Pr[li|Xr]^lt;ai=Pr[li|Vr]^ct;fi=Pr[li|$r]^ht;e=Pr[di|Jr]^Pr[hi|Kr]^Pr[pi|Qr]^Pr[ci|Gr];t=Pr[ci|oi]^Pr[di|ui]^Pr[hi|ai]^Pr[pi|fi];n=Pr[pi|ni]^Pr[ci|ri]^Pr[di|ii]^Pr[hi|si];Hr=Pr[hi|Yr]^Pr[pi|Zr]^Pr[ci|ei]^Pr[di|ti];Br=Pr[di|Yr]^Pr[hi|Zr]^Pr[pi|ei]^Pr[ci|ti];jr=Pr[ci|Jr]^Pr[di|Kr]^Pr[hi|Qr]^Pr[pi|Gr];Fr=Pr[pi|oi]^Pr[ci|ui]^Pr[di|ai]^Pr[hi|fi];Ir=Pr[hi|ni]^Pr[pi|ri]^Pr[ci|ii]^Pr[di|si];qr=Pr[di|ni]^Pr[hi|ri]^Pr[pi|ii]^Pr[ci|si];Rr=Pr[ci|Yr]^Pr[di|Zr]^Pr[hi|ei]^Pr[pi|ti];Ur=Pr[pi|Jr]^Pr[ci|Kr]^Pr[di|Qr]^Pr[hi|Gr];zr=Pr[hi|oi]^Pr[pi|ui]^Pr[ci|ai]^Pr[di|fi];Wr=Pr[di|oi]^Pr[hi|ui]^Pr[pi|ai]^Pr[ci|fi];Xr=Pr[ci|ni]^Pr[di|ri]^Pr[hi|ii]^Pr[pi|si];Vr=Pr[pi|Yr]^Pr[ci|Zr]^Pr[di|ei]^Pr[hi|ti];$r=Pr[hi|Jr]^Pr[pi|Kr]^Pr[ci|Qr]^Pr[di|Gr];Jr=Pr[li|e]^H;Kr=Pr[li|t]^B;Qr=Pr[li|n]^j;Gr=Pr[li|Hr]^F;Yr=Pr[li|Br]^I;Zr=Pr[li|jr]^q;ei=Pr[li|Fr]^R;ti=Pr[li|Ir]^U;ni=Pr[li|qr]^z;ri=Pr[li|Rr]^W;ii=Pr[li|Ur]^X;si=Pr[li|zr]^V;oi=Pr[li|Wr]^$;ui=Pr[li|Xr]^J;ai=Pr[li|Vr]^K;fi=Pr[li|$r]^Q;e=Pr[di|Jr]^Pr[hi|Kr]^Pr[pi|Qr]^Pr[ci|Gr];t=Pr[ci|oi]^Pr[di|ui]^Pr[hi|ai]^Pr[pi|fi];n=Pr[pi|ni]^Pr[ci|ri]^Pr[di|ii]^Pr[hi|si];Hr=Pr[hi|Yr]^Pr[pi|Zr]^Pr[ci|ei]^Pr[di|ti];Br=Pr[di|Yr]^Pr[hi|Zr]^Pr[pi|ei]^Pr[ci|ti];jr=Pr[ci|Jr]^Pr[di|Kr]^Pr[hi|Qr]^Pr[pi|Gr];Fr=Pr[pi|oi]^Pr[ci|ui]^Pr[di|ai]^Pr[hi|fi];Ir=Pr[hi|ni]^Pr[pi|ri]^Pr[ci|ii]^Pr[di|si];qr=Pr[di|ni]^Pr[hi|ri]^Pr[pi|ii]^Pr[ci|si];Rr=Pr[ci|Yr]^Pr[di|Zr]^Pr[hi|ei]^Pr[pi|ti];Ur=Pr[pi|Jr]^Pr[ci|Kr]^Pr[di|Qr]^Pr[hi|Gr];zr=Pr[hi|oi]^Pr[pi|ui]^Pr[ci|ai]^Pr[di|fi];Wr=Pr[di|oi]^Pr[hi|ui]^Pr[pi|ai]^Pr[ci|fi];Xr=Pr[ci|ni]^Pr[di|ri]^Pr[hi|ii]^Pr[pi|si];Vr=Pr[pi|Yr]^Pr[ci|Zr]^Pr[di|ei]^Pr[hi|ti];$r=Pr[hi|Jr]^Pr[pi|Kr]^Pr[ci|Qr]^Pr[di|Gr];r=Pr[li|e]^b;i=Pr[li|t]^w;s=Pr[li|n]^E;o=Pr[li|Hr]^S;u=Pr[li|Br]^x;a=Pr[li|jr]^T;f=Pr[li|Fr]^N;l=Pr[li|Ir]^C;c=Pr[li|qr]^k;h=Pr[li|Rr]^L;p=Pr[li|Ur]^A;d=Pr[li|zr]^O;v=Pr[li|Wr]^M;m=Pr[li|Xr]^_;g=Pr[li|Vr]^D;y=Pr[li|$r]^P}function Fr(e,t,n,b,w,E,S,x,T,N,C,k,L,A,O,M){e=e|0;t=t|0;n=n|0;b=b|0;w=w|0;E=E|0;S=S|0;x=x|0;T=T|0;N=N|0;C=C|0;k=k|0;L=L|0;A=A|0;O=O|0;M=M|0;r=e;i=t;s=n;o=b;u=w;a=E;f=S;l=x;c=T;h=N;p=C;d=k;v=L;m=A;g=O;y=M}function Ir(e){e=e|0;Pr[e]=r;Pr[e|1]=i;Pr[e|2]=s;Pr[e|3]=o;Pr[e|4]=u;Pr[e|5]=a;Pr[e|6]=f;Pr[e|7]=l;Pr[e|8]=c;Pr[e|9]=h;Pr[e|10]=p;Pr[e|11]=d;Pr[e|12]=v;Pr[e|13]=m;Pr[e|14]=g;Pr[e|15]=y}function qr(e,t,n,r,i,s,o,u,a,f,l,c,h,p,d,v){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;s=s|0;o=o|0;u=u|0;a=a|0;f=f|0;l=l|0;c=c|0;h=h|0;p=p|0;d=d|0;v=v|0;b=e;w=t;E=n;S=r;x=i;T=s;N=o;C=u;k=a;L=f;A=l;O=c;M=h;_=p;D=d;P=v;Hr()}function Rr(e,t){e=e|0;t=t|0;if(e&15|t&15)return-1;while((t|0)>0){Br(r^Pr[e],i^Pr[e|1],s^Pr[e|2],o^Pr[e|3],u^Pr[e|4],a^Pr[e|5],f^Pr[e|6],l^Pr[e|7],c^Pr[e|8],h^Pr[e|9],p^Pr[e|10],d^Pr[e|11],v^Pr[e|12],m^Pr[e|13],g^Pr[e|14],y^Pr[e|15]);Pr[e]=r;Pr[e|1]=i;Pr[e|2]=s;Pr[e|3]=o;Pr[e|4]=u;Pr[e|5]=a;Pr[e|6]=f;Pr[e|7]=l;Pr[e|8]=c;Pr[e|9]=h;Pr[e|10]=p;Pr[e|11]=d;Pr[e|12]=v;Pr[e|13]=m;Pr[e|14]=g;Pr[e|15]=y;e=e+16|0;t=t-16|0}return 0}function Ur(e,t){e=e|0;t=t|0;var n=0,b=0,w=0,E=0,S=0,x=0,T=0,N=0,C=0,k=0,L=0,A=0,O=0,M=0,_=0,D=0;if(e&15|t&15)return-1;n=r;b=i;w=s;E=o;S=u;x=a;T=f;N=l;C=c;k=h;L=p;A=d;O=v;M=m;_=g;D=y;while((t|0)>0){jr(Pr[e]|0,Pr[e|1]|0,Pr[e|2]|0,Pr[e|3]|0,Pr[e|4]|0,Pr[e|5]|0,Pr[e|6]|0,Pr[e|7]|0,Pr[e|8]|0,Pr[e|9]|0,Pr[e|10]|0,Pr[e|11]|0,Pr[e|12]|0,Pr[e|13]|0,Pr[e|14]|0,Pr[e|15]|0);r=r^n;n=Pr[e]|0;i=i^b;b=Pr[e|1]|0;s=s^w;w=Pr[e|2]|0;o=o^E;E=Pr[e|3]|0;u=u^S;S=Pr[e|4]|0;a=a^x;x=Pr[e|5]|0;f=f^T;T=Pr[e|6]|0;l=l^N;N=Pr[e|7]|0;c=c^C;C=Pr[e|8]|0;h=h^k;k=Pr[e|9]|0;p=p^L;L=Pr[e|10]|0;d=d^A;A=Pr[e|11]|0;v=v^O;O=Pr[e|12]|0;m=m^M;M=Pr[e|13]|0;g=g^_;_=Pr[e|14]|0;y=y^D;D=Pr[e|15]|0;Pr[e]=r;Pr[e|1]=i;Pr[e|2]=s;Pr[e|3]=o;Pr[e|4]=u;Pr[e|5]=a;Pr[e|6]=f;Pr[e|7]=l;Pr[e|8]=c;Pr[e|9]=h;Pr[e|10]=p;Pr[e|11]=d;Pr[e|12]=v;Pr[e|13]=m;Pr[e|14]=g;Pr[e|15]=y;e=e+16|0;t=t-16|0}r=n;i=b;s=w;o=E;u=S;a=x;f=T;l=N;c=C;h=k;p=L;d=A;v=O;m=M;g=_;y=D;return 0}function zr(e,t,n){e=e|0;t=t|0;n=n|0;if(e&15)return-1;if(~n)if(n&31)return-1;while((t|0)>=16){Br(r^Pr[e],i^Pr[e|1],s^Pr[e|2],o^Pr[e|3],u^Pr[e|4],a^Pr[e|5],f^Pr[e|6],l^Pr[e|7],c^Pr[e|8],h^Pr[e|9],p^Pr[e|10],d^Pr[e|11],v^Pr[e|12],m^Pr[e|13],g^Pr[e|14],y^Pr[e|15]);e=e+16|0;t=t-16|0}if((t|0)>0){r=r^Pr[e];if((t|0)>1)i=i^Pr[e|1];if((t|0)>2)s=s^Pr[e|2];if((t|0)>3)o=o^Pr[e|3];if((t|0)>4)u=u^Pr[e|4];if((t|0)>5)a=a^Pr[e|5];if((t|0)>6)f=f^Pr[e|6];if((t|0)>7)l=l^Pr[e|7];if((t|0)>8)c=c^Pr[e|8];if((t|0)>9)h=h^Pr[e|9];if((t|0)>10)p=p^Pr[e|10];if((t|0)>11)d=d^Pr[e|11];if((t|0)>12)v=v^Pr[e|12];if((t|0)>13)m=m^Pr[e|13];if((t|0)>14)g=g^Pr[e|14];Br(r,i,s,o,u,a,f,l,c,h,p,d,v,m,g,y);e=e+t|0;t=0}if(~n){Pr[n|0]=r;Pr[n|1]=i;Pr[n|2]=s;Pr[n|3]=o;Pr[n|4]=u;Pr[n|5]=a;Pr[n|6]=f;Pr[n|7]=l;Pr[n|8]=c;Pr[n|9]=h;Pr[n|10]=p;Pr[n|11]=d;Pr[n|12]=v;Pr[n|13]=m;Pr[n|14]=g;Pr[n|15]=y}return 0}function Wr(e,t,n,b,w,E,S,x,T,N,C,k,L,A,O,M,_){e=e|0;t=t|0;n=n|0;b=b|0;w=w|0;E=E|0;S=S|0;x=x|0;T=T|0;N=N|0;C=C|0;k=k|0;L=L|0;A=A|0;O=O|0;M=M|0;_=_|0;var D=0,P=0,H=0,B=0,j=0,F=0,I=0,q=0,R=0,U=0,z=0,W=0,X=0,V=0,$=0,J=0,K=0,Q=0,G=0,Y=0,Z=0,et=0,tt=0,nt=0,rt=0,it=0,st=0,ot=0,ut=0,at=0,ft=0,lt=0;if(e&15)return-1;D=r,P=i,H=s,B=o,j=u,F=a,I=f,q=l,R=c,U=h,z=p,W=d,X=v,V=m,$=g,J=y;while((t|0)>=16){K=Pr[e]|0;Q=Pr[e|1]|0;G=Pr[e|2]|0;Y=Pr[e|3]|0;Z=Pr[e|4]|0;et=Pr[e|5]|0;tt=Pr[e|6]|0;nt=Pr[e|7]|0;rt=Pr[e|8]|0;it=Pr[e|9]|0;st=Pr[e|10]|0;ot=Pr[e|11]|0;ut=Pr[e|12]|0;at=Pr[e|13]|0;ft=Pr[e|14]|0;lt=Pr[e|15]|0;Br(n,b,w,E,S,x,T,N,C,k,L,A,O^_>>>24,M^_>>>16&255,_>>>8&255,_&255);Pr[e]=K^r;Pr[e|1]=Q^i;Pr[e|2]=G^s;Pr[e|3]=Y^o;Pr[e|4]=Z^u;Pr[e|5]=et^a;Pr[e|6]=tt^f;Pr[e|7]=nt^l;Pr[e|8]=rt^c;Pr[e|9]=it^h;Pr[e|10]=st^p;Pr[e|11]=ot^d;Pr[e|12]=ut^v;Pr[e|13]=at^m;Pr[e|14]=ft^g;Pr[e|15]=lt^y;Br(K^D,Q^P,G^H,Y^B,Z^j,et^F,tt^I,nt^q,rt^R,it^U,st^z,ot^W,ut^X,at^V,ft^$,lt^J);D=r,P=i,H=s,B=o,j=u,F=a,I=f,q=l,R=c,U=h,z=p,W=d,X=v,V=m,$=g,J=y;e=e+16|0;t=t-16|0;_=_+1|0}if((t|0)>0){K=Pr[e]|0;Q=(t|0)>1?Pr[e|1]|0:0;G=(t|0)>2?Pr[e|2]|0:0;Y=(t|0)>3?Pr[e|3]|0:0;Z=(t|0)>4?Pr[e|4]|0:0;et=(t|0)>5?Pr[e|5]|0:0;tt=(t|0)>6?Pr[e|6]|0:0;nt=(t|0)>7?Pr[e|7]|0:0;rt=(t|0)>8?Pr[e|8]|0:0;it=(t|0)>9?Pr[e|9]|0:0;st=(t|0)>10?Pr[e|10]|0:0;ot=(t|0)>11?Pr[e|11]|0:0;ut=(t|0)>12?Pr[e|12]|0:0;at=(t|0)>13?Pr[e|13]|0:0;ft=(t|0)>14?Pr[e|14]|0:0;Br(n,b,w,E,S,x,T,N,C,k,L,A,O^_>>>24,M^_>>>16&255,_>>>8&255,_&255);Pr[e]=K^r;if((t|0)>1)Pr[e|1]=Q^i;if((t|0)>2)Pr[e|2]=G^s;if((t|0)>3)Pr[e|3]=Y^o;if((t|0)>4)Pr[e|4]=Z^u;if((t|0)>5)Pr[e|5]=et^a;if((t|0)>6)Pr[e|6]=tt^f;if((t|0)>7)Pr[e|7]=nt^l;if((t|0)>8)Pr[e|8]=rt^c;if((t|0)>9)Pr[e|9]=it^h;if((t|0)>10)Pr[e|10]=st^p;if((t|0)>11)Pr[e|11]=ot^d;if((t|0)>12)Pr[e|12]=ut^v;if((t|0)>13)Pr[e|13]=at^m;if((t|0)>14)Pr[e|14]=ft^g;Br(K^D,Q^P,G^H,Y^B,Z^j,et^F,tt^I,nt^q,rt^R,it^U,st^z,ot^W,ut^X,at^V,ft^$,J);D=r,P=i,H=s,B=o,j=u,F=a,I=f,q=l,R=c,U=h,z=p,W=d,X=v,V=m,$=g,J=y;e=e+t|0;t=0;_=_+1|0}return 0}function Xr(e,t,n,b,w,E,S,x,T,N,C,k,L,A,O,M,_){e=e|0;t=t|0;n=n|0;b=b|0;w=w|0;E=E|0;S=S|0;x=x|0;T=T|0;N=N|0;C=C|0;k=k|0;L=L|0;A=A|0;O=O|0;M=M|0;_=_|0;var D=0,P=0,H=0,B=0,j=0,F=0,I=0,q=0,R=0,U=0,z=0,W=0,X=0,V=0,$=0,J=0,K=0,Q=0,G=0,Y=0,Z=0,et=0,tt=0,nt=0,rt=0,it=0,st=0,ot=0,ut=0,at=0,ft=0,lt=0;if(e&15)return-1;D=r,P=i,H=s,B=o,j=u,F=a,I=f,q=l,R=c,U=h,z=p,W=d,X=v,V=m,$=g,J=y;while((t|0)>=16){Br(n,b,w,E,S,x,T,N,C,k,L,A,O^_>>>24,M^_>>>16&255,_>>>8&255,_&255);Pr[e]=K=Pr[e]^r;Pr[e|1]=Q=Pr[e|1]^i;Pr[e|2]=G=Pr[e|2]^s;Pr[e|3]=Y=Pr[e|3]^o;Pr[e|4]=Z=Pr[e|4]^u;Pr[e|5]=et=Pr[e|5]^a;Pr[e|6]=tt=Pr[e|6]^f;Pr[e|7]=nt=Pr[e|7]^l;Pr[e|8]=rt=Pr[e|8]^c;Pr[e|9]=it=Pr[e|9]^h;Pr[e|10]=st=Pr[e|10]^p;Pr[e|11]=ot=Pr[e|11]^d;Pr[e|12]=ut=Pr[e|12]^v;Pr[e|13]=at=Pr[e|13]^m;Pr[e|14]=ft=Pr[e|14]^g;Pr[e|15]=lt=Pr[e|15]^y;Br(K^D,Q^P,G^H,Y^B,Z^j,et^F,tt^I,nt^q,rt^R,it^U,st^z,ot^W,ut^X,at^V,ft^$,lt^J);D=r,P=i,H=s,B=o,j=u,F=a,I=f,q=l,R=c,U=h,z=p,W=d,X=v,V=m,$=g,J=y;e=e+16|0;t=t-16|0;_=_+1|0}if((t|0)>0){Br(n,b,w,E,S,x,T,N,C,k,L,A,O^_>>>24,M^_>>>16&255,_>>>8&255,_&255);K=Pr[e]^r;Q=(t|0)>1?Pr[e|1]^i:0;G=(t|0)>2?Pr[e|2]^s:0;Y=(t|0)>3?Pr[e|3]^o:0;Z=(t|0)>4?Pr[e|4]^u:0;et=(t|0)>5?Pr[e|5]^a:0;tt=(t|0)>6?Pr[e|6]^f:0;nt=(t|0)>7?Pr[e|7]^l:0;rt=(t|0)>8?Pr[e|8]^c:0;it=(t|0)>9?Pr[e|9]^h:0;st=(t|0)>10?Pr[e|10]^p:0;ot=(t|0)>11?Pr[e|11]^d:0;ut=(t|0)>12?Pr[e|12]^v:0;at=(t|0)>13?Pr[e|13]^m:0;ft=(t|0)>14?Pr[e|14]^g:0;lt=(t|0)>15?Pr[e|15]^y:0;Pr[e]=K;if((t|0)>1)Pr[e|1]=Q;if((t|0)>2)Pr[e|2]=G;if((t|0)>3)Pr[e|3]=Y;if((t|0)>4)Pr[e|4]=Z;if((t|0)>5)Pr[e|5]=et;if((t|0)>6)Pr[e|6]=tt;if((t|0)>7)Pr[e|7]=nt;if((t|0)>8)Pr[e|8]=rt;if((t|0)>9)Pr[e|9]=it;if((t|0)>10)Pr[e|10]=st;if((t|0)>11)Pr[e|11]=ot;if((t|0)>12)Pr[e|12]=ut;if((t|0)>13)Pr[e|13]=at;if((t|0)>14)Pr[e|14]=ft;Br(K^D,Q^P,G^H,Y^B,Z^j,et^F,tt^I,nt^q,rt^R,it^U,st^z,ot^W,ut^X,at^V,ft^$,lt^J);D=r,P=i,H=s,B=o,j=u,F=a,I=f,q=l,R=c,U=h,z=p,W=d,X=v,V=m,$=g,J=y;e=e+16|0;t=t-16|0;_=_+1|0}return 0}return{init_state:Fr,save_state:Ir,init_key_128:qr,cbc_encrypt:Rr,cbc_decrypt:Ur,cbc_mac:zr,ccm_encrypt:Wr,ccm_decrypt:Xr}'))( stdlib, foreign, buffer );
}
