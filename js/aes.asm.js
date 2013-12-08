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

    function _sub_shift () {
        var t = 0;

        // row 0
        S0 = HEAP[SBOX|S0]|0;
        S4 = HEAP[SBOX|S4]|0;
        S8 = HEAP[SBOX|S8]|0;
        SC = HEAP[SBOX|SC]|0;

        // row 1
        t = HEAP[SBOX|S1]|0;
        S1 = HEAP[SBOX|S5]|0;
        S5 = HEAP[SBOX|S9]|0;
        S9 = HEAP[SBOX|SD]|0;
        SD = t;

        // row 2
        t = HEAP[SBOX|S2]|0;
        S2 = HEAP[SBOX|SA]|0;
        SA = t;
        t = HEAP[SBOX|S6]|0;
        S6 = HEAP[SBOX|SE]|0;
        SE = t;

        // row 3
        t = HEAP[SBOX|SF]|0;
        SF = HEAP[SBOX|SB]|0;
        SB = HEAP[SBOX|S7]|0;
        S7 = HEAP[SBOX|S3]|0;
        S3 = t;
    }

    function _inv_sub_shift () {
        var t = 0;

        // row 0
        S0 = HEAP[INV_SBOX|S0]|0;
        S4 = HEAP[INV_SBOX|S4]|0;
        S8 = HEAP[INV_SBOX|S8]|0;
        SC = HEAP[INV_SBOX|SC]|0;

        // row 1
        t = HEAP[INV_SBOX|SD]|0;
        SD = HEAP[INV_SBOX|S9]|0;
        S9 = HEAP[INV_SBOX|S5]|0;
        S5 = HEAP[INV_SBOX|S1]|0;
        S1 = t;

        // row 2
        t = HEAP[INV_SBOX|S2]|0;
        S2 = HEAP[INV_SBOX|SA]|0;
        SA = t;
        t = HEAP[INV_SBOX|S6]|0;
        S6 = HEAP[INV_SBOX|SE]|0;
        SE = t;

        // row 3
        t = HEAP[INV_SBOX|S3]|0;
        S3 = HEAP[INV_SBOX|S7]|0;
        S7 = HEAP[INV_SBOX|SB]|0;
        SB = HEAP[INV_SBOX|SF]|0;
        SF = t;
    }

    function _sub_shift_mix () {
        var s0 = 0, s1 = 0, s2 = 0, s3 = 0, s4 = 0, s5 = 0, s6 = 0, s7 = 0, s8 = 0, s9 = 0, sA = 0, sB = 0, sC = 0, sD = 0, sE = 0, sF = 0;

        // column 0
        s0 = HEAP[X2_SBOX|S0] ^ HEAP[X3_SBOX|S5] ^ HEAP[SBOX|SA] ^ HEAP[SBOX|SF];
        s1 = HEAP[SBOX|S0] ^ HEAP[X2_SBOX|S5] ^ HEAP[X3_SBOX|SA] ^ HEAP[SBOX|SF];
        s2 = HEAP[SBOX|S0] ^ HEAP[SBOX|S5] ^ HEAP[X2_SBOX|SA] ^ HEAP[X3_SBOX|SF];
        s3 = HEAP[X3_SBOX|S0] ^ HEAP[SBOX|S5] ^ HEAP[SBOX|SA] ^ HEAP[X2_SBOX|SF];

        // column 1
        s4 = HEAP[X2_SBOX|S4] ^ HEAP[X3_SBOX|S9] ^ HEAP[SBOX|SE] ^ HEAP[SBOX|S3];
        s5 = HEAP[SBOX|S4] ^ HEAP[X2_SBOX|S9] ^ HEAP[X3_SBOX|SE] ^ HEAP[SBOX|S3];
        s6 = HEAP[SBOX|S4] ^ HEAP[SBOX|S9] ^ HEAP[X2_SBOX|SE] ^ HEAP[X3_SBOX|S3];
        s7 = HEAP[X3_SBOX|S4] ^ HEAP[SBOX|S9] ^ HEAP[SBOX|SE] ^ HEAP[X2_SBOX|S3];

        // column 2
        s8 = HEAP[X2_SBOX|S8] ^ HEAP[X3_SBOX|SD] ^ HEAP[SBOX|S2] ^ HEAP[SBOX|S7];
        s9 = HEAP[SBOX|S8] ^ HEAP[X2_SBOX|SD] ^ HEAP[X3_SBOX|S2] ^ HEAP[SBOX|S7];
        sA = HEAP[SBOX|S8] ^ HEAP[SBOX|SD] ^ HEAP[X2_SBOX|S2] ^ HEAP[X3_SBOX|S7];
        sB = HEAP[X3_SBOX|S8] ^ HEAP[SBOX|SD] ^ HEAP[SBOX|S2] ^ HEAP[X2_SBOX|S7];

        // column 3
        sC = HEAP[X2_SBOX|SC] ^ HEAP[X3_SBOX|S1] ^ HEAP[SBOX|S6] ^ HEAP[SBOX|SB];
        sD = HEAP[SBOX|SC] ^ HEAP[X2_SBOX|S1] ^ HEAP[X3_SBOX|S6] ^ HEAP[SBOX|SB];
        sE = HEAP[SBOX|SC] ^ HEAP[SBOX|S1] ^ HEAP[X2_SBOX|S6] ^ HEAP[X3_SBOX|SB];
        sF = HEAP[X3_SBOX|SC] ^ HEAP[SBOX|S1] ^ HEAP[SBOX|S6] ^ HEAP[X2_SBOX|SB];

        S0 = s0|0;
        S1 = s1|0;
        S2 = s2|0;
        S3 = s3|0;
        S4 = s4|0;
        S5 = s5|0;
        S6 = s6|0;
        S7 = s7|0;
        S8 = s8|0;
        S9 = s9|0;
        SA = sA|0;
        SB = sB|0;
        SC = sC|0;
        SD = sD|0;
        SE = sE|0;
        SF = sF|0;
    }

    function _inv_sub_shift_mix () {
        var t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, t8 = 0, t9 = 0, tA = 0, tB = 0, tC = 0, tD = 0, tE = 0, tF = 0;

        // column 0
        t0 = HEAP[XE|S0] ^ HEAP[XB|S1] ^ HEAP[XD|S2] ^ HEAP[X9|S3];
        t5 = HEAP[X9|S0] ^ HEAP[XE|S1] ^ HEAP[XB|S2] ^ HEAP[XD|S3];
        tA = HEAP[XD|S0] ^ HEAP[X9|S1] ^ HEAP[XE|S2] ^ HEAP[XB|S3];
        tF = HEAP[XB|S0] ^ HEAP[XD|S1] ^ HEAP[X9|S2] ^ HEAP[XE|S3];

        // column 1
        t4 = HEAP[XE|S4] ^ HEAP[XB|S5] ^ HEAP[XD|S6] ^ HEAP[X9|S7];
        t9 = HEAP[X9|S4] ^ HEAP[XE|S5] ^ HEAP[XB|S6] ^ HEAP[XD|S7];
        tE = HEAP[XD|S4] ^ HEAP[X9|S5] ^ HEAP[XE|S6] ^ HEAP[XB|S7];
        t3 = HEAP[XB|S4] ^ HEAP[XD|S5] ^ HEAP[X9|S6] ^ HEAP[XE|S7];

        // column 2
        t8 = HEAP[XE|S8] ^ HEAP[XB|S9] ^ HEAP[XD|SA] ^ HEAP[X9|SB];
        tD = HEAP[X9|S8] ^ HEAP[XE|S9] ^ HEAP[XB|SA] ^ HEAP[XD|SB];
        t2 = HEAP[XD|S8] ^ HEAP[X9|S9] ^ HEAP[XE|SA] ^ HEAP[XB|SB];
        t7 = HEAP[XB|S8] ^ HEAP[XD|S9] ^ HEAP[X9|SA] ^ HEAP[XE|SB];

        // column 3
        tC = HEAP[XE|SC] ^ HEAP[XB|SD] ^ HEAP[XD|SE] ^ HEAP[X9|SF];
        t1 = HEAP[X9|SC] ^ HEAP[XE|SD] ^ HEAP[XB|SE] ^ HEAP[XD|SF];
        t6 = HEAP[XD|SC] ^ HEAP[X9|SD] ^ HEAP[XE|SE] ^ HEAP[XB|SF];
        tB = HEAP[XB|SC] ^ HEAP[XD|SD] ^ HEAP[X9|SE] ^ HEAP[XE|SF];

        S0 = HEAP[INV_SBOX|t0]|0;
        S1 = HEAP[INV_SBOX|t1]|0;
        S2 = HEAP[INV_SBOX|t2]|0;
        S3 = HEAP[INV_SBOX|t3]|0;
        S4 = HEAP[INV_SBOX|t4]|0;
        S5 = HEAP[INV_SBOX|t5]|0;
        S6 = HEAP[INV_SBOX|t6]|0;
        S7 = HEAP[INV_SBOX|t7]|0;
        S8 = HEAP[INV_SBOX|t8]|0;
        S9 = HEAP[INV_SBOX|t9]|0;
        SA = HEAP[INV_SBOX|tA]|0;
        SB = HEAP[INV_SBOX|tB]|0;
        SC = HEAP[INV_SBOX|tC]|0;
        SD = HEAP[INV_SBOX|tD]|0;
        SE = HEAP[INV_SBOX|tE]|0;
        SF = HEAP[INV_SBOX|tF]|0;
    }

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

    function _encrypt_128 () {
        // round 0
        S0 = S0 ^ R00; S1 = S1 ^ R01; S2 = S2 ^ R02; S3 = S3 ^ R03; S4 = S4 ^ R04; S5 = S5 ^ R05; S6 = S6 ^ R06; S7 = S7 ^ R07; S8 = S8 ^ R08; S9 = S9 ^ R09; SA = SA ^ R0A; SB = SB ^ R0B; SC = SC ^ R0C; SD = SD ^ R0D; SE = SE ^ R0E; SF = SF ^ R0F;

        // round 1
        _sub_shift_mix();
        S0 = S0 ^ R10; S1 = S1 ^ R11; S2 = S2 ^ R12; S3 = S3 ^ R13; S4 = S4 ^ R14; S5 = S5 ^ R15; S6 = S6 ^ R16; S7 = S7 ^ R17; S8 = S8 ^ R18; S9 = S9 ^ R19; SA = SA ^ R1A; SB = SB ^ R1B; SC = SC ^ R1C; SD = SD ^ R1D; SE = SE ^ R1E; SF = SF ^ R1F;

        // round 2
        _sub_shift_mix();
        S0 = S0 ^ R20; S1 = S1 ^ R21; S2 = S2 ^ R22; S3 = S3 ^ R23; S4 = S4 ^ R24; S5 = S5 ^ R25; S6 = S6 ^ R26; S7 = S7 ^ R27; S8 = S8 ^ R28; S9 = S9 ^ R29; SA = SA ^ R2A; SB = SB ^ R2B; SC = SC ^ R2C; SD = SD ^ R2D; SE = SE ^ R2E; SF = SF ^ R2F;

        // round 3
        _sub_shift_mix();
        S0 = S0 ^ R30; S1 = S1 ^ R31; S2 = S2 ^ R32; S3 = S3 ^ R33; S4 = S4 ^ R34; S5 = S5 ^ R35; S6 = S6 ^ R36; S7 = S7 ^ R37; S8 = S8 ^ R38; S9 = S9 ^ R39; SA = SA ^ R3A; SB = SB ^ R3B; SC = SC ^ R3C; SD = SD ^ R3D; SE = SE ^ R3E; SF = SF ^ R3F;

        // round 4
        _sub_shift_mix();
        S0 = S0 ^ R40; S1 = S1 ^ R41; S2 = S2 ^ R42; S3 = S3 ^ R43; S4 = S4 ^ R44; S5 = S5 ^ R45; S6 = S6 ^ R46; S7 = S7 ^ R47; S8 = S8 ^ R48; S9 = S9 ^ R49; SA = SA ^ R4A; SB = SB ^ R4B; SC = SC ^ R4C; SD = SD ^ R4D; SE = SE ^ R4E; SF = SF ^ R4F;

        // round 5
        _sub_shift_mix();
        S0 = S0 ^ R50; S1 = S1 ^ R51; S2 = S2 ^ R52; S3 = S3 ^ R53; S4 = S4 ^ R54; S5 = S5 ^ R55; S6 = S6 ^ R56; S7 = S7 ^ R57; S8 = S8 ^ R58; S9 = S9 ^ R59; SA = SA ^ R5A; SB = SB ^ R5B; SC = SC ^ R5C; SD = SD ^ R5D; SE = SE ^ R5E; SF = SF ^ R5F;

        // round 6
        _sub_shift_mix();
        S0 = S0 ^ R60; S1 = S1 ^ R61; S2 = S2 ^ R62; S3 = S3 ^ R63; S4 = S4 ^ R64; S5 = S5 ^ R65; S6 = S6 ^ R66; S7 = S7 ^ R67; S8 = S8 ^ R68; S9 = S9 ^ R69; SA = SA ^ R6A; SB = SB ^ R6B; SC = SC ^ R6C; SD = SD ^ R6D; SE = SE ^ R6E; SF = SF ^ R6F;

        // round 7
        _sub_shift_mix();
        S0 = S0 ^ R70; S1 = S1 ^ R71; S2 = S2 ^ R72; S3 = S3 ^ R73; S4 = S4 ^ R74; S5 = S5 ^ R75; S6 = S6 ^ R76; S7 = S7 ^ R77; S8 = S8 ^ R78; S9 = S9 ^ R79; SA = SA ^ R7A; SB = SB ^ R7B; SC = SC ^ R7C; SD = SD ^ R7D; SE = SE ^ R7E; SF = SF ^ R7F;

        // round 8
        _sub_shift_mix();
        S0 = S0 ^ R80; S1 = S1 ^ R81; S2 = S2 ^ R82; S3 = S3 ^ R83; S4 = S4 ^ R84; S5 = S5 ^ R85; S6 = S6 ^ R86; S7 = S7 ^ R87; S8 = S8 ^ R88; S9 = S9 ^ R89; SA = SA ^ R8A; SB = SB ^ R8B; SC = SC ^ R8C; SD = SD ^ R8D; SE = SE ^ R8E; SF = SF ^ R8F;

        // round 9
        _sub_shift_mix();
        S0 = S0 ^ R90; S1 = S1 ^ R91; S2 = S2 ^ R92; S3 = S3 ^ R93; S4 = S4 ^ R94; S5 = S5 ^ R95; S6 = S6 ^ R96; S7 = S7 ^ R97; S8 = S8 ^ R98; S9 = S9 ^ R99; SA = SA ^ R9A; SB = SB ^ R9B; SC = SC ^ R9C; SD = SD ^ R9D; SE = SE ^ R9E; SF = SF ^ R9F;

        // round 10
        _sub_shift();
        S0 = S0 ^ RA0; S1 = S1 ^ RA1; S2 = S2 ^ RA2; S3 = S3 ^ RA3; S4 = S4 ^ RA4; S5 = S5 ^ RA5; S6 = S6 ^ RA6; S7 = S7 ^ RA7; S8 = S8 ^ RA8; S9 = S9 ^ RA9; SA = SA ^ RAA; SB = SB ^ RAB; SC = SC ^ RAC; SD = SD ^ RAD; SE = SE ^ RAE; SF = SF ^ RAF;
    }

    function _decrypt_128 () {
        // round 10
        S0 = S0 ^ RA0; S1 = S1 ^ RA1; S2 = S2 ^ RA2; S3 = S3 ^ RA3; S4 = S4 ^ RA4; S5 = S5 ^ RA5; S6 = S6 ^ RA6; S7 = S7 ^ RA7; S8 = S8 ^ RA8; S9 = S9 ^ RA9; SA = SA ^ RAA; SB = SB ^ RAB; SC = SC ^ RAC; SD = SD ^ RAD; SE = SE ^ RAE; SF = SF ^ RAF;
        _inv_sub_shift();

        // round 9
        S0 = S0 ^ R90; S1 = S1 ^ R91; S2 = S2 ^ R92; S3 = S3 ^ R93; S4 = S4 ^ R94; S5 = S5 ^ R95; S6 = S6 ^ R96; S7 = S7 ^ R97; S8 = S8 ^ R98; S9 = S9 ^ R99; SA = SA ^ R9A; SB = SB ^ R9B; SC = SC ^ R9C; SD = SD ^ R9D; SE = SE ^ R9E; SF = SF ^ R9F;
        _inv_sub_shift_mix();

        // round 8
        S0 = S0 ^ R80; S1 = S1 ^ R81; S2 = S2 ^ R82; S3 = S3 ^ R83; S4 = S4 ^ R84; S5 = S5 ^ R85; S6 = S6 ^ R86; S7 = S7 ^ R87; S8 = S8 ^ R88; S9 = S9 ^ R89; SA = SA ^ R8A; SB = SB ^ R8B; SC = SC ^ R8C; SD = SD ^ R8D; SE = SE ^ R8E; SF = SF ^ R8F;
        _inv_sub_shift_mix();

        // round 7
        S0 = S0 ^ R70; S1 = S1 ^ R71; S2 = S2 ^ R72; S3 = S3 ^ R73; S4 = S4 ^ R74; S5 = S5 ^ R75; S6 = S6 ^ R76; S7 = S7 ^ R77; S8 = S8 ^ R78; S9 = S9 ^ R79; SA = SA ^ R7A; SB = SB ^ R7B; SC = SC ^ R7C; SD = SD ^ R7D; SE = SE ^ R7E; SF = SF ^ R7F;
        _inv_sub_shift_mix();

        // round 6
        S0 = S0 ^ R60; S1 = S1 ^ R61; S2 = S2 ^ R62; S3 = S3 ^ R63; S4 = S4 ^ R64; S5 = S5 ^ R65; S6 = S6 ^ R66; S7 = S7 ^ R67; S8 = S8 ^ R68; S9 = S9 ^ R69; SA = SA ^ R6A; SB = SB ^ R6B; SC = SC ^ R6C; SD = SD ^ R6D; SE = SE ^ R6E; SF = SF ^ R6F;
        _inv_sub_shift_mix();

        // round 5
        S0 = S0 ^ R50; S1 = S1 ^ R51; S2 = S2 ^ R52; S3 = S3 ^ R53; S4 = S4 ^ R54; S5 = S5 ^ R55; S6 = S6 ^ R56; S7 = S7 ^ R57; S8 = S8 ^ R58; S9 = S9 ^ R59; SA = SA ^ R5A; SB = SB ^ R5B; SC = SC ^ R5C; SD = SD ^ R5D; SE = SE ^ R5E; SF = SF ^ R5F;
        _inv_sub_shift_mix();

        // round 4
        S0 = S0 ^ R40; S1 = S1 ^ R41; S2 = S2 ^ R42; S3 = S3 ^ R43; S4 = S4 ^ R44; S5 = S5 ^ R45; S6 = S6 ^ R46; S7 = S7 ^ R47; S8 = S8 ^ R48; S9 = S9 ^ R49; SA = SA ^ R4A; SB = SB ^ R4B; SC = SC ^ R4C; SD = SD ^ R4D; SE = SE ^ R4E; SF = SF ^ R4F;
        _inv_sub_shift_mix();

        // round 3
        S0 = S0 ^ R30; S1 = S1 ^ R31; S2 = S2 ^ R32; S3 = S3 ^ R33; S4 = S4 ^ R34; S5 = S5 ^ R35; S6 = S6 ^ R36; S7 = S7 ^ R37; S8 = S8 ^ R38; S9 = S9 ^ R39; SA = SA ^ R3A; SB = SB ^ R3B; SC = SC ^ R3C; SD = SD ^ R3D; SE = SE ^ R3E; SF = SF ^ R3F;
        _inv_sub_shift_mix();

        // round 2
        S0 = S0 ^ R20; S1 = S1 ^ R21; S2 = S2 ^ R22; S3 = S3 ^ R23; S4 = S4 ^ R24; S5 = S5 ^ R25; S6 = S6 ^ R26; S7 = S7 ^ R27; S8 = S8 ^ R28; S9 = S9 ^ R29; SA = SA ^ R2A; SB = SB ^ R2B; SC = SC ^ R2C; SD = SD ^ R2D; SE = SE ^ R2E; SF = SF ^ R2F;
        _inv_sub_shift_mix();

        // round 1
        S0 = S0 ^ R10; S1 = S1 ^ R11; S2 = S2 ^ R12; S3 = S3 ^ R13; S4 = S4 ^ R14; S5 = S5 ^ R15; S6 = S6 ^ R16; S7 = S7 ^ R17; S8 = S8 ^ R18; S9 = S9 ^ R19; SA = SA ^ R1A; SB = SB ^ R1B; SC = SC ^ R1C; SD = SD ^ R1D; SE = SE ^ R1E; SF = SF ^ R1F;
        _inv_sub_shift_mix();

        // round 0
        S0 = S0 ^ R00; S1 = S1 ^ R01; S2 = S2 ^ R02; S3 = S3 ^ R03; S4 = S4 ^ R04; S5 = S5 ^ R05; S6 = S6 ^ R06; S7 = S7 ^ R07; S8 = S8 ^ R08; S9 = S9 ^ R09; SA = SA ^ R0A; SB = SB ^ R0B; SC = SC ^ R0C; SD = SD ^ R0D; SE = SE ^ R0E; SF = SF ^ R0F;
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
            S0 = S0 ^ HEAP[offset];
            S1 = S1 ^ HEAP[offset|1];
            S2 = S2 ^ HEAP[offset|2];
            S3 = S3 ^ HEAP[offset|3];
            S4 = S4 ^ HEAP[offset|4];
            S5 = S5 ^ HEAP[offset|5];
            S6 = S6 ^ HEAP[offset|6];
            S7 = S7 ^ HEAP[offset|7];
            S8 = S8 ^ HEAP[offset|8];
            S9 = S9 ^ HEAP[offset|9];
            SA = SA ^ HEAP[offset|10];
            SB = SB ^ HEAP[offset|11];
            SC = SC ^ HEAP[offset|12];
            SD = SD ^ HEAP[offset|13];
            SE = SE ^ HEAP[offset|14];
            SF = SF ^ HEAP[offset|15];

            _encrypt_128();

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
            S0 = HEAP[offset]|0;
            S1 = HEAP[offset|1]|0;
            S2 = HEAP[offset|2]|0;
            S3 = HEAP[offset|3]|0;
            S4 = HEAP[offset|4]|0;
            S5 = HEAP[offset|5]|0;
            S6 = HEAP[offset|6]|0;
            S7 = HEAP[offset|7]|0;
            S8 = HEAP[offset|8]|0;
            S9 = HEAP[offset|9]|0;
            SA = HEAP[offset|10]|0;
            SB = HEAP[offset|11]|0;
            SC = HEAP[offset|12]|0;
            SD = HEAP[offset|13]|0;
            SE = HEAP[offset|14]|0;
            SF = HEAP[offset|15]|0;

            _decrypt_128();

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
            S0 = S0 ^ HEAP[offset];
            S1 = S1 ^ HEAP[offset|1];
            S2 = S2 ^ HEAP[offset|2];
            S3 = S3 ^ HEAP[offset|3];
            S4 = S4 ^ HEAP[offset|4];
            S5 = S5 ^ HEAP[offset|5];
            S6 = S6 ^ HEAP[offset|6];
            S7 = S7 ^ HEAP[offset|7];
            S8 = S8 ^ HEAP[offset|8];
            S9 = S9 ^ HEAP[offset|9];
            SA = SA ^ HEAP[offset|10];
            SB = SB ^ HEAP[offset|11];
            SC = SC ^ HEAP[offset|12];
            SD = SD ^ HEAP[offset|13];
            SE = SE ^ HEAP[offset|14];
            SF = SF ^ HEAP[offset|15];

            _encrypt_128();

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

            _encrypt_128();

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

            S0 = nonce0, S1 = nonce1, S2 = nonce2, S3 = nonce3, S4 = nonce4, S5 = nonce5, S6 = nonce6, S7 = nonce7, S8 = nonce8, S9 = nonce9, SA = nonceA, SB = nonceB;
            SC = nonceC ^ (counter>>>24); SD = nonceD ^ (counter>>>16&255), SE = counter>>>8&255, SF = counter&255;

            _encrypt_128();

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

            S0 = s0 ^ iv0;
            S1 = s1 ^ iv1;
            S2 = s2 ^ iv2;
            S3 = s3 ^ iv3;
            S4 = s4 ^ iv4;
            S5 = s5 ^ iv5;
            S6 = s6 ^ iv6;
            S7 = s7 ^ iv7;
            S8 = s8 ^ iv8;
            S9 = s9 ^ iv9;
            SA = sA ^ ivA;
            SB = sB ^ ivB;
            SC = sC ^ ivC;
            SD = sD ^ ivD;
            SE = sE ^ ivE;
            SF = sF ^ ivF;

            _encrypt_128();

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

            S0 = nonce0, S1 = nonce1, S2 = nonce2, S3 = nonce3, S4 = nonce4, S5 = nonce5, S6 = nonce6, S7 = nonce7, S8 = nonce8, S9 = nonce9, SA = nonceA, SB = nonceB;
            SC = nonceC ^ (counter>>>24); SD = nonceD ^ (counter>>>16&255), SE = counter>>>8&255, SF = counter&255;

            _encrypt_128();

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

            S0 = s0 ^ iv0;
            S1 = s1 ^ iv1;
            S2 = s2 ^ iv2;
            S3 = s3 ^ iv3;
            S4 = s4 ^ iv4;
            S5 = s5 ^ iv5;
            S6 = s6 ^ iv6;
            S7 = s7 ^ iv7;
            S8 = s8 ^ iv8;
            S9 = s9 ^ iv9;
            SA = sA ^ ivA;
            SB = sB ^ ivB;
            SC = sC ^ ivC;
            SD = sD ^ ivD;
            SE = sE ^ ivE;
            SF = ivF; // sF = 0

            _encrypt_128();

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

            S0 = nonce0, S1 = nonce1, S2 = nonce2, S3 = nonce3, S4 = nonce4, S5 = nonce5, S6 = nonce6, S7 = nonce7, S8 = nonce8, S9 = nonce9, SA = nonceA, SB = nonceB;
            SC = nonceC ^ (counter>>>24); SD = nonceD ^ (counter>>>16&255), SE = counter>>>8&255, SF = counter&255;

            _encrypt_128();

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

            S0 = s0 ^ iv0;
            S1 = s1 ^ iv1;
            S2 = s2 ^ iv2;
            S3 = s3 ^ iv3;
            S4 = s4 ^ iv4;
            S5 = s5 ^ iv5;
            S6 = s6 ^ iv6;
            S7 = s7 ^ iv7;
            S8 = s8 ^ iv8;
            S9 = s9 ^ iv9;
            SA = sA ^ ivA;
            SB = sB ^ ivB;
            SC = sC ^ ivC;
            SD = sD ^ ivD;
            SE = sE ^ ivE;
            SF = sF ^ ivF;

            _encrypt_128();

            iv0 = S0, iv1 = S1, iv2 = S2, iv3 = S3, iv4 = S4, iv5 = S5, iv6 = S6, iv7 = S7, iv8 = S8, iv9 = S9, ivA = SA, ivB = SB, ivC = SC, ivD = SD, ivE = SE, ivF = SF;

            offset = (offset + 16)|0;
            length = (length - 16)|0;
            counter = (counter + 1)|0;
        }
        if ( (length|0) > 0 ) {
            //
            // Cipher
            //

            S0 = nonce0, S1 = nonce1, S2 = nonce2, S3 = nonce3, S4 = nonce4, S5 = nonce5, S6 = nonce6, S7 = nonce7, S8 = nonce8, S9 = nonce9, SA = nonceA, SB = nonceB;
            SC = nonceC ^ (counter>>>24); SD = nonceD ^ (counter>>>16&255), SE = counter>>>8&255, SF = counter&255;

            _encrypt_128();

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

            S0 = s0 ^ iv0;
            S1 = s1 ^ iv1;
            S2 = s2 ^ iv2;
            S3 = s3 ^ iv3;
            S4 = s4 ^ iv4;
            S5 = s5 ^ iv5;
            S6 = s6 ^ iv6;
            S7 = s7 ^ iv7;
            S8 = s8 ^ iv8;
            S9 = s9 ^ iv9;
            SA = sA ^ ivA;
            SB = sB ^ ivB;
            SC = sC ^ ivC;
            SD = sD ^ ivD;
            SE = sE ^ ivE;
            SF = sF ^ ivF;

            _encrypt_128();

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
    return (new Function('e,t,n','"use asm";var r=0,i=256,s=512,o=768,u=1024,a=1280,f=1536,l=1792,c=0,h=0,p=0,d=0,v=0,m=0,g=0,y=0,b=0,w=0,E=0,S=0,x=0,T=0,N=0,C=0,k=0,L=0,A=0,O=0,M=0,_=0,D=0,P=0,H=0,B=0,j=0,F=0,I=0,q=0,R=0,U=0,z=0,W=0,X=0,V=0,$=0,J=0,K=0,Q=0,G=0,Y=0,Z=0,et=0,tt=0,nt=0,rt=0,it=0,st=0,ot=0,ut=0,at=0,ft=0,lt=0,ct=0,ht=0,pt=0,dt=0,vt=0,mt=0,gt=0,yt=0,bt=0,wt=0,Et=0,St=0,xt=0,Tt=0,Nt=0,Ct=0,kt=0,Lt=0,At=0,Ot=0,Mt=0,_t=0,Dt=0,Pt=0,Ht=0,Bt=0,jt=0,Ft=0,It=0,qt=0,Rt=0,Ut=0,zt=0,Wt=0,Xt=0,Vt=0,$t=0,Jt=0,Kt=0,Qt=0,Gt=0,Yt=0,Zt=0,en=0,tn=0,nn=0,rn=0,sn=0,on=0,un=0,an=0,fn=0,ln=0,cn=0,hn=0,pn=0,dn=0,vn=0,mn=0,gn=0,yn=0,bn=0,wn=0,En=0,Sn=0,xn=0,Tn=0,Nn=0,Cn=0,kn=0,Ln=0,An=0,On=0,Mn=0,_n=0,Dn=0,Pn=0,Hn=0,Bn=0,jn=0,Fn=0,In=0,qn=0,Rn=0,Un=0,zn=0,Wn=0,Xn=0,Vn=0,$n=0,Jn=0,Kn=0,Qn=0,Gn=0,Yn=0,Zn=0,er=0,tr=0,nr=0,rr=0,ir=0,sr=0,or=0,ur=0,ar=0,fr=0,lr=0,cr=0,hr=0,pr=0,dr=0,vr=0,mr=0,gr=0,yr=0,br=0,wr=0,Er=0,Sr=0,xr=0,Tr=0,Nr=0,Cr=0,kr=0,Lr=0,Ar=0,Or=0,Mr=0,_r=0,Dr=0,Pr=0,Hr=0,Br=0,jr=0,Fr=0,Ir=0,qr=0,Rr=0;var Ur=new e.Uint8Array(n);function zr(){var e=0;c=Ur[r|c]|0;v=Ur[r|v]|0;b=Ur[r|b]|0;x=Ur[r|x]|0;e=Ur[r|h]|0;h=Ur[r|m]|0;m=Ur[r|w]|0;w=Ur[r|T]|0;T=e;e=Ur[r|p]|0;p=Ur[r|E]|0;E=e;e=Ur[r|g]|0;g=Ur[r|N]|0;N=e;e=Ur[r|C]|0;C=Ur[r|S]|0;S=Ur[r|y]|0;y=Ur[r|d]|0;d=e}function Wr(){var e=0;c=Ur[i|c]|0;v=Ur[i|v]|0;b=Ur[i|b]|0;x=Ur[i|x]|0;e=Ur[i|T]|0;T=Ur[i|w]|0;w=Ur[i|m]|0;m=Ur[i|h]|0;h=e;e=Ur[i|p]|0;p=Ur[i|E]|0;E=e;e=Ur[i|g]|0;g=Ur[i|N]|0;N=e;e=Ur[i|d]|0;d=Ur[i|y]|0;y=Ur[i|S]|0;S=Ur[i|C]|0;C=e}function Xr(){var e=0,t=0,n=0,i=0,u=0,a=0,f=0,l=0,k=0,L=0,A=0,O=0,M=0,_=0,D=0,P=0;e=Ur[s|c]^Ur[o|m]^Ur[r|E]^Ur[r|C];t=Ur[r|c]^Ur[s|m]^Ur[o|E]^Ur[r|C];n=Ur[r|c]^Ur[r|m]^Ur[s|E]^Ur[o|C];i=Ur[o|c]^Ur[r|m]^Ur[r|E]^Ur[s|C];u=Ur[s|v]^Ur[o|w]^Ur[r|N]^Ur[r|d];a=Ur[r|v]^Ur[s|w]^Ur[o|N]^Ur[r|d];f=Ur[r|v]^Ur[r|w]^Ur[s|N]^Ur[o|d];l=Ur[o|v]^Ur[r|w]^Ur[r|N]^Ur[s|d];k=Ur[s|b]^Ur[o|T]^Ur[r|p]^Ur[r|y];L=Ur[r|b]^Ur[s|T]^Ur[o|p]^Ur[r|y];A=Ur[r|b]^Ur[r|T]^Ur[s|p]^Ur[o|y];O=Ur[o|b]^Ur[r|T]^Ur[r|p]^Ur[s|y];M=Ur[s|x]^Ur[o|h]^Ur[r|g]^Ur[r|S];_=Ur[r|x]^Ur[s|h]^Ur[o|g]^Ur[r|S];D=Ur[r|x]^Ur[r|h]^Ur[s|g]^Ur[o|S];P=Ur[o|x]^Ur[r|h]^Ur[r|g]^Ur[s|S];c=e|0;h=t|0;p=n|0;d=i|0;v=u|0;m=a|0;g=f|0;y=l|0;b=k|0;w=L|0;E=A|0;S=O|0;x=M|0;T=_|0;N=D|0;C=P|0}function Vr(){var e=0,t=0,n=0,r=0,s=0,o=0,k=0,L=0,A=0,O=0,M=0,_=0,D=0,P=0,H=0,B=0;e=Ur[l|c]^Ur[a|h]^Ur[f|p]^Ur[u|d];o=Ur[u|c]^Ur[l|h]^Ur[a|p]^Ur[f|d];M=Ur[f|c]^Ur[u|h]^Ur[l|p]^Ur[a|d];B=Ur[a|c]^Ur[f|h]^Ur[u|p]^Ur[l|d];s=Ur[l|v]^Ur[a|m]^Ur[f|g]^Ur[u|y];O=Ur[u|v]^Ur[l|m]^Ur[a|g]^Ur[f|y];H=Ur[f|v]^Ur[u|m]^Ur[l|g]^Ur[a|y];r=Ur[a|v]^Ur[f|m]^Ur[u|g]^Ur[l|y];A=Ur[l|b]^Ur[a|w]^Ur[f|E]^Ur[u|S];P=Ur[u|b]^Ur[l|w]^Ur[a|E]^Ur[f|S];n=Ur[f|b]^Ur[u|w]^Ur[l|E]^Ur[a|S];L=Ur[a|b]^Ur[f|w]^Ur[u|E]^Ur[l|S];D=Ur[l|x]^Ur[a|T]^Ur[f|N]^Ur[u|C];t=Ur[u|x]^Ur[l|T]^Ur[a|N]^Ur[f|C];k=Ur[f|x]^Ur[u|T]^Ur[l|N]^Ur[a|C];_=Ur[a|x]^Ur[f|T]^Ur[u|N]^Ur[l|C];c=Ur[i|e]|0;h=Ur[i|t]|0;p=Ur[i|n]|0;d=Ur[i|r]|0;v=Ur[i|s]|0;m=Ur[i|o]|0;g=Ur[i|k]|0;y=Ur[i|L]|0;b=Ur[i|A]|0;w=Ur[i|O]|0;E=Ur[i|M]|0;S=Ur[i|_]|0;x=Ur[i|D]|0;T=Ur[i|P]|0;N=Ur[i|H]|0;C=Ur[i|B]|0}function $r(){z=k^Ur[r|q]^1;W=L^Ur[r|R];X=A^Ur[r|U];V=O^Ur[r|I];$=M^z;J=_^W;K=D^X;Q=P^V;G=H^$;Y=B^J;Z=j^K;et=F^Q;tt=I^G;nt=q^Y;rt=R^Z;it=U^et;st=z^Ur[r|nt]^2;ot=W^Ur[r|rt];ut=X^Ur[r|it];at=V^Ur[r|tt];ft=$^st;lt=J^ot;ct=K^ut;ht=Q^at;pt=G^ft;dt=Y^lt;vt=Z^ct;mt=et^ht;gt=tt^pt;yt=nt^dt;bt=rt^vt;wt=it^mt;Et=st^Ur[r|yt]^4;St=ot^Ur[r|bt];xt=ut^Ur[r|wt];Tt=at^Ur[r|gt];Nt=ft^Et;Ct=lt^St;kt=ct^xt;Lt=ht^Tt;At=pt^Nt;Ot=dt^Ct;Mt=vt^kt;_t=mt^Lt;Dt=gt^At;Pt=yt^Ot;Ht=bt^Mt;Bt=wt^_t;jt=Et^Ur[r|Pt]^8;Ft=St^Ur[r|Ht];It=xt^Ur[r|Bt];qt=Tt^Ur[r|Dt];Rt=Nt^jt;Ut=Ct^Ft;zt=kt^It;Wt=Lt^qt;Xt=At^Rt;Vt=Ot^Ut;$t=Mt^zt;Jt=_t^Wt;Kt=Dt^Xt;Qt=Pt^Vt;Gt=Ht^$t;Yt=Bt^Jt;Zt=jt^Ur[r|Qt]^16;en=Ft^Ur[r|Gt];tn=It^Ur[r|Yt];nn=qt^Ur[r|Kt];rn=Rt^Zt;sn=Ut^en;on=zt^tn;un=Wt^nn;an=Xt^rn;fn=Vt^sn;ln=$t^on;cn=Jt^un;hn=Kt^an;pn=Qt^fn;dn=Gt^ln;vn=Yt^cn;mn=Zt^Ur[r|pn]^32;gn=en^Ur[r|dn];yn=tn^Ur[r|vn];bn=nn^Ur[r|hn];wn=rn^mn;En=sn^gn;Sn=on^yn;xn=un^bn;Tn=an^wn;Nn=fn^En;Cn=ln^Sn;kn=cn^xn;Ln=hn^Tn;An=pn^Nn;On=dn^Cn;Mn=vn^kn;_n=mn^Ur[r|An]^64;Dn=gn^Ur[r|On];Pn=yn^Ur[r|Mn];Hn=bn^Ur[r|Ln];Bn=wn^_n;jn=En^Dn;Fn=Sn^Pn;In=xn^Hn;qn=Tn^Bn;Rn=Nn^jn;Un=Cn^Fn;zn=kn^In;Wn=Ln^qn;Xn=An^Rn;Vn=On^Un;$n=Mn^zn;Jn=_n^Ur[r|Xn]^128;Kn=Dn^Ur[r|Vn];Qn=Pn^Ur[r|$n];Gn=Hn^Ur[r|Wn];Yn=Bn^Jn;Zn=jn^Kn;er=Fn^Qn;tr=In^Gn;nr=qn^Yn;rr=Rn^Zn;ir=Un^er;sr=zn^tr;or=Wn^nr;ur=Xn^rr;ar=Vn^ir;fr=$n^sr;lr=Jn^Ur[r|ur]^27;cr=Kn^Ur[r|ar];hr=Qn^Ur[r|fr];pr=Gn^Ur[r|or];dr=Yn^lr;vr=Zn^cr;mr=er^hr;gr=tr^pr;yr=nr^dr;br=rr^vr;wr=ir^mr;Er=sr^gr;Sr=or^yr;xr=ur^br;Tr=ar^wr;Nr=fr^Er;Cr=lr^Ur[r|xr]^54;kr=cr^Ur[r|Tr];Lr=hr^Ur[r|Nr];Ar=pr^Ur[r|Sr];Or=dr^Cr;Mr=vr^kr;_r=mr^Lr;Dr=gr^Ar;Pr=yr^Or;Hr=br^Mr;Br=wr^_r;jr=Er^Dr;Fr=Sr^Pr;Ir=xr^Hr;qr=Tr^Br;Rr=Nr^jr}function Jr(){c=c^k;h=h^L;p=p^A;d=d^O;v=v^M;m=m^_;g=g^D;y=y^P;b=b^H;w=w^B;E=E^j;S=S^F;x=x^I;T=T^q;N=N^R;C=C^U;Xr();c=c^z;h=h^W;p=p^X;d=d^V;v=v^$;m=m^J;g=g^K;y=y^Q;b=b^G;w=w^Y;E=E^Z;S=S^et;x=x^tt;T=T^nt;N=N^rt;C=C^it;Xr();c=c^st;h=h^ot;p=p^ut;d=d^at;v=v^ft;m=m^lt;g=g^ct;y=y^ht;b=b^pt;w=w^dt;E=E^vt;S=S^mt;x=x^gt;T=T^yt;N=N^bt;C=C^wt;Xr();c=c^Et;h=h^St;p=p^xt;d=d^Tt;v=v^Nt;m=m^Ct;g=g^kt;y=y^Lt;b=b^At;w=w^Ot;E=E^Mt;S=S^_t;x=x^Dt;T=T^Pt;N=N^Ht;C=C^Bt;Xr();c=c^jt;h=h^Ft;p=p^It;d=d^qt;v=v^Rt;m=m^Ut;g=g^zt;y=y^Wt;b=b^Xt;w=w^Vt;E=E^$t;S=S^Jt;x=x^Kt;T=T^Qt;N=N^Gt;C=C^Yt;Xr();c=c^Zt;h=h^en;p=p^tn;d=d^nn;v=v^rn;m=m^sn;g=g^on;y=y^un;b=b^an;w=w^fn;E=E^ln;S=S^cn;x=x^hn;T=T^pn;N=N^dn;C=C^vn;Xr();c=c^mn;h=h^gn;p=p^yn;d=d^bn;v=v^wn;m=m^En;g=g^Sn;y=y^xn;b=b^Tn;w=w^Nn;E=E^Cn;S=S^kn;x=x^Ln;T=T^An;N=N^On;C=C^Mn;Xr();c=c^_n;h=h^Dn;p=p^Pn;d=d^Hn;v=v^Bn;m=m^jn;g=g^Fn;y=y^In;b=b^qn;w=w^Rn;E=E^Un;S=S^zn;x=x^Wn;T=T^Xn;N=N^Vn;C=C^$n;Xr();c=c^Jn;h=h^Kn;p=p^Qn;d=d^Gn;v=v^Yn;m=m^Zn;g=g^er;y=y^tr;b=b^nr;w=w^rr;E=E^ir;S=S^sr;x=x^or;T=T^ur;N=N^ar;C=C^fr;Xr();c=c^lr;h=h^cr;p=p^hr;d=d^pr;v=v^dr;m=m^vr;g=g^mr;y=y^gr;b=b^yr;w=w^br;E=E^wr;S=S^Er;x=x^Sr;T=T^xr;N=N^Tr;C=C^Nr;zr();c=c^Cr;h=h^kr;p=p^Lr;d=d^Ar;v=v^Or;m=m^Mr;g=g^_r;y=y^Dr;b=b^Pr;w=w^Hr;E=E^Br;S=S^jr;x=x^Fr;T=T^Ir;N=N^qr;C=C^Rr}function Kr(){c=c^Cr;h=h^kr;p=p^Lr;d=d^Ar;v=v^Or;m=m^Mr;g=g^_r;y=y^Dr;b=b^Pr;w=w^Hr;E=E^Br;S=S^jr;x=x^Fr;T=T^Ir;N=N^qr;C=C^Rr;Wr();c=c^lr;h=h^cr;p=p^hr;d=d^pr;v=v^dr;m=m^vr;g=g^mr;y=y^gr;b=b^yr;w=w^br;E=E^wr;S=S^Er;x=x^Sr;T=T^xr;N=N^Tr;C=C^Nr;Vr();c=c^Jn;h=h^Kn;p=p^Qn;d=d^Gn;v=v^Yn;m=m^Zn;g=g^er;y=y^tr;b=b^nr;w=w^rr;E=E^ir;S=S^sr;x=x^or;T=T^ur;N=N^ar;C=C^fr;Vr();c=c^_n;h=h^Dn;p=p^Pn;d=d^Hn;v=v^Bn;m=m^jn;g=g^Fn;y=y^In;b=b^qn;w=w^Rn;E=E^Un;S=S^zn;x=x^Wn;T=T^Xn;N=N^Vn;C=C^$n;Vr();c=c^mn;h=h^gn;p=p^yn;d=d^bn;v=v^wn;m=m^En;g=g^Sn;y=y^xn;b=b^Tn;w=w^Nn;E=E^Cn;S=S^kn;x=x^Ln;T=T^An;N=N^On;C=C^Mn;Vr();c=c^Zt;h=h^en;p=p^tn;d=d^nn;v=v^rn;m=m^sn;g=g^on;y=y^un;b=b^an;w=w^fn;E=E^ln;S=S^cn;x=x^hn;T=T^pn;N=N^dn;C=C^vn;Vr();c=c^jt;h=h^Ft;p=p^It;d=d^qt;v=v^Rt;m=m^Ut;g=g^zt;y=y^Wt;b=b^Xt;w=w^Vt;E=E^$t;S=S^Jt;x=x^Kt;T=T^Qt;N=N^Gt;C=C^Yt;Vr();c=c^Et;h=h^St;p=p^xt;d=d^Tt;v=v^Nt;m=m^Ct;g=g^kt;y=y^Lt;b=b^At;w=w^Ot;E=E^Mt;S=S^_t;x=x^Dt;T=T^Pt;N=N^Ht;C=C^Bt;Vr();c=c^st;h=h^ot;p=p^ut;d=d^at;v=v^ft;m=m^lt;g=g^ct;y=y^ht;b=b^pt;w=w^dt;E=E^vt;S=S^mt;x=x^gt;T=T^yt;N=N^bt;C=C^wt;Vr();c=c^z;h=h^W;p=p^X;d=d^V;v=v^$;m=m^J;g=g^K;y=y^Q;b=b^G;w=w^Y;E=E^Z;S=S^et;x=x^tt;T=T^nt;N=N^rt;C=C^it;Vr();c=c^k;h=h^L;p=p^A;d=d^O;v=v^M;m=m^_;g=g^D;y=y^P;b=b^H;w=w^B;E=E^j;S=S^F;x=x^I;T=T^q;N=N^R;C=C^U}function Qr(e,t,n,r,i,s,o,u,a,f,l,k,L,A,O,M){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;s=s|0;o=o|0;u=u|0;a=a|0;f=f|0;l=l|0;k=k|0;L=L|0;A=A|0;O=O|0;M=M|0;c=e;h=t;p=n;d=r;v=i;m=s;g=o;y=u;b=a;w=f;E=l;S=k;x=L;T=A;N=O;C=M}function Gr(e){e=e|0;Ur[e]=c;Ur[e|1]=h;Ur[e|2]=p;Ur[e|3]=d;Ur[e|4]=v;Ur[e|5]=m;Ur[e|6]=g;Ur[e|7]=y;Ur[e|8]=b;Ur[e|9]=w;Ur[e|10]=E;Ur[e|11]=S;Ur[e|12]=x;Ur[e|13]=T;Ur[e|14]=N;Ur[e|15]=C}function Yr(e,t,n,r,i,s,o,u,a,f,l,c,h,p,d,v){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;s=s|0;o=o|0;u=u|0;a=a|0;f=f|0;l=l|0;c=c|0;h=h|0;p=p|0;d=d|0;v=v|0;k=e;L=t;A=n;O=r;M=i;_=s;D=o;P=u;H=a;B=f;j=l;F=c;I=h;q=p;R=d;U=v;$r()}function Zr(e,t){e=e|0;t=t|0;if(e&15|t&15)return-1;while((t|0)>0){c=c^Ur[e];h=h^Ur[e|1];p=p^Ur[e|2];d=d^Ur[e|3];v=v^Ur[e|4];m=m^Ur[e|5];g=g^Ur[e|6];y=y^Ur[e|7];b=b^Ur[e|8];w=w^Ur[e|9];E=E^Ur[e|10];S=S^Ur[e|11];x=x^Ur[e|12];T=T^Ur[e|13];N=N^Ur[e|14];C=C^Ur[e|15];Jr();Ur[e]=c;Ur[e|1]=h;Ur[e|2]=p;Ur[e|3]=d;Ur[e|4]=v;Ur[e|5]=m;Ur[e|6]=g;Ur[e|7]=y;Ur[e|8]=b;Ur[e|9]=w;Ur[e|10]=E;Ur[e|11]=S;Ur[e|12]=x;Ur[e|13]=T;Ur[e|14]=N;Ur[e|15]=C;e=e+16|0;t=t-16|0}}function ei(e,t){e=e|0;t=t|0;var n=0,r=0,i=0,s=0,o=0,u=0,a=0,f=0,l=0,k=0,L=0,A=0,O=0,M=0,_=0,D=0;if(e&15|t&15)return-1;n=c;r=h;i=p;s=d;o=v;u=m;a=g;f=y;l=b;k=w;L=E;A=S;O=x;M=T;_=N;D=C;while((t|0)>0){c=Ur[e]|0;h=Ur[e|1]|0;p=Ur[e|2]|0;d=Ur[e|3]|0;v=Ur[e|4]|0;m=Ur[e|5]|0;g=Ur[e|6]|0;y=Ur[e|7]|0;b=Ur[e|8]|0;w=Ur[e|9]|0;E=Ur[e|10]|0;S=Ur[e|11]|0;x=Ur[e|12]|0;T=Ur[e|13]|0;N=Ur[e|14]|0;C=Ur[e|15]|0;Kr();c=c^n;n=Ur[e]|0;h=h^r;r=Ur[e|1]|0;p=p^i;i=Ur[e|2]|0;d=d^s;s=Ur[e|3]|0;v=v^o;o=Ur[e|4]|0;m=m^u;u=Ur[e|5]|0;g=g^a;a=Ur[e|6]|0;y=y^f;f=Ur[e|7]|0;b=b^l;l=Ur[e|8]|0;w=w^k;k=Ur[e|9]|0;E=E^L;L=Ur[e|10]|0;S=S^A;A=Ur[e|11]|0;x=x^O;O=Ur[e|12]|0;T=T^M;M=Ur[e|13]|0;N=N^_;_=Ur[e|14]|0;C=C^D;D=Ur[e|15]|0;Ur[e]=c;Ur[e|1]=h;Ur[e|2]=p;Ur[e|3]=d;Ur[e|4]=v;Ur[e|5]=m;Ur[e|6]=g;Ur[e|7]=y;Ur[e|8]=b;Ur[e|9]=w;Ur[e|10]=E;Ur[e|11]=S;Ur[e|12]=x;Ur[e|13]=T;Ur[e|14]=N;Ur[e|15]=C;e=e+16|0;t=t-16|0}c=n;h=r;p=i;d=s;v=o;m=u;g=a;y=f;b=l;w=k;E=L;S=A;x=O;T=M;N=_;C=D}function ti(e,t,n){e=e|0;t=t|0;n=n|0;if(e&15)return-1;if(~n)if(n&31)return-1;while((t|0)>=16){c=c^Ur[e];h=h^Ur[e|1];p=p^Ur[e|2];d=d^Ur[e|3];v=v^Ur[e|4];m=m^Ur[e|5];g=g^Ur[e|6];y=y^Ur[e|7];b=b^Ur[e|8];w=w^Ur[e|9];E=E^Ur[e|10];S=S^Ur[e|11];x=x^Ur[e|12];T=T^Ur[e|13];N=N^Ur[e|14];C=C^Ur[e|15];Jr();e=e+16|0;t=t-16|0}if((t|0)>0){c=c^Ur[e];if((t|0)>1)h=h^Ur[e|1];if((t|0)>2)p=p^Ur[e|2];if((t|0)>3)d=d^Ur[e|3];if((t|0)>4)v=v^Ur[e|4];if((t|0)>5)m=m^Ur[e|5];if((t|0)>6)g=g^Ur[e|6];if((t|0)>7)y=y^Ur[e|7];if((t|0)>8)b=b^Ur[e|8];if((t|0)>9)w=w^Ur[e|9];if((t|0)>10)E=E^Ur[e|10];if((t|0)>11)S=S^Ur[e|11];if((t|0)>12)x=x^Ur[e|12];if((t|0)>13)T=T^Ur[e|13];if((t|0)>14)N=N^Ur[e|14];Jr();e=e+t|0;t=0}if(~n){Ur[n|0]=c;Ur[n|1]=h;Ur[n|2]=p;Ur[n|3]=d;Ur[n|4]=v;Ur[n|5]=m;Ur[n|6]=g;Ur[n|7]=y;Ur[n|8]=b;Ur[n|9]=w;Ur[n|10]=E;Ur[n|11]=S;Ur[n|12]=x;Ur[n|13]=T;Ur[n|14]=N;Ur[n|15]=C}}function ni(e,t,n,r,i,s,o,u,a,f,l,k,L,A,O,M,_){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;s=s|0;o=o|0;u=u|0;a=a|0;f=f|0;l=l|0;k=k|0;L=L|0;A=A|0;O=O|0;M=M|0;_=_|0;var D=0,P=0,H=0,B=0,j=0,F=0,I=0,q=0,R=0,U=0,z=0,W=0,X=0,V=0,$=0,J=0,K=0,Q=0,G=0,Y=0,Z=0,et=0,tt=0,nt=0,rt=0,it=0,st=0,ot=0,ut=0,at=0,ft=0,lt=0;if(e&15)return-1;D=c,P=h,H=p,B=d,j=v,F=m,I=g,q=y,R=b,U=w,z=E,W=S,X=x,V=T,$=N,J=C;while((t|0)>=16){K=Ur[e]|0;Q=Ur[e|1]|0;G=Ur[e|2]|0;Y=Ur[e|3]|0;Z=Ur[e|4]|0;et=Ur[e|5]|0;tt=Ur[e|6]|0;nt=Ur[e|7]|0;rt=Ur[e|8]|0;it=Ur[e|9]|0;st=Ur[e|10]|0;ot=Ur[e|11]|0;ut=Ur[e|12]|0;at=Ur[e|13]|0;ft=Ur[e|14]|0;lt=Ur[e|15]|0;c=n,h=r,p=i,d=s,v=o,m=u,g=a,y=f,b=l,w=k,E=L,S=A;x=O^_>>>24;T=M^_>>>16&255,N=_>>>8&255,C=_&255;Jr();Ur[e]=K^c;Ur[e|1]=Q^h;Ur[e|2]=G^p;Ur[e|3]=Y^d;Ur[e|4]=Z^v;Ur[e|5]=et^m;Ur[e|6]=tt^g;Ur[e|7]=nt^y;Ur[e|8]=rt^b;Ur[e|9]=it^w;Ur[e|10]=st^E;Ur[e|11]=ot^S;Ur[e|12]=ut^x;Ur[e|13]=at^T;Ur[e|14]=ft^N;Ur[e|15]=lt^C;c=K^D;h=Q^P;p=G^H;d=Y^B;v=Z^j;m=et^F;g=tt^I;y=nt^q;b=rt^R;w=it^U;E=st^z;S=ot^W;x=ut^X;T=at^V;N=ft^$;C=lt^J;Jr();D=c,P=h,H=p,B=d,j=v,F=m,I=g,q=y,R=b,U=w,z=E,W=S,X=x,V=T,$=N,J=C;e=e+16|0;t=t-16|0;_=_+1|0}if((t|0)>0){K=Ur[e]|0;Q=(t|0)>1?Ur[e|1]|0:0;G=(t|0)>2?Ur[e|2]|0:0;Y=(t|0)>3?Ur[e|3]|0:0;Z=(t|0)>4?Ur[e|4]|0:0;et=(t|0)>5?Ur[e|5]|0:0;tt=(t|0)>6?Ur[e|6]|0:0;nt=(t|0)>7?Ur[e|7]|0:0;rt=(t|0)>8?Ur[e|8]|0:0;it=(t|0)>9?Ur[e|9]|0:0;st=(t|0)>10?Ur[e|10]|0:0;ot=(t|0)>11?Ur[e|11]|0:0;ut=(t|0)>12?Ur[e|12]|0:0;at=(t|0)>13?Ur[e|13]|0:0;ft=(t|0)>14?Ur[e|14]|0:0;c=n,h=r,p=i,d=s,v=o,m=u,g=a,y=f,b=l,w=k,E=L,S=A;x=O^_>>>24;T=M^_>>>16&255,N=_>>>8&255,C=_&255;Jr();Ur[e]=K^c;if((t|0)>1)Ur[e|1]=Q^h;if((t|0)>2)Ur[e|2]=G^p;if((t|0)>3)Ur[e|3]=Y^d;if((t|0)>4)Ur[e|4]=Z^v;if((t|0)>5)Ur[e|5]=et^m;if((t|0)>6)Ur[e|6]=tt^g;if((t|0)>7)Ur[e|7]=nt^y;if((t|0)>8)Ur[e|8]=rt^b;if((t|0)>9)Ur[e|9]=it^w;if((t|0)>10)Ur[e|10]=st^E;if((t|0)>11)Ur[e|11]=ot^S;if((t|0)>12)Ur[e|12]=ut^x;if((t|0)>13)Ur[e|13]=at^T;if((t|0)>14)Ur[e|14]=ft^N;c=K^D;h=Q^P;p=G^H;d=Y^B;v=Z^j;m=et^F;g=tt^I;y=nt^q;b=rt^R;w=it^U;E=st^z;S=ot^W;x=ut^X;T=at^V;N=ft^$;C=J;Jr();D=c,P=h,H=p,B=d,j=v,F=m,I=g,q=y,R=b,U=w,z=E,W=S,X=x,V=T,$=N,J=C;e=e+t|0;t=0;_=_+1|0}}function ri(e,t,n,r,i,s,o,u,a,f,l,k,L,A,O,M,_){e=e|0;t=t|0;n=n|0;r=r|0;i=i|0;s=s|0;o=o|0;u=u|0;a=a|0;f=f|0;l=l|0;k=k|0;L=L|0;A=A|0;O=O|0;M=M|0;_=_|0;var D=0,P=0,H=0,B=0,j=0,F=0,I=0,q=0,R=0,U=0,z=0,W=0,X=0,V=0,$=0,J=0,K=0,Q=0,G=0,Y=0,Z=0,et=0,tt=0,nt=0,rt=0,it=0,st=0,ot=0,ut=0,at=0,ft=0,lt=0;if(e&15)return-1;D=c,P=h,H=p,B=d,j=v,F=m,I=g,q=y,R=b,U=w,z=E,W=S,X=x,V=T,$=N,J=C;while((t|0)>=16){c=n,h=r,p=i,d=s,v=o,m=u,g=a,y=f,b=l,w=k,E=L,S=A;x=O^_>>>24;T=M^_>>>16&255,N=_>>>8&255,C=_&255;Jr();Ur[e]=K=Ur[e]^c;Ur[e|1]=Q=Ur[e|1]^h;Ur[e|2]=G=Ur[e|2]^p;Ur[e|3]=Y=Ur[e|3]^d;Ur[e|4]=Z=Ur[e|4]^v;Ur[e|5]=et=Ur[e|5]^m;Ur[e|6]=tt=Ur[e|6]^g;Ur[e|7]=nt=Ur[e|7]^y;Ur[e|8]=rt=Ur[e|8]^b;Ur[e|9]=it=Ur[e|9]^w;Ur[e|10]=st=Ur[e|10]^E;Ur[e|11]=ot=Ur[e|11]^S;Ur[e|12]=ut=Ur[e|12]^x;Ur[e|13]=at=Ur[e|13]^T;Ur[e|14]=ft=Ur[e|14]^N;Ur[e|15]=lt=Ur[e|15]^C;c=K^D;h=Q^P;p=G^H;d=Y^B;v=Z^j;m=et^F;g=tt^I;y=nt^q;b=rt^R;w=it^U;E=st^z;S=ot^W;x=ut^X;T=at^V;N=ft^$;C=lt^J;Jr();D=c,P=h,H=p,B=d,j=v,F=m,I=g,q=y,R=b,U=w,z=E,W=S,X=x,V=T,$=N,J=C;e=e+16|0;t=t-16|0;_=_+1|0}if((t|0)>0){c=n,h=r,p=i,d=s,v=o,m=u,g=a,y=f,b=l,w=k,E=L,S=A;x=O^_>>>24;T=M^_>>>16&255,N=_>>>8&255,C=_&255;Jr();K=Ur[e]^c;Q=(t|0)>1?Ur[e|1]^h:0;G=(t|0)>2?Ur[e|2]^p:0;Y=(t|0)>3?Ur[e|3]^d:0;Z=(t|0)>4?Ur[e|4]^v:0;et=(t|0)>5?Ur[e|5]^m:0;tt=(t|0)>6?Ur[e|6]^g:0;nt=(t|0)>7?Ur[e|7]^y:0;rt=(t|0)>8?Ur[e|8]^b:0;it=(t|0)>9?Ur[e|9]^w:0;st=(t|0)>10?Ur[e|10]^E:0;ot=(t|0)>11?Ur[e|11]^S:0;ut=(t|0)>12?Ur[e|12]^x:0;at=(t|0)>13?Ur[e|13]^T:0;ft=(t|0)>14?Ur[e|14]^N:0;lt=(t|0)>15?Ur[e|15]^C:0;Ur[e]=K;if((t|0)>1)Ur[e|1]=Q;if((t|0)>2)Ur[e|2]=G;if((t|0)>3)Ur[e|3]=Y;if((t|0)>4)Ur[e|4]=Z;if((t|0)>5)Ur[e|5]=et;if((t|0)>6)Ur[e|6]=tt;if((t|0)>7)Ur[e|7]=nt;if((t|0)>8)Ur[e|8]=rt;if((t|0)>9)Ur[e|9]=it;if((t|0)>10)Ur[e|10]=st;if((t|0)>11)Ur[e|11]=ot;if((t|0)>12)Ur[e|12]=ut;if((t|0)>13)Ur[e|13]=at;if((t|0)>14)Ur[e|14]=ft;c=K^D;h=Q^P;p=G^H;d=Y^B;v=Z^j;m=et^F;g=tt^I;y=nt^q;b=rt^R;w=it^U;E=st^z;S=ot^W;x=ut^X;T=at^V;N=ft^$;C=lt^J;Jr();D=c,P=h,H=p,B=d,j=v,F=m,I=g,q=y,R=b,U=w,z=E,W=S,X=x,V=T,$=N,J=C;e=e+16|0;t=t-16|0;_=_+1|0}}return{init_state:Qr,save_state:Gr,init_key_128:Yr,cbc_encrypt:Zr,cbc_decrypt:ei,cbc_mac:ti,ccm_encrypt:ni,ccm_decrypt:ri}'))( stdlib, foreign, buffer );
}
