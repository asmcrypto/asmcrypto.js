function aes_asm ( stdlib, foreign, buffer ) {
    "use asm";

    // AES precomputed tables
    var SBOX = 0, INV_SBOX = 0x100, X2_SBOX = 0x200, X3_SBOX = 0x300,
        X2 = 0x400, X9 = 0x500, XB = 0x600, XD = 0x700, XE = 0x800,
        RCON = 0x900;

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
	    S0 = HEAP[SBOX|S0];
	    S4 = HEAP[SBOX|S4];
	    S8 = HEAP[SBOX|S8];
	    SC = HEAP[SBOX|SC];

	    // row 1
	    t = HEAP[SBOX|S1];
	    S1 = HEAP[SBOX|S5];
	    S5 = HEAP[SBOX|S9];
	    S9 = HEAP[SBOX|SD];
	    SD = t;

	    // row 2
	    t = HEAP[SBOX|S2];
	    S2 = HEAP[SBOX|SA];
	    SA = t;
	    t = HEAP[SBOX|S6];
	    S6 = HEAP[SBOX|SE];
	    SE = t;

	    // row 3
	    t = HEAP[SBOX|SF];
	    SF = HEAP[SBOX|SB];
	    SB = HEAP[SBOX|S7];
	    S7 = HEAP[SBOX|S3];
	    S3 = t;
    }

    function _inv_sub_shift () {
        var t = 0;

	    // row 0
	    S0 = HEAP[INV_SBOX|S0];
	    S4 = HEAP[INV_SBOX|S4];
	    S8 = HEAP[INV_SBOX|S8];
	    SC = HEAP[INV_SBOX|SC];

	    // row 1
	    t = HEAP[INV_SBOX|SD];
	    SD = HEAP[INV_SBOX|S9];
	    S9 = HEAP[INV_SBOX|S5];
	    S5 = HEAP[INV_SBOX|S1];
	    S1 = t;

	    // row 2
	    t = HEAP[INV_SBOX|S2]
	    S2 = HEAP[INV_SBOX|SA]
	    SA = t;
	    t = HEAP[INV_SBOX|S6]
	    S6 = HEAP[INV_SBOX|SE]
	    SE = t;

	    // row 3
	    t = HEAP[INV_SBOX|S3];
	    S3 = HEAP[INV_SBOX|S7];
	    S7 = HEAP[INV_SBOX|SB];
	    SB = HEAP[INV_SBOX|SF];
	    SF = t;
    }

    function _sub_shift_mix () {
        var s0 = 0, s1 = 0, s2 = 0, s3 = 0, s4 = 0, s5 = 0, s6 = 0, s7 = 0, s8 = 0, s9 = 0, aA = 0, sB = 0, sC = 0, sD = 0, sE = 0, sF = 0;

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

        S0 = HEAP[INV_SBOX|t0];
        S1 = HEAP[INV_SBOX|t1];
        S2 = HEAP[INV_SBOX|t2];
        S3 = HEAP[INV_SBOX|t3];
        S4 = HEAP[INV_SBOX|t4];
        S5 = HEAP[INV_SBOX|t5];
        S6 = HEAP[INV_SBOX|t6];
        S7 = HEAP[INV_SBOX|t7];
        S8 = HEAP[INV_SBOX|t8];
        S9 = HEAP[INV_SBOX|t9];
        SA = HEAP[INV_SBOX|tA];
        SB = HEAP[INV_SBOX|tB];
        SC = HEAP[INV_SBOX|tC];
        SD = HEAP[INV_SBOX|tD];
        SE = HEAP[INV_SBOX|tE];
        SF = HEAP[INV_SBOX|tF];
    }

    function _expand_key_128 () {
        var t = 0;

        // key 1
        R10 = R00 ^ HEAP[SBOX|R0D] ^ HEAP[RCON|1];
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
        R20 = R10 ^ HEAP[SBOX|R1D] ^ HEAP[RCON|2];
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
        R30 = R20 ^ HEAP[SBOX|R2D] ^ HEAP[RCON|3];
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
        R40 = R30 ^ HEAP[SBOX|R3D] ^ HEAP[RCON|4];
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
        R50 = R40 ^ HEAP[SBOX|R4D] ^ HEAP[RCON|5];
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
        R60 = R50 ^ HEAP[SBOX|R5D] ^ HEAP[RCON|6];
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
        R70 = R60 ^ HEAP[SBOX|R6D] ^ HEAP[RCON|7];
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
        R80 = R70 ^ HEAP[SBOX|R7D] ^ HEAP[RCON|8];
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
        R90 = R80 ^ HEAP[SBOX|R8D] ^ HEAP[RCON|9];
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
        RA0 = R90 ^ HEAP[SBOX|R9D] ^ HEAP[RCON|10];
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

    function _init_state ( w0, w1, w2, w3 ) {
        w0 = w0|0;
        w1 = w1|0;
        w2 = w2|0;
        w3 = w3|0;

	    S0 = w0>>>24;
	    S1 = w0>>>16&255;
	    S2 = w0>>>8&255;
	    S3 = w0&255;
	    S4 = w1>>>24;
	    S5 = w1>>>16&255;
	    S6 = w1>>>8&255;
	    S7 = w1&255;
	    S8 = w2>>>24;
	    S9 = w2>>>16&255;
	    SA = w2>>>8&255;
	    SB = w2&255;
	    SC = w3>>>24;
	    SD = w3>>>16&255;
	    SE = w3>>>8&255;
	    SF = w3&255;
    }

    function _test_state ( w0, w1, w2, w3 ) {
        w0 = w0|0;
        w1 = w1|0;
        w2 = w2|0;
        w3 = w3|0;

        return ( ( (S0<<24)|(S1<<16)|(S2<<8)|S3 ) ^ w0 )
             | ( ( (S4<<24)|(S5<<16)|(S6<<8)|S7 ) ^ w1 )
             | ( ( (S8<<24)|(S9<<16)|(SA<<8)|SB ) ^ w2 )
             | ( ( (SC<<24)|(SD<<16)|(SE<<8)|SF ) ^ w3 )
             ? 0 : 1;
    }

    function _init_key_128 ( w0, w1, w2, w3 ) {
        w0 = w0|0;
        w1 = w1|0;
        w2 = w2|0;
        w3 = w3|0;

	    R00 = w0>>>24;
	    R01 = w0>>>16&255;
	    R02 = w0>>>8&255;
	    R03 = w0&255;
	    R04 = w1>>>24;
	    R05 = w1>>>16&255;
	    R06 = w1>>>8&255;
	    R07 = w1&255;
	    R08 = w2>>>24;
	    R09 = w2>>>16&255;
	    R0A = w2>>>8&255;
	    R0B = w2&255;
	    R0C = w3>>>24;
	    R0D = w3>>>16&255;
	    R0E = w3>>>8&255;
	    R0F = w3&255;
    }

    function _test_key_128 ( i, w0, w1, w2, w3 ) {
        i = i|0;
        w0 = w0|0;
        w1 = w1|0;
        w2 = w2|0;
        w3 = w3|0;

        var r0 = 0, r1 = 0, r2 = 0, r3 = 0;

        switch ( i ) {
            case 1:
                r0 = (R10<<24)|(R11<<16)|(R12<<8)|R13;
                r1 = (R14<<24)|(R15<<16)|(R16<<8)|R17;
                r2 = (R18<<24)|(R19<<16)|(R1A<<8)|R1B;
                r3 = (R1C<<24)|(R1D<<16)|(R1E<<8)|R1F;
                break;
            case 2:
                r0 = (R20<<24)|(R21<<16)|(R22<<8)|R23;
                r1 = (R24<<24)|(R25<<16)|(R26<<8)|R27;
                r2 = (R28<<24)|(R29<<16)|(R2A<<8)|R2B;
                r3 = (R2C<<24)|(R2D<<16)|(R2E<<8)|R2F;
                break;
            default:
                r0 = (R00<<24)|(R01<<16)|(R02<<8)|R03;
                r1 = (R04<<24)|(R05<<16)|(R06<<8)|R07;
                r2 = (R08<<24)|(R09<<16)|(R0A<<8)|R0B;
                r3 = (R0C<<24)|(R0D<<16)|(R0E<<8)|R0F;
        }

        return (r0^w0)|(r1^w1)|(r2^w2)|(r3^w3)
                ? 0 : 1;
    }

    return {
        _sub_shift: _sub_shift,
        _inv_sub_shift: _inv_sub_shift,
        _sub_shift_mix: _sub_shift_mix,
        _inv_sub_shift_mix: _inv_sub_shift_mix,
        _expand_key_128: _expand_key_128,
        _encrypt_128: _encrypt_128,
        _decrypt_128: _decrypt_128,
        _init_state: _init_state,
        _test_state: _test_state,
        _init_key_128: _init_key_128,
        _test_key_128: _test_key_128
    };
}
