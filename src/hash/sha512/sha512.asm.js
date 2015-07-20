function sha512_asm ( stdlib, foreign, buffer ) {
    "use asm";

    // SHA512 state
    var H0h = 0, H0l = 0, H1h = 0, H1l = 0, H2h = 0, H2l = 0, H3h = 0, H3l = 0,
        H4h = 0, H4l = 0, H5h = 0, H5l = 0, H6h = 0, H6l = 0, H7h = 0, H7l = 0,
        TOTAL0 = 0, TOTAL1 = 0;

    // HMAC state
    var I0h = 0, I0l = 0, I1h = 0, I1l = 0, I2h = 0, I2l = 0, I3h = 0, I3l = 0,
        I4h = 0, I4l = 0, I5h = 0, I5l = 0, I6h = 0, I6l = 0, I7h = 0, I7l = 0,
        O0h = 0, O0l = 0, O1h = 0, O1l = 0, O2h = 0, O2l = 0, O3h = 0, O3l = 0,
        O4h = 0, O4l = 0, O5h = 0, O5l = 0, O6h = 0, O6l = 0, O7h = 0, O7l = 0;

    // I/O buffer
    var HEAP = new stdlib.Uint8Array(buffer);

    function _core ( w0h, w0l, w1h, w1l, w2h, w2l, w3h, w3l, w4h, w4l, w5h, w5l, w6h, w6l, w7h, w7l, w8h, w8l, w9h, w9l, w10h, w10l, w11h, w11l, w12h, w12l, w13h, w13l, w14h, w14l, w15h, w15l ) {
        w0h = w0h|0;
        w0l = w0l|0;
        w1h = w1h|0;
        w1l = w1l|0;
        w2h = w2h|0;
        w2l = w2l|0;
        w3h = w3h|0;
        w3l = w3l|0;
        w4h = w4h|0;
        w4l = w4l|0;
        w5h = w5h|0;
        w5l = w5l|0;
        w6h = w6h|0;
        w6l = w6l|0;
        w7h = w7h|0;
        w7l = w7l|0;
        w8h = w8h|0;
        w8l = w8l|0;
        w9h = w9h|0;
        w9l = w9l|0;
        w10h = w10h|0;
        w10l = w10l|0;
        w11h = w11h|0;
        w11l = w11l|0;
        w12h = w12h|0;
        w12l = w12l|0;
        w13h = w13h|0;
        w13l = w13l|0;
        w14h = w14h|0;
        w14l = w14l|0;
        w15h = w15h|0;
        w15l = w15l|0;

        var ah = 0, al = 0, bh = 0, bl = 0, ch = 0, cl = 0, dh = 0, dl = 0, eh = 0, el = 0, fh = 0, fl = 0, gh = 0, gl = 0, hh = 0, hl = 0,
            th = 0, tl = 0, xl = 0;

        ah = H0h;
        al = H0l;
        bh = H1h;
        bl = H1l;
        ch = H2h;
        cl = H2l;
        dh = H3h;
        dl = H3l;
        eh = H4h;
        el = H4l;
        fh = H5h;
        fl = H5l;
        gh = H6h;
        gl = H6l;
        hh = H7h;
        hl = H7l;

        // 0
        tl = ( 0xd728ae22 + w0l )|0;
        th = ( 0x428a2f98 + w0h + ((tl >>> 0) < (w0l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 1
        tl = ( 0x23ef65cd + w1l )|0;
        th = ( 0x71374491 + w1h + ((tl >>> 0) < (w1l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 2
        tl = ( 0xec4d3b2f + w2l )|0;
        th = ( 0xb5c0fbcf + w2h + ((tl >>> 0) < (w2l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 3
        tl = ( 0x8189dbbc + w3l )|0;
        th = ( 0xe9b5dba5 + w3h + ((tl >>> 0) < (w3l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 4
        tl = ( 0xf348b538 + w4l )|0;
        th = ( 0x3956c25b + w4h + ((tl >>> 0) < (w4l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 5
        tl = ( 0xb605d019 + w5l )|0;
        th = ( 0x59f111f1 + w5h + ((tl >>> 0) < (w5l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 6
        tl = ( 0xaf194f9b + w6l )|0;
        th = ( 0x923f82a4 + w6h + ((tl >>> 0) < (w6l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 7
        tl = ( 0xda6d8118 + w7l )|0;
        th = ( 0xab1c5ed5 + w7h + ((tl >>> 0) < (w7l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 8
        tl = ( 0xa3030242 + w8l )|0;
        th = ( 0xd807aa98 + w8h + ((tl >>> 0) < (w8l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 9
        tl = ( 0x45706fbe + w9l )|0;
        th = ( 0x12835b01 + w9h + ((tl >>> 0) < (w9l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 10
        tl = ( 0x4ee4b28c + w10l )|0;
        th = ( 0x243185be + w10h + ((tl >>> 0) < (w10l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 11
        tl = ( 0xd5ffb4e2 + w11l )|0;
        th = ( 0x550c7dc3 + w11h + ((tl >>> 0) < (w11l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 12
        tl = ( 0xf27b896f + w12l )|0;
        th = ( 0x72be5d74 + w12h + ((tl >>> 0) < (w12l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 13
        tl = ( 0x3b1696b1 + w13l )|0;
        th = ( 0x80deb1fe + w13h + ((tl >>> 0) < (w13l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 14
        tl = ( 0x25c71235 + w14l )|0;
        th = ( 0x9bdc06a7 + w14h + ((tl >>> 0) < (w14l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 15
        tl = ( 0xcf692694 + w15l )|0;
        th = ( 0xc19bf174 + w15h + ((tl >>> 0) < (w15l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 16
        w0l = ( w0l + w9l )|0;
        w0h = ( w0h + w9h + ((w0l >>> 0) < (w9l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w1l >>> 1) | (w1h << 31)) ^ ((w1l >>> 8) | (w1h << 24)) ^ ((w1l >>> 7) | (w1h << 25)) )|0;
        w0l = ( w0l + xl)|0;
        w0h = ( w0h + ( ((w1h >>> 1) | (w1l << 31)) ^ ((w1h >>> 8) | (w1l << 24)) ^ (w1h >>> 7) ) + ((w0l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w14l >>> 19) | (w14h << 13)) ^ ((w14l << 3) | (w14h >>> 29)) ^ ((w14l >>> 6) | (w14h << 26)) )|0;
        w0l = ( w0l + xl)|0;
        w0h = ( w0h + ( ((w14h >>> 19) | (w14l << 13)) ^ ((w14h << 3) | (w14l >>> 29)) ^ (w14h >>> 6) ) + ((w0l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x9ef14ad2 + w0l )|0;
        th = ( 0xe49b69c1 + w0h + ((tl >>> 0) < (w0l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 17
        w1l = ( w1l + w10l )|0;
        w1h = ( w1h + w10h + ((w1l >>> 0) < (w10l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w2l >>> 1) | (w2h << 31)) ^ ((w2l >>> 8) | (w2h << 24)) ^ ((w2l >>> 7) | (w2h << 25)) )|0;
        w1l = ( w1l + xl)|0;
        w1h = ( w1h + ( ((w2h >>> 1) | (w2l << 31)) ^ ((w2h >>> 8) | (w2l << 24)) ^ (w2h >>> 7) ) + ((w1l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w15l >>> 19) | (w15h << 13)) ^ ((w15l << 3) | (w15h >>> 29)) ^ ((w15l >>> 6) | (w15h << 26)) )|0;
        w1l = ( w1l + xl)|0;
        w1h = ( w1h + ( ((w15h >>> 19) | (w15l << 13)) ^ ((w15h << 3) | (w15l >>> 29)) ^ (w15h >>> 6) ) + ((w1l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x384f25e3 + w1l )|0;
        th = ( 0xefbe4786 + w1h + ((tl >>> 0) < (w1l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 18
        w2l = ( w2l + w11l )|0;
        w2h = ( w2h + w11h + ((w2l >>> 0) < (w11l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w3l >>> 1) | (w3h << 31)) ^ ((w3l >>> 8) | (w3h << 24)) ^ ((w3l >>> 7) | (w3h << 25)) )|0;
        w2l = ( w2l + xl)|0;
        w2h = ( w2h + ( ((w3h >>> 1) | (w3l << 31)) ^ ((w3h >>> 8) | (w3l << 24)) ^ (w3h >>> 7) ) + ((w2l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w0l >>> 19) | (w0h << 13)) ^ ((w0l << 3) | (w0h >>> 29)) ^ ((w0l >>> 6) | (w0h << 26)) )|0;
        w2l = ( w2l + xl)|0;
        w2h = ( w2h + ( ((w0h >>> 19) | (w0l << 13)) ^ ((w0h << 3) | (w0l >>> 29)) ^ (w0h >>> 6) ) + ((w2l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x8b8cd5b5 + w2l )|0;
        th = ( 0xfc19dc6 + w2h + ((tl >>> 0) < (w2l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 19
        w3l = ( w3l + w12l )|0;
        w3h = ( w3h + w12h + ((w3l >>> 0) < (w12l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w4l >>> 1) | (w4h << 31)) ^ ((w4l >>> 8) | (w4h << 24)) ^ ((w4l >>> 7) | (w4h << 25)) )|0;
        w3l = ( w3l + xl)|0;
        w3h = ( w3h + ( ((w4h >>> 1) | (w4l << 31)) ^ ((w4h >>> 8) | (w4l << 24)) ^ (w4h >>> 7) ) + ((w3l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w1l >>> 19) | (w1h << 13)) ^ ((w1l << 3) | (w1h >>> 29)) ^ ((w1l >>> 6) | (w1h << 26)) )|0;
        w3l = ( w3l + xl)|0;
        w3h = ( w3h + ( ((w1h >>> 19) | (w1l << 13)) ^ ((w1h << 3) | (w1l >>> 29)) ^ (w1h >>> 6) ) + ((w3l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x77ac9c65 + w3l )|0;
        th = ( 0x240ca1cc + w3h + ((tl >>> 0) < (w3l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 20
        w4l = ( w4l + w13l )|0;
        w4h = ( w4h + w13h + ((w4l >>> 0) < (w13l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w5l >>> 1) | (w5h << 31)) ^ ((w5l >>> 8) | (w5h << 24)) ^ ((w5l >>> 7) | (w5h << 25)) )|0;
        w4l = ( w4l + xl)|0;
        w4h = ( w4h + ( ((w5h >>> 1) | (w5l << 31)) ^ ((w5h >>> 8) | (w5l << 24)) ^ (w5h >>> 7) ) + ((w4l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w2l >>> 19) | (w2h << 13)) ^ ((w2l << 3) | (w2h >>> 29)) ^ ((w2l >>> 6) | (w2h << 26)) )|0;
        w4l = ( w4l + xl)|0;
        w4h = ( w4h + ( ((w2h >>> 19) | (w2l << 13)) ^ ((w2h << 3) | (w2l >>> 29)) ^ (w2h >>> 6) ) + ((w4l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x592b0275 + w4l )|0;
        th = ( 0x2de92c6f + w4h + ((tl >>> 0) < (w4l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 21
        w5l = ( w5l + w14l )|0;
        w5h = ( w5h + w14h + ((w5l >>> 0) < (w14l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w6l >>> 1) | (w6h << 31)) ^ ((w6l >>> 8) | (w6h << 24)) ^ ((w6l >>> 7) | (w6h << 25)) )|0;
        w5l = ( w5l + xl)|0;
        w5h = ( w5h + ( ((w6h >>> 1) | (w6l << 31)) ^ ((w6h >>> 8) | (w6l << 24)) ^ (w6h >>> 7) ) + ((w5l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w3l >>> 19) | (w3h << 13)) ^ ((w3l << 3) | (w3h >>> 29)) ^ ((w3l >>> 6) | (w3h << 26)) )|0;
        w5l = ( w5l + xl)|0;
        w5h = ( w5h + ( ((w3h >>> 19) | (w3l << 13)) ^ ((w3h << 3) | (w3l >>> 29)) ^ (w3h >>> 6) ) + ((w5l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x6ea6e483 + w5l )|0;
        th = ( 0x4a7484aa + w5h + ((tl >>> 0) < (w5l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 22
        w6l = ( w6l + w15l )|0;
        w6h = ( w6h + w15h + ((w6l >>> 0) < (w15l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w7l >>> 1) | (w7h << 31)) ^ ((w7l >>> 8) | (w7h << 24)) ^ ((w7l >>> 7) | (w7h << 25)) )|0;
        w6l = ( w6l + xl)|0;
        w6h = ( w6h + ( ((w7h >>> 1) | (w7l << 31)) ^ ((w7h >>> 8) | (w7l << 24)) ^ (w7h >>> 7) ) + ((w6l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w4l >>> 19) | (w4h << 13)) ^ ((w4l << 3) | (w4h >>> 29)) ^ ((w4l >>> 6) | (w4h << 26)) )|0;
        w6l = ( w6l + xl)|0;
        w6h = ( w6h + ( ((w4h >>> 19) | (w4l << 13)) ^ ((w4h << 3) | (w4l >>> 29)) ^ (w4h >>> 6) ) + ((w6l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xbd41fbd4 + w6l )|0;
        th = ( 0x5cb0a9dc + w6h + ((tl >>> 0) < (w6l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 23
        w7l = ( w7l + w0l )|0;
        w7h = ( w7h + w0h + ((w7l >>> 0) < (w0l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w8l >>> 1) | (w8h << 31)) ^ ((w8l >>> 8) | (w8h << 24)) ^ ((w8l >>> 7) | (w8h << 25)) )|0;
        w7l = ( w7l + xl)|0;
        w7h = ( w7h + ( ((w8h >>> 1) | (w8l << 31)) ^ ((w8h >>> 8) | (w8l << 24)) ^ (w8h >>> 7) ) + ((w7l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w5l >>> 19) | (w5h << 13)) ^ ((w5l << 3) | (w5h >>> 29)) ^ ((w5l >>> 6) | (w5h << 26)) )|0;
        w7l = ( w7l + xl)|0;
        w7h = ( w7h + ( ((w5h >>> 19) | (w5l << 13)) ^ ((w5h << 3) | (w5l >>> 29)) ^ (w5h >>> 6) ) + ((w7l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x831153b5 + w7l )|0;
        th = ( 0x76f988da + w7h + ((tl >>> 0) < (w7l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 24
        w8l = ( w8l + w1l )|0;
        w8h = ( w8h + w1h + ((w8l >>> 0) < (w1l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w9l >>> 1) | (w9h << 31)) ^ ((w9l >>> 8) | (w9h << 24)) ^ ((w9l >>> 7) | (w9h << 25)) )|0;
        w8l = ( w8l + xl)|0;
        w8h = ( w8h + ( ((w9h >>> 1) | (w9l << 31)) ^ ((w9h >>> 8) | (w9l << 24)) ^ (w9h >>> 7) ) + ((w8l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w6l >>> 19) | (w6h << 13)) ^ ((w6l << 3) | (w6h >>> 29)) ^ ((w6l >>> 6) | (w6h << 26)) )|0;
        w8l = ( w8l + xl)|0;
        w8h = ( w8h + ( ((w6h >>> 19) | (w6l << 13)) ^ ((w6h << 3) | (w6l >>> 29)) ^ (w6h >>> 6) ) + ((w8l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xee66dfab + w8l )|0;
        th = ( 0x983e5152 + w8h + ((tl >>> 0) < (w8l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 25
        w9l = ( w9l + w2l )|0;
        w9h = ( w9h + w2h + ((w9l >>> 0) < (w2l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w10l >>> 1) | (w10h << 31)) ^ ((w10l >>> 8) | (w10h << 24)) ^ ((w10l >>> 7) | (w10h << 25)) )|0;
        w9l = ( w9l + xl)|0;
        w9h = ( w9h + ( ((w10h >>> 1) | (w10l << 31)) ^ ((w10h >>> 8) | (w10l << 24)) ^ (w10h >>> 7) ) + ((w9l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w7l >>> 19) | (w7h << 13)) ^ ((w7l << 3) | (w7h >>> 29)) ^ ((w7l >>> 6) | (w7h << 26)) )|0;
        w9l = ( w9l + xl)|0;
        w9h = ( w9h + ( ((w7h >>> 19) | (w7l << 13)) ^ ((w7h << 3) | (w7l >>> 29)) ^ (w7h >>> 6) ) + ((w9l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x2db43210 + w9l )|0;
        th = ( 0xa831c66d + w9h + ((tl >>> 0) < (w9l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 26
        w10l = ( w10l + w3l )|0;
        w10h = ( w10h + w3h + ((w10l >>> 0) < (w3l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w11l >>> 1) | (w11h << 31)) ^ ((w11l >>> 8) | (w11h << 24)) ^ ((w11l >>> 7) | (w11h << 25)) )|0;
        w10l = ( w10l + xl)|0;
        w10h = ( w10h + ( ((w11h >>> 1) | (w11l << 31)) ^ ((w11h >>> 8) | (w11l << 24)) ^ (w11h >>> 7) ) + ((w10l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w8l >>> 19) | (w8h << 13)) ^ ((w8l << 3) | (w8h >>> 29)) ^ ((w8l >>> 6) | (w8h << 26)) )|0;
        w10l = ( w10l + xl)|0;
        w10h = ( w10h + ( ((w8h >>> 19) | (w8l << 13)) ^ ((w8h << 3) | (w8l >>> 29)) ^ (w8h >>> 6) ) + ((w10l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x98fb213f + w10l )|0;
        th = ( 0xb00327c8 + w10h + ((tl >>> 0) < (w10l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 27
        w11l = ( w11l + w4l )|0;
        w11h = ( w11h + w4h + ((w11l >>> 0) < (w4l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w12l >>> 1) | (w12h << 31)) ^ ((w12l >>> 8) | (w12h << 24)) ^ ((w12l >>> 7) | (w12h << 25)) )|0;
        w11l = ( w11l + xl)|0;
        w11h = ( w11h + ( ((w12h >>> 1) | (w12l << 31)) ^ ((w12h >>> 8) | (w12l << 24)) ^ (w12h >>> 7) ) + ((w11l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w9l >>> 19) | (w9h << 13)) ^ ((w9l << 3) | (w9h >>> 29)) ^ ((w9l >>> 6) | (w9h << 26)) )|0;
        w11l = ( w11l + xl)|0;
        w11h = ( w11h + ( ((w9h >>> 19) | (w9l << 13)) ^ ((w9h << 3) | (w9l >>> 29)) ^ (w9h >>> 6) ) + ((w11l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xbeef0ee4 + w11l )|0;
        th = ( 0xbf597fc7 + w11h + ((tl >>> 0) < (w11l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 28
        w12l = ( w12l + w5l )|0;
        w12h = ( w12h + w5h + ((w12l >>> 0) < (w5l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w13l >>> 1) | (w13h << 31)) ^ ((w13l >>> 8) | (w13h << 24)) ^ ((w13l >>> 7) | (w13h << 25)) )|0;
        w12l = ( w12l + xl)|0;
        w12h = ( w12h + ( ((w13h >>> 1) | (w13l << 31)) ^ ((w13h >>> 8) | (w13l << 24)) ^ (w13h >>> 7) ) + ((w12l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w10l >>> 19) | (w10h << 13)) ^ ((w10l << 3) | (w10h >>> 29)) ^ ((w10l >>> 6) | (w10h << 26)) )|0;
        w12l = ( w12l + xl)|0;
        w12h = ( w12h + ( ((w10h >>> 19) | (w10l << 13)) ^ ((w10h << 3) | (w10l >>> 29)) ^ (w10h >>> 6) ) + ((w12l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x3da88fc2 + w12l )|0;
        th = ( 0xc6e00bf3 + w12h + ((tl >>> 0) < (w12l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 29
        w13l = ( w13l + w6l )|0;
        w13h = ( w13h + w6h + ((w13l >>> 0) < (w6l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w14l >>> 1) | (w14h << 31)) ^ ((w14l >>> 8) | (w14h << 24)) ^ ((w14l >>> 7) | (w14h << 25)) )|0;
        w13l = ( w13l + xl)|0;
        w13h = ( w13h + ( ((w14h >>> 1) | (w14l << 31)) ^ ((w14h >>> 8) | (w14l << 24)) ^ (w14h >>> 7) ) + ((w13l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w11l >>> 19) | (w11h << 13)) ^ ((w11l << 3) | (w11h >>> 29)) ^ ((w11l >>> 6) | (w11h << 26)) )|0;
        w13l = ( w13l + xl)|0;
        w13h = ( w13h + ( ((w11h >>> 19) | (w11l << 13)) ^ ((w11h << 3) | (w11l >>> 29)) ^ (w11h >>> 6) ) + ((w13l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x930aa725 + w13l )|0;
        th = ( 0xd5a79147 + w13h + ((tl >>> 0) < (w13l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 30
        w14l = ( w14l + w7l )|0;
        w14h = ( w14h + w7h + ((w14l >>> 0) < (w7l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w15l >>> 1) | (w15h << 31)) ^ ((w15l >>> 8) | (w15h << 24)) ^ ((w15l >>> 7) | (w15h << 25)) )|0;
        w14l = ( w14l + xl)|0;
        w14h = ( w14h + ( ((w15h >>> 1) | (w15l << 31)) ^ ((w15h >>> 8) | (w15l << 24)) ^ (w15h >>> 7) ) + ((w14l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w12l >>> 19) | (w12h << 13)) ^ ((w12l << 3) | (w12h >>> 29)) ^ ((w12l >>> 6) | (w12h << 26)) )|0;
        w14l = ( w14l + xl)|0;
        w14h = ( w14h + ( ((w12h >>> 19) | (w12l << 13)) ^ ((w12h << 3) | (w12l >>> 29)) ^ (w12h >>> 6) ) + ((w14l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xe003826f + w14l )|0;
        th = ( 0x6ca6351 + w14h + ((tl >>> 0) < (w14l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 31
        w15l = ( w15l + w8l )|0;
        w15h = ( w15h + w8h + ((w15l >>> 0) < (w8l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w0l >>> 1) | (w0h << 31)) ^ ((w0l >>> 8) | (w0h << 24)) ^ ((w0l >>> 7) | (w0h << 25)) )|0;
        w15l = ( w15l + xl)|0;
        w15h = ( w15h + ( ((w0h >>> 1) | (w0l << 31)) ^ ((w0h >>> 8) | (w0l << 24)) ^ (w0h >>> 7) ) + ((w15l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w13l >>> 19) | (w13h << 13)) ^ ((w13l << 3) | (w13h >>> 29)) ^ ((w13l >>> 6) | (w13h << 26)) )|0;
        w15l = ( w15l + xl)|0;
        w15h = ( w15h + ( ((w13h >>> 19) | (w13l << 13)) ^ ((w13h << 3) | (w13l >>> 29)) ^ (w13h >>> 6) ) + ((w15l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xa0e6e70 + w15l )|0;
        th = ( 0x14292967 + w15h + ((tl >>> 0) < (w15l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 32
        w0l = ( w0l + w9l )|0;
        w0h = ( w0h + w9h + ((w0l >>> 0) < (w9l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w1l >>> 1) | (w1h << 31)) ^ ((w1l >>> 8) | (w1h << 24)) ^ ((w1l >>> 7) | (w1h << 25)) )|0;
        w0l = ( w0l + xl)|0;
        w0h = ( w0h + ( ((w1h >>> 1) | (w1l << 31)) ^ ((w1h >>> 8) | (w1l << 24)) ^ (w1h >>> 7) ) + ((w0l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w14l >>> 19) | (w14h << 13)) ^ ((w14l << 3) | (w14h >>> 29)) ^ ((w14l >>> 6) | (w14h << 26)) )|0;
        w0l = ( w0l + xl)|0;
        w0h = ( w0h + ( ((w14h >>> 19) | (w14l << 13)) ^ ((w14h << 3) | (w14l >>> 29)) ^ (w14h >>> 6) ) + ((w0l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x46d22ffc + w0l )|0;
        th = ( 0x27b70a85 + w0h + ((tl >>> 0) < (w0l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 33
        w1l = ( w1l + w10l )|0;
        w1h = ( w1h + w10h + ((w1l >>> 0) < (w10l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w2l >>> 1) | (w2h << 31)) ^ ((w2l >>> 8) | (w2h << 24)) ^ ((w2l >>> 7) | (w2h << 25)) )|0;
        w1l = ( w1l + xl)|0;
        w1h = ( w1h + ( ((w2h >>> 1) | (w2l << 31)) ^ ((w2h >>> 8) | (w2l << 24)) ^ (w2h >>> 7) ) + ((w1l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w15l >>> 19) | (w15h << 13)) ^ ((w15l << 3) | (w15h >>> 29)) ^ ((w15l >>> 6) | (w15h << 26)) )|0;
        w1l = ( w1l + xl)|0;
        w1h = ( w1h + ( ((w15h >>> 19) | (w15l << 13)) ^ ((w15h << 3) | (w15l >>> 29)) ^ (w15h >>> 6) ) + ((w1l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x5c26c926 + w1l )|0;
        th = ( 0x2e1b2138 + w1h + ((tl >>> 0) < (w1l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 34
        w2l = ( w2l + w11l )|0;
        w2h = ( w2h + w11h + ((w2l >>> 0) < (w11l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w3l >>> 1) | (w3h << 31)) ^ ((w3l >>> 8) | (w3h << 24)) ^ ((w3l >>> 7) | (w3h << 25)) )|0;
        w2l = ( w2l + xl)|0;
        w2h = ( w2h + ( ((w3h >>> 1) | (w3l << 31)) ^ ((w3h >>> 8) | (w3l << 24)) ^ (w3h >>> 7) ) + ((w2l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w0l >>> 19) | (w0h << 13)) ^ ((w0l << 3) | (w0h >>> 29)) ^ ((w0l >>> 6) | (w0h << 26)) )|0;
        w2l = ( w2l + xl)|0;
        w2h = ( w2h + ( ((w0h >>> 19) | (w0l << 13)) ^ ((w0h << 3) | (w0l >>> 29)) ^ (w0h >>> 6) ) + ((w2l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x5ac42aed + w2l )|0;
        th = ( 0x4d2c6dfc + w2h + ((tl >>> 0) < (w2l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 35
        w3l = ( w3l + w12l )|0;
        w3h = ( w3h + w12h + ((w3l >>> 0) < (w12l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w4l >>> 1) | (w4h << 31)) ^ ((w4l >>> 8) | (w4h << 24)) ^ ((w4l >>> 7) | (w4h << 25)) )|0;
        w3l = ( w3l + xl)|0;
        w3h = ( w3h + ( ((w4h >>> 1) | (w4l << 31)) ^ ((w4h >>> 8) | (w4l << 24)) ^ (w4h >>> 7) ) + ((w3l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w1l >>> 19) | (w1h << 13)) ^ ((w1l << 3) | (w1h >>> 29)) ^ ((w1l >>> 6) | (w1h << 26)) )|0;
        w3l = ( w3l + xl)|0;
        w3h = ( w3h + ( ((w1h >>> 19) | (w1l << 13)) ^ ((w1h << 3) | (w1l >>> 29)) ^ (w1h >>> 6) ) + ((w3l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x9d95b3df + w3l )|0;
        th = ( 0x53380d13 + w3h + ((tl >>> 0) < (w3l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 36
        w4l = ( w4l + w13l )|0;
        w4h = ( w4h + w13h + ((w4l >>> 0) < (w13l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w5l >>> 1) | (w5h << 31)) ^ ((w5l >>> 8) | (w5h << 24)) ^ ((w5l >>> 7) | (w5h << 25)) )|0;
        w4l = ( w4l + xl)|0;
        w4h = ( w4h + ( ((w5h >>> 1) | (w5l << 31)) ^ ((w5h >>> 8) | (w5l << 24)) ^ (w5h >>> 7) ) + ((w4l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w2l >>> 19) | (w2h << 13)) ^ ((w2l << 3) | (w2h >>> 29)) ^ ((w2l >>> 6) | (w2h << 26)) )|0;
        w4l = ( w4l + xl)|0;
        w4h = ( w4h + ( ((w2h >>> 19) | (w2l << 13)) ^ ((w2h << 3) | (w2l >>> 29)) ^ (w2h >>> 6) ) + ((w4l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x8baf63de + w4l )|0;
        th = ( 0x650a7354 + w4h + ((tl >>> 0) < (w4l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 37
        w5l = ( w5l + w14l )|0;
        w5h = ( w5h + w14h + ((w5l >>> 0) < (w14l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w6l >>> 1) | (w6h << 31)) ^ ((w6l >>> 8) | (w6h << 24)) ^ ((w6l >>> 7) | (w6h << 25)) )|0;
        w5l = ( w5l + xl)|0;
        w5h = ( w5h + ( ((w6h >>> 1) | (w6l << 31)) ^ ((w6h >>> 8) | (w6l << 24)) ^ (w6h >>> 7) ) + ((w5l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w3l >>> 19) | (w3h << 13)) ^ ((w3l << 3) | (w3h >>> 29)) ^ ((w3l >>> 6) | (w3h << 26)) )|0;
        w5l = ( w5l + xl)|0;
        w5h = ( w5h + ( ((w3h >>> 19) | (w3l << 13)) ^ ((w3h << 3) | (w3l >>> 29)) ^ (w3h >>> 6) ) + ((w5l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x3c77b2a8 + w5l )|0;
        th = ( 0x766a0abb + w5h + ((tl >>> 0) < (w5l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 38
        w6l = ( w6l + w15l )|0;
        w6h = ( w6h + w15h + ((w6l >>> 0) < (w15l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w7l >>> 1) | (w7h << 31)) ^ ((w7l >>> 8) | (w7h << 24)) ^ ((w7l >>> 7) | (w7h << 25)) )|0;
        w6l = ( w6l + xl)|0;
        w6h = ( w6h + ( ((w7h >>> 1) | (w7l << 31)) ^ ((w7h >>> 8) | (w7l << 24)) ^ (w7h >>> 7) ) + ((w6l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w4l >>> 19) | (w4h << 13)) ^ ((w4l << 3) | (w4h >>> 29)) ^ ((w4l >>> 6) | (w4h << 26)) )|0;
        w6l = ( w6l + xl)|0;
        w6h = ( w6h + ( ((w4h >>> 19) | (w4l << 13)) ^ ((w4h << 3) | (w4l >>> 29)) ^ (w4h >>> 6) ) + ((w6l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x47edaee6 + w6l )|0;
        th = ( 0x81c2c92e + w6h + ((tl >>> 0) < (w6l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 39
        w7l = ( w7l + w0l )|0;
        w7h = ( w7h + w0h + ((w7l >>> 0) < (w0l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w8l >>> 1) | (w8h << 31)) ^ ((w8l >>> 8) | (w8h << 24)) ^ ((w8l >>> 7) | (w8h << 25)) )|0;
        w7l = ( w7l + xl)|0;
        w7h = ( w7h + ( ((w8h >>> 1) | (w8l << 31)) ^ ((w8h >>> 8) | (w8l << 24)) ^ (w8h >>> 7) ) + ((w7l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w5l >>> 19) | (w5h << 13)) ^ ((w5l << 3) | (w5h >>> 29)) ^ ((w5l >>> 6) | (w5h << 26)) )|0;
        w7l = ( w7l + xl)|0;
        w7h = ( w7h + ( ((w5h >>> 19) | (w5l << 13)) ^ ((w5h << 3) | (w5l >>> 29)) ^ (w5h >>> 6) ) + ((w7l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x1482353b + w7l )|0;
        th = ( 0x92722c85 + w7h + ((tl >>> 0) < (w7l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 40
        w8l = ( w8l + w1l )|0;
        w8h = ( w8h + w1h + ((w8l >>> 0) < (w1l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w9l >>> 1) | (w9h << 31)) ^ ((w9l >>> 8) | (w9h << 24)) ^ ((w9l >>> 7) | (w9h << 25)) )|0;
        w8l = ( w8l + xl)|0;
        w8h = ( w8h + ( ((w9h >>> 1) | (w9l << 31)) ^ ((w9h >>> 8) | (w9l << 24)) ^ (w9h >>> 7) ) + ((w8l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w6l >>> 19) | (w6h << 13)) ^ ((w6l << 3) | (w6h >>> 29)) ^ ((w6l >>> 6) | (w6h << 26)) )|0;
        w8l = ( w8l + xl)|0;
        w8h = ( w8h + ( ((w6h >>> 19) | (w6l << 13)) ^ ((w6h << 3) | (w6l >>> 29)) ^ (w6h >>> 6) ) + ((w8l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x4cf10364 + w8l )|0;
        th = ( 0xa2bfe8a1 + w8h + ((tl >>> 0) < (w8l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 41
        w9l = ( w9l + w2l )|0;
        w9h = ( w9h + w2h + ((w9l >>> 0) < (w2l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w10l >>> 1) | (w10h << 31)) ^ ((w10l >>> 8) | (w10h << 24)) ^ ((w10l >>> 7) | (w10h << 25)) )|0;
        w9l = ( w9l + xl)|0;
        w9h = ( w9h + ( ((w10h >>> 1) | (w10l << 31)) ^ ((w10h >>> 8) | (w10l << 24)) ^ (w10h >>> 7) ) + ((w9l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w7l >>> 19) | (w7h << 13)) ^ ((w7l << 3) | (w7h >>> 29)) ^ ((w7l >>> 6) | (w7h << 26)) )|0;
        w9l = ( w9l + xl)|0;
        w9h = ( w9h + ( ((w7h >>> 19) | (w7l << 13)) ^ ((w7h << 3) | (w7l >>> 29)) ^ (w7h >>> 6) ) + ((w9l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xbc423001 + w9l )|0;
        th = ( 0xa81a664b + w9h + ((tl >>> 0) < (w9l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 42
        w10l = ( w10l + w3l )|0;
        w10h = ( w10h + w3h + ((w10l >>> 0) < (w3l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w11l >>> 1) | (w11h << 31)) ^ ((w11l >>> 8) | (w11h << 24)) ^ ((w11l >>> 7) | (w11h << 25)) )|0;
        w10l = ( w10l + xl)|0;
        w10h = ( w10h + ( ((w11h >>> 1) | (w11l << 31)) ^ ((w11h >>> 8) | (w11l << 24)) ^ (w11h >>> 7) ) + ((w10l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w8l >>> 19) | (w8h << 13)) ^ ((w8l << 3) | (w8h >>> 29)) ^ ((w8l >>> 6) | (w8h << 26)) )|0;
        w10l = ( w10l + xl)|0;
        w10h = ( w10h + ( ((w8h >>> 19) | (w8l << 13)) ^ ((w8h << 3) | (w8l >>> 29)) ^ (w8h >>> 6) ) + ((w10l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xd0f89791 + w10l )|0;
        th = ( 0xc24b8b70 + w10h + ((tl >>> 0) < (w10l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 43
        w11l = ( w11l + w4l )|0;
        w11h = ( w11h + w4h + ((w11l >>> 0) < (w4l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w12l >>> 1) | (w12h << 31)) ^ ((w12l >>> 8) | (w12h << 24)) ^ ((w12l >>> 7) | (w12h << 25)) )|0;
        w11l = ( w11l + xl)|0;
        w11h = ( w11h + ( ((w12h >>> 1) | (w12l << 31)) ^ ((w12h >>> 8) | (w12l << 24)) ^ (w12h >>> 7) ) + ((w11l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w9l >>> 19) | (w9h << 13)) ^ ((w9l << 3) | (w9h >>> 29)) ^ ((w9l >>> 6) | (w9h << 26)) )|0;
        w11l = ( w11l + xl)|0;
        w11h = ( w11h + ( ((w9h >>> 19) | (w9l << 13)) ^ ((w9h << 3) | (w9l >>> 29)) ^ (w9h >>> 6) ) + ((w11l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x654be30 + w11l )|0;
        th = ( 0xc76c51a3 + w11h + ((tl >>> 0) < (w11l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 44
        w12l = ( w12l + w5l )|0;
        w12h = ( w12h + w5h + ((w12l >>> 0) < (w5l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w13l >>> 1) | (w13h << 31)) ^ ((w13l >>> 8) | (w13h << 24)) ^ ((w13l >>> 7) | (w13h << 25)) )|0;
        w12l = ( w12l + xl)|0;
        w12h = ( w12h + ( ((w13h >>> 1) | (w13l << 31)) ^ ((w13h >>> 8) | (w13l << 24)) ^ (w13h >>> 7) ) + ((w12l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w10l >>> 19) | (w10h << 13)) ^ ((w10l << 3) | (w10h >>> 29)) ^ ((w10l >>> 6) | (w10h << 26)) )|0;
        w12l = ( w12l + xl)|0;
        w12h = ( w12h + ( ((w10h >>> 19) | (w10l << 13)) ^ ((w10h << 3) | (w10l >>> 29)) ^ (w10h >>> 6) ) + ((w12l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xd6ef5218 + w12l )|0;
        th = ( 0xd192e819 + w12h + ((tl >>> 0) < (w12l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 45
        w13l = ( w13l + w6l )|0;
        w13h = ( w13h + w6h + ((w13l >>> 0) < (w6l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w14l >>> 1) | (w14h << 31)) ^ ((w14l >>> 8) | (w14h << 24)) ^ ((w14l >>> 7) | (w14h << 25)) )|0;
        w13l = ( w13l + xl)|0;
        w13h = ( w13h + ( ((w14h >>> 1) | (w14l << 31)) ^ ((w14h >>> 8) | (w14l << 24)) ^ (w14h >>> 7) ) + ((w13l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w11l >>> 19) | (w11h << 13)) ^ ((w11l << 3) | (w11h >>> 29)) ^ ((w11l >>> 6) | (w11h << 26)) )|0;
        w13l = ( w13l + xl)|0;
        w13h = ( w13h + ( ((w11h >>> 19) | (w11l << 13)) ^ ((w11h << 3) | (w11l >>> 29)) ^ (w11h >>> 6) ) + ((w13l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x5565a910 + w13l )|0;
        th = ( 0xd6990624 + w13h + ((tl >>> 0) < (w13l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 46
        w14l = ( w14l + w7l )|0;
        w14h = ( w14h + w7h + ((w14l >>> 0) < (w7l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w15l >>> 1) | (w15h << 31)) ^ ((w15l >>> 8) | (w15h << 24)) ^ ((w15l >>> 7) | (w15h << 25)) )|0;
        w14l = ( w14l + xl)|0;
        w14h = ( w14h + ( ((w15h >>> 1) | (w15l << 31)) ^ ((w15h >>> 8) | (w15l << 24)) ^ (w15h >>> 7) ) + ((w14l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w12l >>> 19) | (w12h << 13)) ^ ((w12l << 3) | (w12h >>> 29)) ^ ((w12l >>> 6) | (w12h << 26)) )|0;
        w14l = ( w14l + xl)|0;
        w14h = ( w14h + ( ((w12h >>> 19) | (w12l << 13)) ^ ((w12h << 3) | (w12l >>> 29)) ^ (w12h >>> 6) ) + ((w14l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x5771202a + w14l )|0;
        th = ( 0xf40e3585 + w14h + ((tl >>> 0) < (w14l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 47
        w15l = ( w15l + w8l )|0;
        w15h = ( w15h + w8h + ((w15l >>> 0) < (w8l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w0l >>> 1) | (w0h << 31)) ^ ((w0l >>> 8) | (w0h << 24)) ^ ((w0l >>> 7) | (w0h << 25)) )|0;
        w15l = ( w15l + xl)|0;
        w15h = ( w15h + ( ((w0h >>> 1) | (w0l << 31)) ^ ((w0h >>> 8) | (w0l << 24)) ^ (w0h >>> 7) ) + ((w15l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w13l >>> 19) | (w13h << 13)) ^ ((w13l << 3) | (w13h >>> 29)) ^ ((w13l >>> 6) | (w13h << 26)) )|0;
        w15l = ( w15l + xl)|0;
        w15h = ( w15h + ( ((w13h >>> 19) | (w13l << 13)) ^ ((w13h << 3) | (w13l >>> 29)) ^ (w13h >>> 6) ) + ((w15l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x32bbd1b8 + w15l )|0;
        th = ( 0x106aa070 + w15h + ((tl >>> 0) < (w15l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 48
        w0l = ( w0l + w9l )|0;
        w0h = ( w0h + w9h + ((w0l >>> 0) < (w9l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w1l >>> 1) | (w1h << 31)) ^ ((w1l >>> 8) | (w1h << 24)) ^ ((w1l >>> 7) | (w1h << 25)) )|0;
        w0l = ( w0l + xl)|0;
        w0h = ( w0h + ( ((w1h >>> 1) | (w1l << 31)) ^ ((w1h >>> 8) | (w1l << 24)) ^ (w1h >>> 7) ) + ((w0l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w14l >>> 19) | (w14h << 13)) ^ ((w14l << 3) | (w14h >>> 29)) ^ ((w14l >>> 6) | (w14h << 26)) )|0;
        w0l = ( w0l + xl)|0;
        w0h = ( w0h + ( ((w14h >>> 19) | (w14l << 13)) ^ ((w14h << 3) | (w14l >>> 29)) ^ (w14h >>> 6) ) + ((w0l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xb8d2d0c8 + w0l )|0;
        th = ( 0x19a4c116 + w0h + ((tl >>> 0) < (w0l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 49
        w1l = ( w1l + w10l )|0;
        w1h = ( w1h + w10h + ((w1l >>> 0) < (w10l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w2l >>> 1) | (w2h << 31)) ^ ((w2l >>> 8) | (w2h << 24)) ^ ((w2l >>> 7) | (w2h << 25)) )|0;
        w1l = ( w1l + xl)|0;
        w1h = ( w1h + ( ((w2h >>> 1) | (w2l << 31)) ^ ((w2h >>> 8) | (w2l << 24)) ^ (w2h >>> 7) ) + ((w1l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w15l >>> 19) | (w15h << 13)) ^ ((w15l << 3) | (w15h >>> 29)) ^ ((w15l >>> 6) | (w15h << 26)) )|0;
        w1l = ( w1l + xl)|0;
        w1h = ( w1h + ( ((w15h >>> 19) | (w15l << 13)) ^ ((w15h << 3) | (w15l >>> 29)) ^ (w15h >>> 6) ) + ((w1l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x5141ab53 + w1l )|0;
        th = ( 0x1e376c08 + w1h + ((tl >>> 0) < (w1l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 50
        w2l = ( w2l + w11l )|0;
        w2h = ( w2h + w11h + ((w2l >>> 0) < (w11l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w3l >>> 1) | (w3h << 31)) ^ ((w3l >>> 8) | (w3h << 24)) ^ ((w3l >>> 7) | (w3h << 25)) )|0;
        w2l = ( w2l + xl)|0;
        w2h = ( w2h + ( ((w3h >>> 1) | (w3l << 31)) ^ ((w3h >>> 8) | (w3l << 24)) ^ (w3h >>> 7) ) + ((w2l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w0l >>> 19) | (w0h << 13)) ^ ((w0l << 3) | (w0h >>> 29)) ^ ((w0l >>> 6) | (w0h << 26)) )|0;
        w2l = ( w2l + xl)|0;
        w2h = ( w2h + ( ((w0h >>> 19) | (w0l << 13)) ^ ((w0h << 3) | (w0l >>> 29)) ^ (w0h >>> 6) ) + ((w2l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xdf8eeb99 + w2l )|0;
        th = ( 0x2748774c + w2h + ((tl >>> 0) < (w2l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 51
        w3l = ( w3l + w12l )|0;
        w3h = ( w3h + w12h + ((w3l >>> 0) < (w12l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w4l >>> 1) | (w4h << 31)) ^ ((w4l >>> 8) | (w4h << 24)) ^ ((w4l >>> 7) | (w4h << 25)) )|0;
        w3l = ( w3l + xl)|0;
        w3h = ( w3h + ( ((w4h >>> 1) | (w4l << 31)) ^ ((w4h >>> 8) | (w4l << 24)) ^ (w4h >>> 7) ) + ((w3l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w1l >>> 19) | (w1h << 13)) ^ ((w1l << 3) | (w1h >>> 29)) ^ ((w1l >>> 6) | (w1h << 26)) )|0;
        w3l = ( w3l + xl)|0;
        w3h = ( w3h + ( ((w1h >>> 19) | (w1l << 13)) ^ ((w1h << 3) | (w1l >>> 29)) ^ (w1h >>> 6) ) + ((w3l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xe19b48a8 + w3l )|0;
        th = ( 0x34b0bcb5 + w3h + ((tl >>> 0) < (w3l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 52
        w4l = ( w4l + w13l )|0;
        w4h = ( w4h + w13h + ((w4l >>> 0) < (w13l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w5l >>> 1) | (w5h << 31)) ^ ((w5l >>> 8) | (w5h << 24)) ^ ((w5l >>> 7) | (w5h << 25)) )|0;
        w4l = ( w4l + xl)|0;
        w4h = ( w4h + ( ((w5h >>> 1) | (w5l << 31)) ^ ((w5h >>> 8) | (w5l << 24)) ^ (w5h >>> 7) ) + ((w4l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w2l >>> 19) | (w2h << 13)) ^ ((w2l << 3) | (w2h >>> 29)) ^ ((w2l >>> 6) | (w2h << 26)) )|0;
        w4l = ( w4l + xl)|0;
        w4h = ( w4h + ( ((w2h >>> 19) | (w2l << 13)) ^ ((w2h << 3) | (w2l >>> 29)) ^ (w2h >>> 6) ) + ((w4l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xc5c95a63 + w4l )|0;
        th = ( 0x391c0cb3 + w4h + ((tl >>> 0) < (w4l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 53
        w5l = ( w5l + w14l )|0;
        w5h = ( w5h + w14h + ((w5l >>> 0) < (w14l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w6l >>> 1) | (w6h << 31)) ^ ((w6l >>> 8) | (w6h << 24)) ^ ((w6l >>> 7) | (w6h << 25)) )|0;
        w5l = ( w5l + xl)|0;
        w5h = ( w5h + ( ((w6h >>> 1) | (w6l << 31)) ^ ((w6h >>> 8) | (w6l << 24)) ^ (w6h >>> 7) ) + ((w5l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w3l >>> 19) | (w3h << 13)) ^ ((w3l << 3) | (w3h >>> 29)) ^ ((w3l >>> 6) | (w3h << 26)) )|0;
        w5l = ( w5l + xl)|0;
        w5h = ( w5h + ( ((w3h >>> 19) | (w3l << 13)) ^ ((w3h << 3) | (w3l >>> 29)) ^ (w3h >>> 6) ) + ((w5l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xe3418acb + w5l )|0;
        th = ( 0x4ed8aa4a + w5h + ((tl >>> 0) < (w5l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 54
        w6l = ( w6l + w15l )|0;
        w6h = ( w6h + w15h + ((w6l >>> 0) < (w15l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w7l >>> 1) | (w7h << 31)) ^ ((w7l >>> 8) | (w7h << 24)) ^ ((w7l >>> 7) | (w7h << 25)) )|0;
        w6l = ( w6l + xl)|0;
        w6h = ( w6h + ( ((w7h >>> 1) | (w7l << 31)) ^ ((w7h >>> 8) | (w7l << 24)) ^ (w7h >>> 7) ) + ((w6l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w4l >>> 19) | (w4h << 13)) ^ ((w4l << 3) | (w4h >>> 29)) ^ ((w4l >>> 6) | (w4h << 26)) )|0;
        w6l = ( w6l + xl)|0;
        w6h = ( w6h + ( ((w4h >>> 19) | (w4l << 13)) ^ ((w4h << 3) | (w4l >>> 29)) ^ (w4h >>> 6) ) + ((w6l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x7763e373 + w6l )|0;
        th = ( 0x5b9cca4f + w6h + ((tl >>> 0) < (w6l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 55
        w7l = ( w7l + w0l )|0;
        w7h = ( w7h + w0h + ((w7l >>> 0) < (w0l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w8l >>> 1) | (w8h << 31)) ^ ((w8l >>> 8) | (w8h << 24)) ^ ((w8l >>> 7) | (w8h << 25)) )|0;
        w7l = ( w7l + xl)|0;
        w7h = ( w7h + ( ((w8h >>> 1) | (w8l << 31)) ^ ((w8h >>> 8) | (w8l << 24)) ^ (w8h >>> 7) ) + ((w7l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w5l >>> 19) | (w5h << 13)) ^ ((w5l << 3) | (w5h >>> 29)) ^ ((w5l >>> 6) | (w5h << 26)) )|0;
        w7l = ( w7l + xl)|0;
        w7h = ( w7h + ( ((w5h >>> 19) | (w5l << 13)) ^ ((w5h << 3) | (w5l >>> 29)) ^ (w5h >>> 6) ) + ((w7l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xd6b2b8a3 + w7l )|0;
        th = ( 0x682e6ff3 + w7h + ((tl >>> 0) < (w7l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 56
        w8l = ( w8l + w1l )|0;
        w8h = ( w8h + w1h + ((w8l >>> 0) < (w1l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w9l >>> 1) | (w9h << 31)) ^ ((w9l >>> 8) | (w9h << 24)) ^ ((w9l >>> 7) | (w9h << 25)) )|0;
        w8l = ( w8l + xl)|0;
        w8h = ( w8h + ( ((w9h >>> 1) | (w9l << 31)) ^ ((w9h >>> 8) | (w9l << 24)) ^ (w9h >>> 7) ) + ((w8l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w6l >>> 19) | (w6h << 13)) ^ ((w6l << 3) | (w6h >>> 29)) ^ ((w6l >>> 6) | (w6h << 26)) )|0;
        w8l = ( w8l + xl)|0;
        w8h = ( w8h + ( ((w6h >>> 19) | (w6l << 13)) ^ ((w6h << 3) | (w6l >>> 29)) ^ (w6h >>> 6) ) + ((w8l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x5defb2fc + w8l )|0;
        th = ( 0x748f82ee + w8h + ((tl >>> 0) < (w8l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 57
        w9l = ( w9l + w2l )|0;
        w9h = ( w9h + w2h + ((w9l >>> 0) < (w2l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w10l >>> 1) | (w10h << 31)) ^ ((w10l >>> 8) | (w10h << 24)) ^ ((w10l >>> 7) | (w10h << 25)) )|0;
        w9l = ( w9l + xl)|0;
        w9h = ( w9h + ( ((w10h >>> 1) | (w10l << 31)) ^ ((w10h >>> 8) | (w10l << 24)) ^ (w10h >>> 7) ) + ((w9l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w7l >>> 19) | (w7h << 13)) ^ ((w7l << 3) | (w7h >>> 29)) ^ ((w7l >>> 6) | (w7h << 26)) )|0;
        w9l = ( w9l + xl)|0;
        w9h = ( w9h + ( ((w7h >>> 19) | (w7l << 13)) ^ ((w7h << 3) | (w7l >>> 29)) ^ (w7h >>> 6) ) + ((w9l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x43172f60 + w9l )|0;
        th = ( 0x78a5636f + w9h + ((tl >>> 0) < (w9l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 58
        w10l = ( w10l + w3l )|0;
        w10h = ( w10h + w3h + ((w10l >>> 0) < (w3l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w11l >>> 1) | (w11h << 31)) ^ ((w11l >>> 8) | (w11h << 24)) ^ ((w11l >>> 7) | (w11h << 25)) )|0;
        w10l = ( w10l + xl)|0;
        w10h = ( w10h + ( ((w11h >>> 1) | (w11l << 31)) ^ ((w11h >>> 8) | (w11l << 24)) ^ (w11h >>> 7) ) + ((w10l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w8l >>> 19) | (w8h << 13)) ^ ((w8l << 3) | (w8h >>> 29)) ^ ((w8l >>> 6) | (w8h << 26)) )|0;
        w10l = ( w10l + xl)|0;
        w10h = ( w10h + ( ((w8h >>> 19) | (w8l << 13)) ^ ((w8h << 3) | (w8l >>> 29)) ^ (w8h >>> 6) ) + ((w10l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xa1f0ab72 + w10l )|0;
        th = ( 0x84c87814 + w10h + ((tl >>> 0) < (w10l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 59
        w11l = ( w11l + w4l )|0;
        w11h = ( w11h + w4h + ((w11l >>> 0) < (w4l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w12l >>> 1) | (w12h << 31)) ^ ((w12l >>> 8) | (w12h << 24)) ^ ((w12l >>> 7) | (w12h << 25)) )|0;
        w11l = ( w11l + xl)|0;
        w11h = ( w11h + ( ((w12h >>> 1) | (w12l << 31)) ^ ((w12h >>> 8) | (w12l << 24)) ^ (w12h >>> 7) ) + ((w11l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w9l >>> 19) | (w9h << 13)) ^ ((w9l << 3) | (w9h >>> 29)) ^ ((w9l >>> 6) | (w9h << 26)) )|0;
        w11l = ( w11l + xl)|0;
        w11h = ( w11h + ( ((w9h >>> 19) | (w9l << 13)) ^ ((w9h << 3) | (w9l >>> 29)) ^ (w9h >>> 6) ) + ((w11l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x1a6439ec + w11l )|0;
        th = ( 0x8cc70208 + w11h + ((tl >>> 0) < (w11l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 60
        w12l = ( w12l + w5l )|0;
        w12h = ( w12h + w5h + ((w12l >>> 0) < (w5l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w13l >>> 1) | (w13h << 31)) ^ ((w13l >>> 8) | (w13h << 24)) ^ ((w13l >>> 7) | (w13h << 25)) )|0;
        w12l = ( w12l + xl)|0;
        w12h = ( w12h + ( ((w13h >>> 1) | (w13l << 31)) ^ ((w13h >>> 8) | (w13l << 24)) ^ (w13h >>> 7) ) + ((w12l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w10l >>> 19) | (w10h << 13)) ^ ((w10l << 3) | (w10h >>> 29)) ^ ((w10l >>> 6) | (w10h << 26)) )|0;
        w12l = ( w12l + xl)|0;
        w12h = ( w12h + ( ((w10h >>> 19) | (w10l << 13)) ^ ((w10h << 3) | (w10l >>> 29)) ^ (w10h >>> 6) ) + ((w12l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x23631e28 + w12l )|0;
        th = ( 0x90befffa + w12h + ((tl >>> 0) < (w12l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 61
        w13l = ( w13l + w6l )|0;
        w13h = ( w13h + w6h + ((w13l >>> 0) < (w6l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w14l >>> 1) | (w14h << 31)) ^ ((w14l >>> 8) | (w14h << 24)) ^ ((w14l >>> 7) | (w14h << 25)) )|0;
        w13l = ( w13l + xl)|0;
        w13h = ( w13h + ( ((w14h >>> 1) | (w14l << 31)) ^ ((w14h >>> 8) | (w14l << 24)) ^ (w14h >>> 7) ) + ((w13l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w11l >>> 19) | (w11h << 13)) ^ ((w11l << 3) | (w11h >>> 29)) ^ ((w11l >>> 6) | (w11h << 26)) )|0;
        w13l = ( w13l + xl)|0;
        w13h = ( w13h + ( ((w11h >>> 19) | (w11l << 13)) ^ ((w11h << 3) | (w11l >>> 29)) ^ (w11h >>> 6) ) + ((w13l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xde82bde9 + w13l )|0;
        th = ( 0xa4506ceb + w13h + ((tl >>> 0) < (w13l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 62
        w14l = ( w14l + w7l )|0;
        w14h = ( w14h + w7h + ((w14l >>> 0) < (w7l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w15l >>> 1) | (w15h << 31)) ^ ((w15l >>> 8) | (w15h << 24)) ^ ((w15l >>> 7) | (w15h << 25)) )|0;
        w14l = ( w14l + xl)|0;
        w14h = ( w14h + ( ((w15h >>> 1) | (w15l << 31)) ^ ((w15h >>> 8) | (w15l << 24)) ^ (w15h >>> 7) ) + ((w14l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w12l >>> 19) | (w12h << 13)) ^ ((w12l << 3) | (w12h >>> 29)) ^ ((w12l >>> 6) | (w12h << 26)) )|0;
        w14l = ( w14l + xl)|0;
        w14h = ( w14h + ( ((w12h >>> 19) | (w12l << 13)) ^ ((w12h << 3) | (w12l >>> 29)) ^ (w12h >>> 6) ) + ((w14l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xb2c67915 + w14l )|0;
        th = ( 0xbef9a3f7 + w14h + ((tl >>> 0) < (w14l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 63
        w15l = ( w15l + w8l )|0;
        w15h = ( w15h + w8h + ((w15l >>> 0) < (w8l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w0l >>> 1) | (w0h << 31)) ^ ((w0l >>> 8) | (w0h << 24)) ^ ((w0l >>> 7) | (w0h << 25)) )|0;
        w15l = ( w15l + xl)|0;
        w15h = ( w15h + ( ((w0h >>> 1) | (w0l << 31)) ^ ((w0h >>> 8) | (w0l << 24)) ^ (w0h >>> 7) ) + ((w15l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w13l >>> 19) | (w13h << 13)) ^ ((w13l << 3) | (w13h >>> 29)) ^ ((w13l >>> 6) | (w13h << 26)) )|0;
        w15l = ( w15l + xl)|0;
        w15h = ( w15h + ( ((w13h >>> 19) | (w13l << 13)) ^ ((w13h << 3) | (w13l >>> 29)) ^ (w13h >>> 6) ) + ((w15l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xe372532b + w15l )|0;
        th = ( 0xc67178f2 + w15h + ((tl >>> 0) < (w15l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 64
        w0l = ( w0l + w9l )|0;
        w0h = ( w0h + w9h + ((w0l >>> 0) < (w9l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w1l >>> 1) | (w1h << 31)) ^ ((w1l >>> 8) | (w1h << 24)) ^ ((w1l >>> 7) | (w1h << 25)) )|0;
        w0l = ( w0l + xl)|0;
        w0h = ( w0h + ( ((w1h >>> 1) | (w1l << 31)) ^ ((w1h >>> 8) | (w1l << 24)) ^ (w1h >>> 7) ) + ((w0l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w14l >>> 19) | (w14h << 13)) ^ ((w14l << 3) | (w14h >>> 29)) ^ ((w14l >>> 6) | (w14h << 26)) )|0;
        w0l = ( w0l + xl)|0;
        w0h = ( w0h + ( ((w14h >>> 19) | (w14l << 13)) ^ ((w14h << 3) | (w14l >>> 29)) ^ (w14h >>> 6) ) + ((w0l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xea26619c + w0l )|0;
        th = ( 0xca273ece + w0h + ((tl >>> 0) < (w0l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 65
        w1l = ( w1l + w10l )|0;
        w1h = ( w1h + w10h + ((w1l >>> 0) < (w10l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w2l >>> 1) | (w2h << 31)) ^ ((w2l >>> 8) | (w2h << 24)) ^ ((w2l >>> 7) | (w2h << 25)) )|0;
        w1l = ( w1l + xl)|0;
        w1h = ( w1h + ( ((w2h >>> 1) | (w2l << 31)) ^ ((w2h >>> 8) | (w2l << 24)) ^ (w2h >>> 7) ) + ((w1l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w15l >>> 19) | (w15h << 13)) ^ ((w15l << 3) | (w15h >>> 29)) ^ ((w15l >>> 6) | (w15h << 26)) )|0;
        w1l = ( w1l + xl)|0;
        w1h = ( w1h + ( ((w15h >>> 19) | (w15l << 13)) ^ ((w15h << 3) | (w15l >>> 29)) ^ (w15h >>> 6) ) + ((w1l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x21c0c207 + w1l )|0;
        th = ( 0xd186b8c7 + w1h + ((tl >>> 0) < (w1l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 66
        w2l = ( w2l + w11l )|0;
        w2h = ( w2h + w11h + ((w2l >>> 0) < (w11l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w3l >>> 1) | (w3h << 31)) ^ ((w3l >>> 8) | (w3h << 24)) ^ ((w3l >>> 7) | (w3h << 25)) )|0;
        w2l = ( w2l + xl)|0;
        w2h = ( w2h + ( ((w3h >>> 1) | (w3l << 31)) ^ ((w3h >>> 8) | (w3l << 24)) ^ (w3h >>> 7) ) + ((w2l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w0l >>> 19) | (w0h << 13)) ^ ((w0l << 3) | (w0h >>> 29)) ^ ((w0l >>> 6) | (w0h << 26)) )|0;
        w2l = ( w2l + xl)|0;
        w2h = ( w2h + ( ((w0h >>> 19) | (w0l << 13)) ^ ((w0h << 3) | (w0l >>> 29)) ^ (w0h >>> 6) ) + ((w2l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xcde0eb1e + w2l )|0;
        th = ( 0xeada7dd6 + w2h + ((tl >>> 0) < (w2l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 67
        w3l = ( w3l + w12l )|0;
        w3h = ( w3h + w12h + ((w3l >>> 0) < (w12l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w4l >>> 1) | (w4h << 31)) ^ ((w4l >>> 8) | (w4h << 24)) ^ ((w4l >>> 7) | (w4h << 25)) )|0;
        w3l = ( w3l + xl)|0;
        w3h = ( w3h + ( ((w4h >>> 1) | (w4l << 31)) ^ ((w4h >>> 8) | (w4l << 24)) ^ (w4h >>> 7) ) + ((w3l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w1l >>> 19) | (w1h << 13)) ^ ((w1l << 3) | (w1h >>> 29)) ^ ((w1l >>> 6) | (w1h << 26)) )|0;
        w3l = ( w3l + xl)|0;
        w3h = ( w3h + ( ((w1h >>> 19) | (w1l << 13)) ^ ((w1h << 3) | (w1l >>> 29)) ^ (w1h >>> 6) ) + ((w3l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xee6ed178 + w3l )|0;
        th = ( 0xf57d4f7f + w3h + ((tl >>> 0) < (w3l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 68
        w4l = ( w4l + w13l )|0;
        w4h = ( w4h + w13h + ((w4l >>> 0) < (w13l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w5l >>> 1) | (w5h << 31)) ^ ((w5l >>> 8) | (w5h << 24)) ^ ((w5l >>> 7) | (w5h << 25)) )|0;
        w4l = ( w4l + xl)|0;
        w4h = ( w4h + ( ((w5h >>> 1) | (w5l << 31)) ^ ((w5h >>> 8) | (w5l << 24)) ^ (w5h >>> 7) ) + ((w4l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w2l >>> 19) | (w2h << 13)) ^ ((w2l << 3) | (w2h >>> 29)) ^ ((w2l >>> 6) | (w2h << 26)) )|0;
        w4l = ( w4l + xl)|0;
        w4h = ( w4h + ( ((w2h >>> 19) | (w2l << 13)) ^ ((w2h << 3) | (w2l >>> 29)) ^ (w2h >>> 6) ) + ((w4l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x72176fba + w4l )|0;
        th = ( 0x6f067aa + w4h + ((tl >>> 0) < (w4l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 69
        w5l = ( w5l + w14l )|0;
        w5h = ( w5h + w14h + ((w5l >>> 0) < (w14l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w6l >>> 1) | (w6h << 31)) ^ ((w6l >>> 8) | (w6h << 24)) ^ ((w6l >>> 7) | (w6h << 25)) )|0;
        w5l = ( w5l + xl)|0;
        w5h = ( w5h + ( ((w6h >>> 1) | (w6l << 31)) ^ ((w6h >>> 8) | (w6l << 24)) ^ (w6h >>> 7) ) + ((w5l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w3l >>> 19) | (w3h << 13)) ^ ((w3l << 3) | (w3h >>> 29)) ^ ((w3l >>> 6) | (w3h << 26)) )|0;
        w5l = ( w5l + xl)|0;
        w5h = ( w5h + ( ((w3h >>> 19) | (w3l << 13)) ^ ((w3h << 3) | (w3l >>> 29)) ^ (w3h >>> 6) ) + ((w5l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xa2c898a6 + w5l )|0;
        th = ( 0xa637dc5 + w5h + ((tl >>> 0) < (w5l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 70
        w6l = ( w6l + w15l )|0;
        w6h = ( w6h + w15h + ((w6l >>> 0) < (w15l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w7l >>> 1) | (w7h << 31)) ^ ((w7l >>> 8) | (w7h << 24)) ^ ((w7l >>> 7) | (w7h << 25)) )|0;
        w6l = ( w6l + xl)|0;
        w6h = ( w6h + ( ((w7h >>> 1) | (w7l << 31)) ^ ((w7h >>> 8) | (w7l << 24)) ^ (w7h >>> 7) ) + ((w6l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w4l >>> 19) | (w4h << 13)) ^ ((w4l << 3) | (w4h >>> 29)) ^ ((w4l >>> 6) | (w4h << 26)) )|0;
        w6l = ( w6l + xl)|0;
        w6h = ( w6h + ( ((w4h >>> 19) | (w4l << 13)) ^ ((w4h << 3) | (w4l >>> 29)) ^ (w4h >>> 6) ) + ((w6l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xbef90dae + w6l )|0;
        th = ( 0x113f9804 + w6h + ((tl >>> 0) < (w6l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 71
        w7l = ( w7l + w0l )|0;
        w7h = ( w7h + w0h + ((w7l >>> 0) < (w0l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w8l >>> 1) | (w8h << 31)) ^ ((w8l >>> 8) | (w8h << 24)) ^ ((w8l >>> 7) | (w8h << 25)) )|0;
        w7l = ( w7l + xl)|0;
        w7h = ( w7h + ( ((w8h >>> 1) | (w8l << 31)) ^ ((w8h >>> 8) | (w8l << 24)) ^ (w8h >>> 7) ) + ((w7l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w5l >>> 19) | (w5h << 13)) ^ ((w5l << 3) | (w5h >>> 29)) ^ ((w5l >>> 6) | (w5h << 26)) )|0;
        w7l = ( w7l + xl)|0;
        w7h = ( w7h + ( ((w5h >>> 19) | (w5l << 13)) ^ ((w5h << 3) | (w5l >>> 29)) ^ (w5h >>> 6) ) + ((w7l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x131c471b + w7l )|0;
        th = ( 0x1b710b35 + w7h + ((tl >>> 0) < (w7l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 72
        w8l = ( w8l + w1l )|0;
        w8h = ( w8h + w1h + ((w8l >>> 0) < (w1l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w9l >>> 1) | (w9h << 31)) ^ ((w9l >>> 8) | (w9h << 24)) ^ ((w9l >>> 7) | (w9h << 25)) )|0;
        w8l = ( w8l + xl)|0;
        w8h = ( w8h + ( ((w9h >>> 1) | (w9l << 31)) ^ ((w9h >>> 8) | (w9l << 24)) ^ (w9h >>> 7) ) + ((w8l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w6l >>> 19) | (w6h << 13)) ^ ((w6l << 3) | (w6h >>> 29)) ^ ((w6l >>> 6) | (w6h << 26)) )|0;
        w8l = ( w8l + xl)|0;
        w8h = ( w8h + ( ((w6h >>> 19) | (w6l << 13)) ^ ((w6h << 3) | (w6l >>> 29)) ^ (w6h >>> 6) ) + ((w8l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x23047d84 + w8l )|0;
        th = ( 0x28db77f5 + w8h + ((tl >>> 0) < (w8l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 73
        w9l = ( w9l + w2l )|0;
        w9h = ( w9h + w2h + ((w9l >>> 0) < (w2l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w10l >>> 1) | (w10h << 31)) ^ ((w10l >>> 8) | (w10h << 24)) ^ ((w10l >>> 7) | (w10h << 25)) )|0;
        w9l = ( w9l + xl)|0;
        w9h = ( w9h + ( ((w10h >>> 1) | (w10l << 31)) ^ ((w10h >>> 8) | (w10l << 24)) ^ (w10h >>> 7) ) + ((w9l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w7l >>> 19) | (w7h << 13)) ^ ((w7l << 3) | (w7h >>> 29)) ^ ((w7l >>> 6) | (w7h << 26)) )|0;
        w9l = ( w9l + xl)|0;
        w9h = ( w9h + ( ((w7h >>> 19) | (w7l << 13)) ^ ((w7h << 3) | (w7l >>> 29)) ^ (w7h >>> 6) ) + ((w9l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x40c72493 + w9l )|0;
        th = ( 0x32caab7b + w9h + ((tl >>> 0) < (w9l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 74
        w10l = ( w10l + w3l )|0;
        w10h = ( w10h + w3h + ((w10l >>> 0) < (w3l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w11l >>> 1) | (w11h << 31)) ^ ((w11l >>> 8) | (w11h << 24)) ^ ((w11l >>> 7) | (w11h << 25)) )|0;
        w10l = ( w10l + xl)|0;
        w10h = ( w10h + ( ((w11h >>> 1) | (w11l << 31)) ^ ((w11h >>> 8) | (w11l << 24)) ^ (w11h >>> 7) ) + ((w10l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w8l >>> 19) | (w8h << 13)) ^ ((w8l << 3) | (w8h >>> 29)) ^ ((w8l >>> 6) | (w8h << 26)) )|0;
        w10l = ( w10l + xl)|0;
        w10h = ( w10h + ( ((w8h >>> 19) | (w8l << 13)) ^ ((w8h << 3) | (w8l >>> 29)) ^ (w8h >>> 6) ) + ((w10l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x15c9bebc + w10l )|0;
        th = ( 0x3c9ebe0a + w10h + ((tl >>> 0) < (w10l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 75
        w11l = ( w11l + w4l )|0;
        w11h = ( w11h + w4h + ((w11l >>> 0) < (w4l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w12l >>> 1) | (w12h << 31)) ^ ((w12l >>> 8) | (w12h << 24)) ^ ((w12l >>> 7) | (w12h << 25)) )|0;
        w11l = ( w11l + xl)|0;
        w11h = ( w11h + ( ((w12h >>> 1) | (w12l << 31)) ^ ((w12h >>> 8) | (w12l << 24)) ^ (w12h >>> 7) ) + ((w11l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w9l >>> 19) | (w9h << 13)) ^ ((w9l << 3) | (w9h >>> 29)) ^ ((w9l >>> 6) | (w9h << 26)) )|0;
        w11l = ( w11l + xl)|0;
        w11h = ( w11h + ( ((w9h >>> 19) | (w9l << 13)) ^ ((w9h << 3) | (w9l >>> 29)) ^ (w9h >>> 6) ) + ((w11l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x9c100d4c + w11l )|0;
        th = ( 0x431d67c4 + w11h + ((tl >>> 0) < (w11l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 76
        w12l = ( w12l + w5l )|0;
        w12h = ( w12h + w5h + ((w12l >>> 0) < (w5l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w13l >>> 1) | (w13h << 31)) ^ ((w13l >>> 8) | (w13h << 24)) ^ ((w13l >>> 7) | (w13h << 25)) )|0;
        w12l = ( w12l + xl)|0;
        w12h = ( w12h + ( ((w13h >>> 1) | (w13l << 31)) ^ ((w13h >>> 8) | (w13l << 24)) ^ (w13h >>> 7) ) + ((w12l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w10l >>> 19) | (w10h << 13)) ^ ((w10l << 3) | (w10h >>> 29)) ^ ((w10l >>> 6) | (w10h << 26)) )|0;
        w12l = ( w12l + xl)|0;
        w12h = ( w12h + ( ((w10h >>> 19) | (w10l << 13)) ^ ((w10h << 3) | (w10l >>> 29)) ^ (w10h >>> 6) ) + ((w12l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xcb3e42b6 + w12l )|0;
        th = ( 0x4cc5d4be + w12h + ((tl >>> 0) < (w12l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 77
        w13l = ( w13l + w6l )|0;
        w13h = ( w13h + w6h + ((w13l >>> 0) < (w6l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w14l >>> 1) | (w14h << 31)) ^ ((w14l >>> 8) | (w14h << 24)) ^ ((w14l >>> 7) | (w14h << 25)) )|0;
        w13l = ( w13l + xl)|0;
        w13h = ( w13h + ( ((w14h >>> 1) | (w14l << 31)) ^ ((w14h >>> 8) | (w14l << 24)) ^ (w14h >>> 7) ) + ((w13l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w11l >>> 19) | (w11h << 13)) ^ ((w11l << 3) | (w11h >>> 29)) ^ ((w11l >>> 6) | (w11h << 26)) )|0;
        w13l = ( w13l + xl)|0;
        w13h = ( w13h + ( ((w11h >>> 19) | (w11l << 13)) ^ ((w11h << 3) | (w11l >>> 29)) ^ (w11h >>> 6) ) + ((w13l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0xfc657e2a + w13l )|0;
        th = ( 0x597f299c + w13h + ((tl >>> 0) < (w13l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 78
        w14l = ( w14l + w7l )|0;
        w14h = ( w14h + w7h + ((w14l >>> 0) < (w7l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w15l >>> 1) | (w15h << 31)) ^ ((w15l >>> 8) | (w15h << 24)) ^ ((w15l >>> 7) | (w15h << 25)) )|0;
        w14l = ( w14l + xl)|0;
        w14h = ( w14h + ( ((w15h >>> 1) | (w15l << 31)) ^ ((w15h >>> 8) | (w15l << 24)) ^ (w15h >>> 7) ) + ((w14l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w12l >>> 19) | (w12h << 13)) ^ ((w12l << 3) | (w12h >>> 29)) ^ ((w12l >>> 6) | (w12h << 26)) )|0;
        w14l = ( w14l + xl)|0;
        w14h = ( w14h + ( ((w12h >>> 19) | (w12l << 13)) ^ ((w12h << 3) | (w12l >>> 29)) ^ (w12h >>> 6) ) + ((w14l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x3ad6faec + w14l )|0;
        th = ( 0x5fcb6fab + w14h + ((tl >>> 0) < (w14l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        // 79
        w15l = ( w15l + w8l )|0;
        w15h = ( w15h + w8h + ((w15l >>> 0) < (w8l >>> 0) ? 1 : 0) )|0;
        xl = ( ((w0l >>> 1) | (w0h << 31)) ^ ((w0l >>> 8) | (w0h << 24)) ^ ((w0l >>> 7) | (w0h << 25)) )|0;
        w15l = ( w15l + xl)|0;
        w15h = ( w15h + ( ((w0h >>> 1) | (w0l << 31)) ^ ((w0h >>> 8) | (w0l << 24)) ^ (w0h >>> 7) ) + ((w15l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ((w13l >>> 19) | (w13h << 13)) ^ ((w13l << 3) | (w13h >>> 29)) ^ ((w13l >>> 6) | (w13h << 26)) )|0;
        w15l = ( w15l + xl)|0;
        w15h = ( w15h + ( ((w13h >>> 19) | (w13l << 13)) ^ ((w13h << 3) | (w13l >>> 29)) ^ (w13h >>> 6) ) + ((w15l >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        tl = ( 0x4a475817 + w15l )|0;
        th = ( 0x6c44198c + w15h + ((tl >>> 0) < (w15l >>> 0) ? 1 : 0) )|0;
        tl = ( tl + hl )|0;
        th = ( th + hh + ((tl >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
        xl = ( ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9)) )|0;
        tl = ( tl + xl )|0;
        th = ( th + (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9))) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        xl = ( ( gl ^ el & (fl^gl) ) )|0;
        tl = ( tl + xl )|0;
        th = ( th + ( gh ^ eh & (fh^gh) ) + ((tl >>> 0) < (xl >>> 0) ? 1 : 0) )|0;
        hl = gl; hh = gh;
        gl = fl; gh = fh;
        fl = el; fh = eh;
        el = ( dl + tl )|0; eh = ( dh + th + ((el >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        dl = cl; dh = ch;
        cl = bl; ch = bh;
        bl = al; bh = ah;
        al = ( tl + ( (bl & cl) ^ ( dl & (bl ^ cl) ) ) )|0;
        ah = ( th + ( (bh & ch) ^ ( dh & (bh ^ ch) ) ) + ((al >>> 0) < (tl >>> 0) ? 1 : 0) )|0;
        xl = ( ((bl >>> 28) | (bh << 4)) ^ ((bl << 30) | (bh >>> 2)) ^ ((bl << 25) | (bh >>> 7)) )|0;
        al = ( al + xl )|0;
        ah = ( ah + (((bh >>> 28) | (bl << 4)) ^ ((bh << 30) | (bl >>> 2)) ^ ((bh << 25) | (bl >>> 7))) + ((al >>> 0) < (xl >>> 0) ? 1 : 0) )|0;

        H0l = ( H0l + al )|0;
        H0h = ( H0h + ah + ((H0l >>> 0) < (al >>> 0) ? 1 : 0) )|0;
        H1l = ( H1l + bl )|0;
        H1h = ( H1h + bh + ((H1l >>> 0) < (bl >>> 0) ? 1 : 0) )|0;
        H2l = ( H2l + cl )|0;
        H2h = ( H2h + ch + ((H2l >>> 0) < (cl >>> 0) ? 1 : 0) )|0;
        H3l = ( H3l + dl )|0;
        H3h = ( H3h + dh + ((H3l >>> 0) < (dl >>> 0) ? 1 : 0) )|0;
        H4l = ( H4l + el )|0;
        H4h = ( H4h + eh + ((H4l >>> 0) < (el >>> 0) ? 1 : 0) )|0;
        H5l = ( H5l + fl )|0;
        H5h = ( H5h + fh + ((H5l >>> 0) < (fl >>> 0) ? 1 : 0) )|0;
        H6l = ( H6l + gl )|0;
        H6h = ( H6h + gh + ((H6l >>> 0) < (gl >>> 0) ? 1 : 0) )|0;
        H7l = ( H7l + hl )|0;
        H7h = ( H7h + hh + ((H7l >>> 0) < (hl >>> 0) ? 1 : 0) )|0;
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
            HEAP[offset|60]<<24 | HEAP[offset|61]<<16 | HEAP[offset|62]<<8 | HEAP[offset|63],
            HEAP[offset|64]<<24 | HEAP[offset|65]<<16 | HEAP[offset|66]<<8 | HEAP[offset|67],
            HEAP[offset|68]<<24 | HEAP[offset|69]<<16 | HEAP[offset|70]<<8 | HEAP[offset|71],
            HEAP[offset|72]<<24 | HEAP[offset|73]<<16 | HEAP[offset|74]<<8 | HEAP[offset|75],
            HEAP[offset|76]<<24 | HEAP[offset|77]<<16 | HEAP[offset|78]<<8 | HEAP[offset|79],
            HEAP[offset|80]<<24 | HEAP[offset|81]<<16 | HEAP[offset|82]<<8 | HEAP[offset|83],
            HEAP[offset|84]<<24 | HEAP[offset|85]<<16 | HEAP[offset|86]<<8 | HEAP[offset|87],
            HEAP[offset|88]<<24 | HEAP[offset|89]<<16 | HEAP[offset|90]<<8 | HEAP[offset|91],
            HEAP[offset|92]<<24 | HEAP[offset|93]<<16 | HEAP[offset|94]<<8 | HEAP[offset|95],
            HEAP[offset|96]<<24 | HEAP[offset|97]<<16 | HEAP[offset|98]<<8 | HEAP[offset|99],
            HEAP[offset|100]<<24 | HEAP[offset|101]<<16 | HEAP[offset|102]<<8 | HEAP[offset|103],
            HEAP[offset|104]<<24 | HEAP[offset|105]<<16 | HEAP[offset|106]<<8 | HEAP[offset|107],
            HEAP[offset|108]<<24 | HEAP[offset|109]<<16 | HEAP[offset|110]<<8 | HEAP[offset|111],
            HEAP[offset|112]<<24 | HEAP[offset|113]<<16 | HEAP[offset|114]<<8 | HEAP[offset|115],
            HEAP[offset|116]<<24 | HEAP[offset|117]<<16 | HEAP[offset|118]<<8 | HEAP[offset|119],
            HEAP[offset|120]<<24 | HEAP[offset|121]<<16 | HEAP[offset|122]<<8 | HEAP[offset|123],
            HEAP[offset|124]<<24 | HEAP[offset|125]<<16 | HEAP[offset|126]<<8 | HEAP[offset|127]
        );
    }

    // offset — multiple of 32
    function _state_to_heap ( output ) {
        output = output|0;

        HEAP[output|0] = H0h>>>24;
        HEAP[output|1] = H0h>>>16&255;
        HEAP[output|2] = H0h>>>8&255;
        HEAP[output|3] = H0h&255;
        HEAP[output|4] = H0l>>>24;
        HEAP[output|5] = H0l>>>16&255;
        HEAP[output|6] = H0l>>>8&255;
        HEAP[output|7] = H0l&255;
        HEAP[output|8] = H1h>>>24;
        HEAP[output|9] = H1h>>>16&255;
        HEAP[output|10] = H1h>>>8&255;
        HEAP[output|11] = H1h&255;
        HEAP[output|12] = H1l>>>24;
        HEAP[output|13] = H1l>>>16&255;
        HEAP[output|14] = H1l>>>8&255;
        HEAP[output|15] = H1l&255;
        HEAP[output|16] = H2h>>>24;
        HEAP[output|17] = H2h>>>16&255;
        HEAP[output|18] = H2h>>>8&255;
        HEAP[output|19] = H2h&255;
        HEAP[output|20] = H2l>>>24;
        HEAP[output|21] = H2l>>>16&255;
        HEAP[output|22] = H2l>>>8&255;
        HEAP[output|23] = H2l&255;
        HEAP[output|24] = H3h>>>24;
        HEAP[output|25] = H3h>>>16&255;
        HEAP[output|26] = H3h>>>8&255;
        HEAP[output|27] = H3h&255;
        HEAP[output|28] = H3l>>>24;
        HEAP[output|29] = H3l>>>16&255;
        HEAP[output|30] = H3l>>>8&255;
        HEAP[output|31] = H3l&255;
        HEAP[output|32] = H4h>>>24;
        HEAP[output|33] = H4h>>>16&255;
        HEAP[output|34] = H4h>>>8&255;
        HEAP[output|35] = H4h&255;
        HEAP[output|36] = H4l>>>24;
        HEAP[output|37] = H4l>>>16&255;
        HEAP[output|38] = H4l>>>8&255;
        HEAP[output|39] = H4l&255;
        HEAP[output|40] = H5h>>>24;
        HEAP[output|41] = H5h>>>16&255;
        HEAP[output|42] = H5h>>>8&255;
        HEAP[output|43] = H5h&255;
        HEAP[output|44] = H5l>>>24;
        HEAP[output|45] = H5l>>>16&255;
        HEAP[output|46] = H5l>>>8&255;
        HEAP[output|47] = H5l&255;
        HEAP[output|48] = H6h>>>24;
        HEAP[output|49] = H6h>>>16&255;
        HEAP[output|50] = H6h>>>8&255;
        HEAP[output|51] = H6h&255;
        HEAP[output|52] = H6l>>>24;
        HEAP[output|53] = H6l>>>16&255;
        HEAP[output|54] = H6l>>>8&255;
        HEAP[output|55] = H6l&255;
        HEAP[output|56] = H7h>>>24;
        HEAP[output|57] = H7h>>>16&255;
        HEAP[output|58] = H7h>>>8&255;
        HEAP[output|59] = H7h&255;
        HEAP[output|60] = H7l>>>24;
        HEAP[output|61] = H7l>>>16&255;
        HEAP[output|62] = H7l>>>8&255;
        HEAP[output|63] = H7l&255;
    }

    function reset () {
        H0h = 0x6a09e667;
        H0l = 0xf3bcc908;
        H1h = 0xbb67ae85;
        H1l = 0x84caa73b;
        H2h = 0x3c6ef372;
        H2l = 0xfe94f82b;
        H3h = 0xa54ff53a;
        H3l = 0x5f1d36f1;
        H4h = 0x510e527f;
        H4l = 0xade682d1;
        H5h = 0x9b05688c;
        H5l = 0x2b3e6c1f;
        H6h = 0x1f83d9ab;
        H6l = 0xfb41bd6b;
        H7h = 0x5be0cd19;
        H7l = 0x137e2179;

        TOTAL0 = TOTAL1 = 0;
    }

    function init ( h0h, h0l, h1h, h1l, h2h, h2l, h3h, h3l, h4h, h4l, h5h, h5l, h6h, h6l, h7h, h7l, total0, total1 ) {
        h0h = h0h|0;
        h0l = h0l|0;
        h1h = h1h|0;
        h1l = h1l|0;
        h2h = h2h|0;
        h2l = h2l|0;
        h3h = h3h|0;
        h3l = h3l|0;
        h4h = h4h|0;
        h4l = h4l|0;
        h5h = h5h|0;
        h5l = h5l|0;
        h6h = h6h|0;
        h6l = h6l|0;
        h7h = h7h|0;
        h7l = h7l|0;
        total0 = total0|0;
        total1 = total1|0;

        H0h = h0h;
        H0l = h0l;
        H1h = h1h;
        H1l = h1l;
        H2h = h2h;
        H2l = h2l;
        H3h = h3h;
        H3l = h3l;
        H4h = h4h;
        H4l = h4l;
        H5h = h5h;
        H5l = h5l;
        H6h = h6h;
        H6l = h6l;
        H7h = h7h;
        H7l = h7l;
        TOTAL0 = total0;
        TOTAL1 = total1;
    }

    // offset — multiple of 128
    function process ( offset, length ) {
        offset = offset|0;
        length = length|0;

        var hashed = 0;

        if ( offset & 127 )
            return -1;

        while ( (length|0) >= 128 ) {
            _core_heap(offset);

            offset = ( offset + 128 )|0;
            length = ( length - 128 )|0;

            hashed = ( hashed + 128 )|0;
        }

        TOTAL0 = ( TOTAL0 + hashed )|0;
        if ( TOTAL0>>>0 < hashed>>>0 ) TOTAL1 = ( TOTAL1 + 1 )|0;

        return hashed|0;
    }

    // offset — multiple of 128
    // output — multiple of 64
    function finish ( offset, length, output ) {
        offset = offset|0;
        length = length|0;
        output = output|0;

        var hashed = 0,
            i = 0;

        if ( offset & 127 )
            return -1;

        if ( ~output )
            if ( output & 63 )
                return -1;

        if ( (length|0) >= 128 ) {
            hashed = process( offset, length )|0;
            if ( (hashed|0) == -1 )
                return -1;

            offset = ( offset + hashed )|0;
            length = ( length - hashed )|0;
        }

        hashed = ( hashed + length )|0;
        TOTAL0 = ( TOTAL0 + length )|0;
        if ( TOTAL0>>>0 < length>>>0 ) TOTAL1 = ( TOTAL1 + 1 )|0;

        HEAP[offset|length] = 0x80;

        if ( (length|0) >= 112 ) {
            for ( i = (length+1)|0; (i|0) < 128; i = (i+1)|0 )
                HEAP[offset|i] = 0x00;

            _core_heap(offset);

            length = 0;

            HEAP[offset|0] = 0;
        }

        for ( i = (length+1)|0; (i|0) < 123; i = (i+1)|0 )
            HEAP[offset|i] = 0;

        HEAP[offset|120] = TOTAL1>>>21&255;
        HEAP[offset|121] = TOTAL1>>>13&255;
        HEAP[offset|122] = TOTAL1>>>5&255;
        HEAP[offset|123] = TOTAL1<<3&255 | TOTAL0>>>29;
        HEAP[offset|124] = TOTAL0>>>21&255;
        HEAP[offset|125] = TOTAL0>>>13&255;
        HEAP[offset|126] = TOTAL0>>>5&255;
        HEAP[offset|127] = TOTAL0<<3&255;
        _core_heap(offset);

        if ( ~output )
            _state_to_heap(output);

        return hashed|0;
    }

    function hmac_reset () {
        H0h = I0h;
        H0l = I0l;
        H1h = I1h;
        H1l = I1l;
        H2h = I2h;
        H2l = I2l;
        H3h = I3h;
        H3l = I3l;
        H4h = I4h;
        H4l = I4l;
        H5h = I5h;
        H5l = I5l;
        H6h = I6h;
        H6l = I6l;
        H7h = I7h;
        H7l = I7l;
        TOTAL0 = 128;
        TOTAL1 = 0;
    }

    function _hmac_opad () {
        H0h = O0h;
        H0l = O0l;
        H1h = O1h;
        H1l = O1l;
        H2h = O2h;
        H2l = O2l;
        H3h = O3h;
        H3l = O3l;
        H4h = O4h;
        H4l = O4l;
        H5h = O5h;
        H5l = O5l;
        H6h = O6h;
        H6l = O6l;
        H7h = O7h;
        H7l = O7l;
        TOTAL0 = 128;
        TOTAL1 = 0;
    }

    function hmac_init ( p0h, p0l, p1h, p1l, p2h, p2l, p3h, p3l, p4h, p4l, p5h, p5l, p6h, p6l, p7h, p7l, p8h, p8l, p9h, p9l, p10h, p10l, p11h, p11l, p12h, p12l, p13h, p13l, p14h, p14l, p15h, p15l ) {
        p0h = p0h|0;
        p0l = p0l|0;
        p1h = p1h|0;
        p1l = p1l|0;
        p2h = p2h|0;
        p2l = p2l|0;
        p3h = p3h|0;
        p3l = p3l|0;
        p4h = p4h|0;
        p4l = p4l|0;
        p5h = p5h|0;
        p5l = p5l|0;
        p6h = p6h|0;
        p6l = p6l|0;
        p7h = p7h|0;
        p7l = p7l|0;
        p8h = p8h|0;
        p8l = p8l|0;
        p9h = p9h|0;
        p9l = p9l|0;
        p10h = p10h|0;
        p10l = p10l|0;
        p11h = p11h|0;
        p11l = p11l|0;
        p12h = p12h|0;
        p12l = p12l|0;
        p13h = p13h|0;
        p13l = p13l|0;
        p14h = p14h|0;
        p14l = p14l|0;
        p15h = p15h|0;
        p15l = p15l|0;

        // opad
        reset();
        _core(
            p0h ^ 0x5c5c5c5c,
            p0l ^ 0x5c5c5c5c,
            p1h ^ 0x5c5c5c5c,
            p1l ^ 0x5c5c5c5c,
            p2h ^ 0x5c5c5c5c,
            p2l ^ 0x5c5c5c5c,
            p3h ^ 0x5c5c5c5c,
            p3l ^ 0x5c5c5c5c,
            p4h ^ 0x5c5c5c5c,
            p4l ^ 0x5c5c5c5c,
            p5h ^ 0x5c5c5c5c,
            p5l ^ 0x5c5c5c5c,
            p6h ^ 0x5c5c5c5c,
            p6l ^ 0x5c5c5c5c,
            p7h ^ 0x5c5c5c5c,
            p7l ^ 0x5c5c5c5c,
            p8h ^ 0x5c5c5c5c,
            p8l ^ 0x5c5c5c5c,
            p9h ^ 0x5c5c5c5c,
            p9l ^ 0x5c5c5c5c,
            p10h ^ 0x5c5c5c5c,
            p10l ^ 0x5c5c5c5c,
            p11h ^ 0x5c5c5c5c,
            p11l ^ 0x5c5c5c5c,
            p12h ^ 0x5c5c5c5c,
            p12l ^ 0x5c5c5c5c,
            p13h ^ 0x5c5c5c5c,
            p13l ^ 0x5c5c5c5c,
            p14h ^ 0x5c5c5c5c,
            p14l ^ 0x5c5c5c5c,
            p15h ^ 0x5c5c5c5c,
            p15l ^ 0x5c5c5c5c
        );
        O0h = H0h;
        O0l = H0l;
        O1h = H1h;
        O1l = H1l;
        O2h = H2h;
        O2l = H2l;
        O3h = H3h;
        O3l = H3l;
        O4h = H4h;
        O4l = H4l;
        O5h = H5h;
        O5l = H5l;
        O6h = H6h;
        O6l = H6l;
        O7h = H7h;
        O7l = H7l;

        // ipad
        reset();
        _core(
           p0h ^ 0x36363636,
           p0l ^ 0x36363636,
           p1h ^ 0x36363636,
           p1l ^ 0x36363636,
           p2h ^ 0x36363636,
           p2l ^ 0x36363636,
           p3h ^ 0x36363636,
           p3l ^ 0x36363636,
           p4h ^ 0x36363636,
           p4l ^ 0x36363636,
           p5h ^ 0x36363636,
           p5l ^ 0x36363636,
           p6h ^ 0x36363636,
           p6l ^ 0x36363636,
           p7h ^ 0x36363636,
           p7l ^ 0x36363636,
           p8h ^ 0x36363636,
           p8l ^ 0x36363636,
           p9h ^ 0x36363636,
           p9l ^ 0x36363636,
           p10h ^ 0x36363636,
           p10l ^ 0x36363636,
           p11h ^ 0x36363636,
           p11l ^ 0x36363636,
           p12h ^ 0x36363636,
           p12l ^ 0x36363636,
           p13h ^ 0x36363636,
           p13l ^ 0x36363636,
           p14h ^ 0x36363636,
           p14l ^ 0x36363636,
           p15h ^ 0x36363636,
           p15l ^ 0x36363636
        );
        I0h = H0h;
        I0l = H0l;
        I1h = H1h;
        I1l = H1l;
        I2h = H2h;
        I2l = H2l;
        I3h = H3h;
        I3l = H3l;
        I4h = H4h;
        I4l = H4l;
        I5h = H5h;
        I5l = H5l;
        I6h = H6h;
        I6l = H6l;
        I7h = H7h;
        I7l = H7l;

        TOTAL0 = 128;
        TOTAL1 = 0;
    }

    // offset — multiple of 128
    // output — multiple of 64
    function hmac_finish ( offset, length, output ) {
        offset = offset|0;
        length = length|0;
        output = output|0;

        var t0h = 0, t0l = 0, t1h = 0, t1l = 0, t2h = 0, t2l = 0, t3h = 0, t3l = 0,
            t4h = 0, t4l = 0, t5h = 0, t5l = 0, t6h = 0, t6l = 0, t7h = 0, t7l = 0,
            hashed = 0;

        if ( offset & 127 )
            return -1;

        if ( ~output )
            if ( output & 63 )
                return -1;

        hashed = finish( offset, length, -1 )|0;
        t0h = H0h;
        t0l = H0l;
        t1h = H1h;
        t1l = H1l;
        t2h = H2h;
        t2l = H2l;
        t3h = H3h;
        t3l = H3l;
        t4h = H4h;
        t4l = H4l;
        t5h = H5h;
        t5l = H5l;
        t6h = H6h;
        t6l = H6l;
        t7h = H7h;
        t7l = H7l;

        _hmac_opad();
        _core( t0h, t0l, t1h, t1l, t2h, t2l, t3h, t3l, t4h, t4l, t5h, t5l, t6h, t6l, t7h, t7l, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1536 );

        if ( ~output )
            _state_to_heap(output);

        return hashed|0;
    }

    // salt is assumed to be already processed
    // offset — multiple of 128
    // output — multiple of 64
    function pbkdf2_generate_block ( offset, length, block, count, output ) {
        offset = offset|0;
        length = length|0;
        block = block|0;
        count = count|0;
        output = output|0;

        var h0h = 0, h0l = 0, h1h = 0, h1l = 0, h2h = 0, h2l = 0, h3h = 0, h3l = 0,
            h4h = 0, h4l = 0, h5h = 0, h5l = 0, h6h = 0, h6l = 0, h7h = 0, h7l = 0,
            t0h = 0, t0l = 0, t1h = 0, t1l = 0, t2h = 0, t2l = 0, t3h = 0, t3l = 0,
            t4h = 0, t4l = 0, t5h = 0, t5l = 0, t6h = 0, t6l = 0, t7h = 0, t7l = 0;

        if ( offset & 127 )
            return -1;

        if ( ~output )
            if ( output & 63 )
                return -1;

        // pad block number into heap
        // FIXME probable OOB write
        HEAP[(offset+length)|0]   = block>>>24;
        HEAP[(offset+length+1)|0] = block>>>16&255;
        HEAP[(offset+length+2)|0] = block>>>8&255;
        HEAP[(offset+length+3)|0] = block&255;

        // finish first iteration
        hmac_finish( offset, (length+4)|0, -1 )|0;

        h0h = t0h = H0h;
        h0l = t0l = H0l;
        h1h = t1h = H1h;
        h1l = t1l = H1l;
        h2h = t2h = H2h;
        h2l = t2l = H2l;
        h3h = t3h = H3h;
        h3l = t3l = H3l;
        h4h = t4h = H4h;
        h4l = t4l = H4l;
        h5h = t5h = H5h;
        h5l = t5l = H5l;
        h6h = t6h = H6h;
        h6l = t6l = H6l;
        h7h = t7h = H7h;
        h7l = t7l = H7l;

        count = (count-1)|0;

        // perform the rest iterations
        while ( (count|0) > 0 ) {
            hmac_reset();
            _core( t0h, t0l, t1h, t1l, t2h, t2l, t3h, t3l, t4h, t4l, t5h, t5l, t6h, t6l, t7h, t7l, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1536 );

            t0h = H0h;
            t0l = H0l;
            t1h = H1h;
            t1l = H1l;
            t2h = H2h;
            t2l = H2l;
            t3h = H3h;
            t3l = H3l;
            t4h = H4h;
            t4l = H4l;
            t5h = H5h;
            t5l = H5l;
            t6h = H6h;
            t6l = H6l;
            t7h = H7h;
            t7l = H7l;

            _hmac_opad();
            _core( t0h, t0l, t1h, t1l, t2h, t2l, t3h, t3l, t4h, t4l, t5h, t5l, t6h, t6l, t7h, t7l, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1536 );

            t0h = H0h;
            t0l = H0l;
            t1h = H1h;
            t1l = H1l;
            t2h = H2h;
            t2l = H2l;
            t3h = H3h;
            t3l = H3l;
            t4h = H4h;
            t4l = H4l;
            t5h = H5h;
            t5l = H5l;
            t6h = H6h;
            t6l = H6l;
            t7h = H7h;
            t7l = H7l;

            h0h = h0h ^ H0h;
            h0l = h0l ^ H0l;
            h1h = h1h ^ H1h;
            h1l = h1l ^ H1l;
            h2h = h2h ^ H2h;
            h2l = h2l ^ H2l;
            h3h = h3h ^ H3h;
            h3l = h3l ^ H3l;
            h4h = h4h ^ H4h;
            h4l = h4l ^ H4l;
            h5h = h5h ^ H5h;
            h5l = h5l ^ H5l;
            h6h = h6h ^ H6h;
            h6l = h6l ^ H6l;
            h7h = h7h ^ H7h;
            h7l = h7l ^ H7l;

            count = (count-1)|0;
        }

        H0h = h0h;
        H0l = h0l;
        H1h = h1h;
        H1l = h1l;
        H2h = h2h;
        H2l = h2l;
        H3h = h3h;
        H3l = h3l;
        H4h = h4h;
        H4l = h4l;
        H5h = h5h;
        H5l = h5l;
        H6h = h6h;
        H6l = h6l;
        H7h = h7h;
        H7l = h7l;

        if ( ~output )
            _state_to_heap(output);

        return 0;
    }

    return {
        // SHA512
        reset: reset,
        init: init,
        process: process,
        finish: finish,

        // HMAC-SHA512
        hmac_reset: hmac_reset,
        hmac_init: hmac_init,
        hmac_finish: hmac_finish,

        // PBKDF2-HMAC-SHA512
        pbkdf2_generate_block: pbkdf2_generate_block
    }
}
