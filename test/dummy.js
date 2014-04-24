module("dummy");

test( "dummy test", function () {
    ok( true, "Passed!" );
});

test( "add with carry proparation", function () {
    var a = 0xad4e6ae6, b = 0xedfdecc8, c = 1, d = 0x19b4c57af, dc = 1,
        r = 0, rc = 0, u = 0, v = 0;

    r = (a + c)|0, rc = (r>>>0) < (a>>>0) ? 1 : 0;
    r = (b + r)|0, rc = (r>>>0) < (b>>>0) ? 1 : rc;
    equal( r>>>0, d>>>0, "adc32 result ok" );
    equal( rc, dc, "adc32 carry ok" );

    u = ( (a & 0xffff) + (b & 0xffff)|0 ) + c|0;
    v = ( (a >>> 16) + (b >>> 16)|0 ) + (u >>> 16)|0;
    r = (u & 0xffff) | (v << 16);
    rc = v >>> 16;
    equal( r>>>0, d>>>0, "adc16x2 result ok" );
    equal( rc, dc, "adc16x2 carry ok" );
});

test( "multiply and add", function () {
    var imul = Math.imul,
        x = 0xad4e6ae6, y = 0xedfdecc8, z = 0x9b4c57af,
        h = 0xa11d7fc2, l = 0xde69e35f,
        u = 0, v = 0, w = 0,
        rh = 0, rl = 0;

    u = imul( x & 0xffff, y & 0xffff ) + (z & 0xffff) | 0;
    v = imul( x & 0xffff, y >>> 16 ) + (z >>> 16) | 0;
    w = ( imul( x >>> 16, y & 0xffff ) + (v & 0xffff) | 0 ) + (u >>> 16) | 0;
    rh = ( imul( x >>> 16, y >>> 16 ) + (v >>> 16) | 0 ) + (w >>> 16) | 0;
    rl = (w << 16) | (u & 0xffff);

    equal( h>>>0, rh>>>0, "high part is ok" );
    equal( l>>>0, rl>>>0, "low part is ok" );
});

test( "divide with remainder", function () {
    var n0 = 0xad4e6ae6, n1 = 0xedfdecc8, d0 = 0xeeddccbb, q0 = 0xff101123, r0 = 0x39b30255;

    var qh, ql, rh, rl, w0, w1, n, dh, dl, c, imul = Math.imul;

    dh = d0 >>> 16, dl = d0 & 0xffff;

    n = n1;
    qh = ( n / dh )|0, rh = n % dh;
    while ( ( (rh|0) < 0x10000 )
        & ( ( qh == 0x10000 ) | ( (imul(qh,dl)>>>0) > (((rh<<16)|(n0>>>16))>>>0) ) ) )
    {
        qh = (qh-1)|0;
        rh = (rh+dh)|0;
    }
    w0 = imul(qh, dl)|0;
    w1 = (w0 >>> 16) + imul(qh, dh)|0;
    w0 = w0 << 16;
    n = (n0-w0)|0, c = ( (n>>>0) > (n0>>>0) )|0, n0 = n;
    n = (n1-c)|0, c = ( (n>>>0) > (n1>>>0) )|0, n1 = (n-w1)|0, c = ( (n1>>>0) > (n>>>0) )|c;
    if ( c ) {
        qh = (qh-1)|0;
        n = (n0+(d0<<16))|0, c = ( (n>>>0) < (n0>>>0) )|0, n0 = n;
        n = (n1+c)|0, c = !n, n1 = (n+dh)|0, c = ( (n1>>>0) < (n>>>0) )|c;
    }

    n = (n1 << 16) | (n0 >>> 16);
    ql = ( n / dh )|0, rl = n % dh;
    while ( ( (rl|0) < 0x10000 )
        & ( ( ql == 0x10000 ) | ( (imul(ql,dl)>>>0) > (((rl << 16)|(n0 & 0xffff))>>>0) ) ) )
    {
        ql = (ql-1)|0;
        rl = (rl+dh)|0;
    }
    w0 = imul(ql, dl)|0;
    w1 = (w0 >>> 16) + imul(ql, dh)|0;
    w0 = (w1 << 16) | (w0 & 0xffff);
    w1 = w1 >>> 16;
    n = (n0-w0)|0, c = ( (n>>>0) > (n0>>>0) )|0, n0 = n;
    n = (n1-c)|0, c = ( (n>>>0) > (n1>>>0) )|0, n1 = (n-w1)|0, c = ( (n1>>>0) > (n>>>0) )|c;
    if ( c ) {
        ql = (ql-1)|0;
        n = (n0+d0)|0, c = ( (n>>>0) < (n0>>>0) )|0, n0 = n;
        n1 = (n1+c)|0;
    }

    equal( ((qh<<16)|ql)>>>0, q0, "quotient ok" );
    equal( n0>>>0, r0, "remainder ok" );
});

test( "imul", function () {
    equal( Math.imul(-338592732,968756475)|0, 787375948, "imul works fine" );
});
