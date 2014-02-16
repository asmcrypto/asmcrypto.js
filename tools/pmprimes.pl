#!/usb/bin/env perl
use uni::perl;

use Math::BigInt;
use Math::Prime::Util qw( prev_prime is_provable_prime );

for ( my $n = int($ARGV[0])||1; ; $n++ ) {
    my $e = 32*$n;
    my $q = Math::BigInt->new(1) << $e;
    my $p;

    for ( $p = $q; is_provable_prime($p) != 2; $p = prev_prime($p) ) {
        last if ($q-$p) > 0xffff;
    }

    if ( (my $k = $q-$p) > 0xffff ) {
        say "oops, nothing found for 2^(32*$n)";
    } else {
        say "gotcha! found 2^(32 * $n) - " . $k->as_hex;
    }
}
