package ABR::MICROTIME;
# Version=1.0
use Time::HiRes qw(gettimeofday);
use bignum;

sub getmicro {
    my $micros;
    (my $ts, my $tm) = gettimeofday();
    $micros = ($ts + $tm / 1000000) * 1000000;
    return $micros;
}

1;
