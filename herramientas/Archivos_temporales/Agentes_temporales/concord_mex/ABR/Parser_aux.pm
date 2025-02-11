package ABR::Parser_aux;
# Version=1.1
use POSIX qw(strftime);
use warnings;
use strict;

use ABR::concord_mex;

sub new {
    my $class = shift;
    my $self;
    my $mensaje_x733;
    my %find_hash;

    %find_hash = (
        "1.3.6.1.4.1.149.22" => { trap_name => "nhLiveClearException", subroutine => "ABR::concord_mex::_1_3_6_1_4_1_149_22" },
        "1.3.6.1.4.1.149.16" => { trap_name => "netHealthWarning", subroutine => "ABR::concord_mex::_1_3_6_1_4_1_149_16" },
        "1.3.6.1.4.1.149.21" => { trap_name => "nhLiveAlarm", subroutine => "ABR::concord_mex::_1_3_6_1_4_1_149_21" },
        "1.3.6.1.4.1.149.23" => { trap_name => "nhLiveClearAlarm", subroutine => "ABR::concord_mex::_1_3_6_1_4_1_149_23" },
        "1.3.6.1.4.1.149.20" => { trap_name => "nhLiveException", subroutine => "ABR::concord_mex::_1_3_6_1_4_1_149_20" },
        "1.3.6.1.4.1.149.15" => { trap_name => "netHealthInfo", subroutine => "ABR::concord_mex::_1_3_6_1_4_1_149_15" },
        "1.3.6.1.4.1.149.18" => { trap_name => "netHealthUrgent", subroutine => "ABR::concord_mex::_1_3_6_1_4_1_149_18" },
        "1.3.6.1.4.1.149.19" => { trap_name => "netHealthException", subroutine => "ABR::concord_mex::_1_3_6_1_4_1_149_19" },
        "1.3.6.1.4.1.149.25" => { trap_name => "nhLiveResetExceptions", subroutine => "ABR::concord_mex::_1_3_6_1_4_1_149_25" },
        "1.3.6.1.4.1.149.24" => { trap_name => "nhLiveUpdateException", subroutine => "ABR::concord_mex::_1_3_6_1_4_1_149_24" },
        "1.3.6.1.4.1.149.17" => { trap_name => "netHealthReset", subroutine => "ABR::concord_mex::_1_3_6_1_4_1_149_17" },
    );

    $self = bless( { find_hash => \%find_hash, mensaje_x733 => \$mensaje_x733 }, $class );
}

sub formatter {
    my $self           = shift;
    my $trap_array_ref = shift;
    my $config         = shift;
    my $onPrints       = shift;
    my @trap_array     = @{$trap_array_ref};
    my $find_hash      = $self->{find_hash};
    my %entrada_val;
    my $entrada        = \%entrada_val;
    my $trap;
    my $trap_name;
    my $trap_sub;
    my $func_ref;
    my $trap_oid;
    my $trap_info;
    my $alarm_txt;
    my $contador = 0;

    if ($onPrints) { print "\n"; }

    foreach (@trap_array) {
        my $key_var = (keys %$_)[0];
        if (ifexists($key_var)) {
            $entrada_val{$key_var} = $_->{$key_var};
            
            print "THE KEY IS: $key_var" . " AND THE VALUE IS: $entrada_val{ $key_var }" . "\n";

            my $trap_oid = $entrada->{"EOID"};
            if (!ifexists($trap_oid)) {
                $trap_oid = "EMPTY";
            }

            if ($key_var =~ /(.+)\.0$/) {
                my $key_var_tmp = $1;
                my $val_tmp = $entrada->{$key_var};
                delete($entrada->{$key_var});
                $entrada->{$key_var_tmp} = $val_tmp;
                if ($onPrints) { print "THE KEY IS: $key_var_tmp AND THE VALUE IS: $val_tmp\n"; }
            } else {
                if ($onPrints) { print "THE KEY IS: $key_var AND THE VALUE IS: $entrada_val{$key_var}\n"; }
            }
        }
    }

    $trap_oid = $entrada->{"EOID"};
    if (!ifexists($trap_oid)) {
        $trap_oid = "EMPTY";
    }
    
    print "The Trap is: $trap_oid\n";
    
    $trap_info = $find_hash->{$trap_oid};

    if ($onPrints) {
        if (ifexists($trap_info->{trap_name})) { print "The TRAP name is: " . $trap_info->{trap_name} . "\n"; }
        else { print "The TRAP name is: not defined\n"; }
        if (ifexists($trap_info->{subroutine})) {
            print "The TRAP subroutine is: " . $trap_info->{subroutine} . "\n";
            print "\n\n";
        } else { print "The TRAP subroutine is: not defined\n"; }
    }

    $trap_name = $trap_info->{trap_name};
    $trap_sub  = $trap_info->{subroutine};


    print "$trap_oid -> $trap_sub";
    print "The Trap is $trap_name\n";


    if (ifexists($trap_name)) {
        $func_ref = \&$trap_sub;
        $alarm_txt = $func_ref->(\%entrada_val, $trap_name, $config);
        $contador += 1;
        print "$trap_oid -> $trap_sub\n";
        print "\n\n======================== *** =================================\n\n";
        if ($onPrints) { print "ESTA ES LA ALARMA: $alarm_txt\n"; }
        print "\n\n======================== *** =================================\n\n";

    } else {
        if ($onPrints) { print "Alarm message is empty\n"; }
    }
    return $alarm_txt;
}

sub ifexists {
    my $variable = shift;
    if (defined $variable && $variable ne "") {
        return 1;
    } else {
        return 0;
    }
}

1;
