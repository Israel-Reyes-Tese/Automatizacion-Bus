#!/usr/bin/perl -I C:/Users/ALEX/Documents/Codigo/Automatizacion-Bus/herramientas/Archivos_temporales/Agentes_temporales/northstart_arg

package ABR::Parser_aux;
# Version=1.1
use POSIX qw(strftime);
use warnings;
use strict;

use ABR::northstart_arg;

sub new {
    my $class = shift;
    my $self;
    my $mensaje_x733;
    my %find_hash;

    %find_hash = (
        "1.3.6.1.6.3.1.1.5.3" => { trap_name => "linkDown", subroutine => "ABR::northstart_arg::_1_3_6_1_6_3_1_1_5_3" },
        "1.3.6.1.2.1.88.2.0.3" => { trap_name => "mteTriggerFalling", subroutine => "ABR::northstart_arg::_1_3_6_1_2_1_88_2_0_3" },
        "1.3.6.1.4.1.2021.251.2" => { trap_name => "ucdShutdown", subroutine => "ABR::northstart_arg::_1_3_6_1_4_1_2021_251_2" },
        "1.3.6.1.2.1.88.2.0.4" => { trap_name => "mteTriggerFailure", subroutine => "ABR::northstart_arg::_1_3_6_1_2_1_88_2_0_4" },
        "1.3.6.1.4.1.2021.251.1" => { trap_name => "ucdStart", subroutine => "ABR::northstart_arg::_1_3_6_1_4_1_2021_251_1" },
        "1.3.6.1.2.1.88.2.0.1" => { trap_name => "mteTriggerFired", subroutine => "ABR::northstart_arg::_1_3_6_1_2_1_88_2_0_1" },
        "1.3.6.1.6.3.1.1.5.4" => { trap_name => "linkUp", subroutine => "ABR::northstart_arg::_1_3_6_1_6_3_1_1_5_4" },
        "1.3.6.1.2.1.88.2.0.2" => { trap_name => "mteTriggerRising", subroutine => "ABR::northstart_arg::_1_3_6_1_2_1_88_2_0_2" },
        "1.3.6.1.6.3.1.1.5.1" => { trap_name => "coldStart", subroutine => "ABR::northstart_arg::_1_3_6_1_6_3_1_1_5_1" },
        "1.3.6.1.6.3.1.1.5.2" => { trap_name => "warmStart", subroutine => "ABR::northstart_arg::_1_3_6_1_6_3_1_1_5_2" },
        "1.3.6.1.2.1.88.2.0.5" => { trap_name => "mteEventSetFailure", subroutine => "ABR::northstart_arg::_1_3_6_1_2_1_88_2_0_5" },
        "1.3.6.1.2.1.88.1.4.3.1.1" => { trap_name => "the", subroutine => "ABR::northstart_arg::_1_3_6_1_2_1_88_1_4_3_1_1" },
        "1.3.6.1.6.3.1.1.5.5" => { trap_name => "authenticationFailure", subroutine => "ABR::northstart_arg::_1_3_6_1_6_3_1_1_5_5" },
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
