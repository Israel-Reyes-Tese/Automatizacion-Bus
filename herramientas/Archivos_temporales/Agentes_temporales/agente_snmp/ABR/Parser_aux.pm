package ABR::Parser_aux;
# Version=1.1
use POSIX qw(strftime);
use warnings;
use strict;

use ABR::agente_snmp;

sub new {
    my $class = shift;
    my $self;
    my $mensaje_x733;
    my %find_hash;

    %find_hash = (
        "1.3.6.1.4.1.193.183.4.2.0.11" => { trap_name => "eriAlarmWarnAlert", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_11" },
        "1.3.6.1.4.1.193.183.6.2.0.14" => { trap_name => "eriAlarmXCriticalAlert", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_14" },
        "1.3.6.1.4.1.193.183.4.2.0.3" => { trap_name => "eriAlarmMinor", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_3" },
        "1.3.6.1.4.1.193.183.6.2.0.15" => { trap_name => "eriAlarmXAppendAlertInfo", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_15" },
        "1.3.6.1.4.1.193.183.4.2.0.15" => { trap_name => "eriAlarmAppendAlertInfo", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_15" },
        "1.3.6.1.4.1.193.183.6.2.0.13" => { trap_name => "eriAlarmXMajorAlert", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_13" },
        "1.3.6.1.4.1.193.183.6.2.0.20" => { trap_name => "eriAlarmXHeartBeatNotif", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_20" },
        "1.3.6.1.4.1.193.183.4.2.0.12" => { trap_name => "eriAlarmMinorAlert", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_12" },
        "1.3.6.1.4.1.193.183.6.2.0.11" => { trap_name => "eriAlarmXWarnAlert", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_11" },
        "1.3.6.1.4.1.193.183.4.2.0.7" => { trap_name => "eriAlarmCleared", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_7" },
        "1.3.6.1.4.1.193.183.6.2.0.7" => { trap_name => "eriAlarmXCleared", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_7" },
        "1.3.6.1.4.1.193.183.6.2.0.10" => { trap_name => "eriAlarmXIndAlert", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_10" },
        "1.3.6.1.4.1.193.183.4.2.0.13" => { trap_name => "eriAlarmMajorAlert", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_13" },
        "1.3.6.1.4.1.193.183.4.2.0.20" => { trap_name => "eriAlarmHeartBeatNotif", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_20" },
        "1.3.6.1.4.1.193.183.6.2.0.1" => { trap_name => "eriAlarmXIndeterminate", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_1" },
        "1.3.6.1.4.1.193.183.4.2.0.2" => { trap_name => "eriAlarmWarning", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_2" },
        "1.3.6.1.4.1.193.183.4.2.0.14" => { trap_name => "eriAlarmCriticalAlert", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_14" },
        "1.3.6.1.4.1.193.183.4.2.0.5" => { trap_name => "eriAlarmCritical", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_5" },
        "1.3.6.1.4.1.193.183.6.2.0.2" => { trap_name => "eriAlarmXWarning", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_2" },
        "1.3.6.1.4.1.193.183.4.2.0.4" => { trap_name => "eriAlarmMajor", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_4" },
        "1.3.6.1.4.1.193.183.6.2.0.5" => { trap_name => "eriAlarmXCritical", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_5" },
        "1.3.6.1.4.1.193.183.6.2.0.8" => { trap_name => "eriAlarmXAppendInfo", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_8" },
        "1.3.6.1.4.1.193.183.6.2.0.3" => { trap_name => "eriAlarmXMinor", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_3" },
        "1.3.6.1.4.1.193.183.4.2.0.10" => { trap_name => "eriAlarmIndAlert", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_10" },
        "1.3.6.1.4.1.193.183.4.2.0.1" => { trap_name => "eriAlarmIndeterminate", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_1" },
        "1.3.6.1.4.1.193.183.4.2.0.8" => { trap_name => "eriAlarmAppendInfo", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_4_2_0_8" },
        "1.3.6.1.4.1.193.183.6.2.0.4" => { trap_name => "eriAlarmXMajor", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_4" },
        "1.3.6.1.4.1.193.183.6.2.0.12" => { trap_name => "eriAlarmXMinorAlert", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_193_183_6_2_0_12" },
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
    my $entrada        = %entrada_val;
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

    if (ifexists($trap_name)) {
        $func_ref = \&$trap_sub;
        $alarm_txt = $func_ref->(%entrada_val, $trap_name, $config);
        $contador += 1;

        if ($onPrints) { print "ESTA ES LA ALARMA: $alarm_txt\n"; }
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
