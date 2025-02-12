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
        "1.3.6.1.4.1.3902.4101.1.4.1.10" => { trap_name => "alarmServiceChange", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_1_4_1_10" },
        "1.3.6.1.4.1.3902.4101.1.4.1.8" => { trap_name => "alarmSeverityChange", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_1_4_1_8" },
        "1.3.6.1.4.1.3902.4101.10.2.1.1" => { trap_name => "ntsNotificationNew", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_10_2_1_1" },
        "1.3.6.1.4.1.3902.4101.4.2.1.1" => { trap_name => "heartbeatNotification", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_4_2_1_1" },
        "1.3.6.1.4.1.3902.4101.1.4.1.1" => { trap_name => "alarmNew", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_1_4_1_1" },
        "1.3.6.1.4.1.3902.4101.1.4.1.11" => { trap_name => "alarmSyncStart", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_1_4_1_11" },
        "1.3.6.1.4.1.3902.4101.1.4.1.3" => { trap_name => "alarmAckChange", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_1_4_1_3" },
        "1.3.6.1.4.1.3902.4101.1.4.1.2" => { trap_name => "alarmCleared", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_1_4_1_2" },
        "1.3.6.1.4.1.3902.4101.1.4.1.4" => { trap_name => "alarmCommentChange", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_1_4_1_4" },
        "1.3.6.1.4.1.3902.4101.1.4.1.5" => { trap_name => "alarmListRebuild", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_1_4_1_5" },
        "1.3.6.1.4.1.3902.4101.1.4.1.7" => { trap_name => "messageInfo", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_1_4_1_7" },
        "1.3.6.1.4.1.3902.4101.1.4.1.9" => { trap_name => "alarmManagedObjectInstanceNameChange", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_1_4_1_9" },
        "1.3.6.1.4.1.3902.4101.1.4.1.6" => { trap_name => "alarmSync", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_1_4_1_6" },
        "1.3.6.1.4.1.3902.4101.1.4.1.12" => { trap_name => "alarmSyncEnd", subroutine => "ABR::agente_snmp::_1_3_6_1_4_1_3902_4101_1_4_1_12" },
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
