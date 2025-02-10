#!/usr/bin/perl -I C:/Users/ALEX/Documents/Codigo/Automatizacion-Bus/herramientas/Archivos_temporales/Agentes_temporales/aaems_car

package ABR::Parser_aux;
# Version=1.1
use POSIX qw(strftime);
use warnings;
use strict;

use ABR::aaems_car;

sub new {
    my $class = shift;
    my $self;
    my $mensaje_x733;
    my %find_hash;

    %find_hash = (
        "1.3.6.1.4.1.20858.10.104.101.2.2.37" => { trap_name => "ipsecTunnelIkeSaExpiry", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_37" },
        "1.3.6.1.4.1.20858.10.104.101.2.3" => { trap_name => "casaHeMSSmallCellGWAlarm", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_3" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.14" => { trap_name => "lanError", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_14" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.16" => { trap_name => "paTemperatureUnacceptable", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_16" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.3" => { trap_name => "kpiAgentNotDetected", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_3" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.15" => { trap_name => "remoteAeMSsStatusAlarm", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_15" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.47" => { trap_name => "criticalConfigurationFailure", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_47" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.13" => { trap_name => "sctpFailure", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_13" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.28" => { trap_name => "clockSynchronizationProblem", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_28" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.32" => { trap_name => "failedBackingUpConfigurationFile", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_32" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.39" => { trap_name => "holdoverPeriodExpiration", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_39" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.35" => { trap_name => "ipsecTunnelIsDown", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_35" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.17" => { trap_name => "unauthorisedAccessAttempt", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_17" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.13" => { trap_name => "cellOnAlarm", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_13" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.12" => { trap_name => "cellOffAlarm", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_12" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.8" => { trap_name => "deviceOfflineAlarm", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_8" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.27" => { trap_name => "dspOrPhyCrash", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_27" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.2" => { trap_name => "cpuUsageIsHigh", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_2" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.6" => { trap_name => "congestion", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_6" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.11" => { trap_name => "gpsSynchronizationLost", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_11" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.20" => { trap_name => "thresholdCrossedRLF", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_20" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.48" => { trap_name => "oOAMProxyRestarted", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_48" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.10" => { trap_name => "radioOffAlarm", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_10" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.41" => { trap_name => "forcedReboot", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_41" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.36" => { trap_name => "ipsecTunnelExpiry", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_36" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.14" => { trap_name => "dbReplicationAlarm", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_14" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.9" => { trap_name => "deviceOnlineAlarm", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_9" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.5" => { trap_name => "mmeConnectionIsDown", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_5" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.26" => { trap_name => "l1StartTimeout", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_26" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.4" => { trap_name => "flashMemoryUsage", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_4" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.5" => { trap_name => "dbSlaveConnectionAlarm", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_5" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.33" => { trap_name => "failedRestoringConfigurationFile", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_33" },
        "1.3.6.1.4.1.20858.10.104.101.2.4" => { trap_name => "casaHeMSHeartBeatMsg", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_4" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.30" => { trap_name => "invalidPhyOrRfConfiguration", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_30" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.31" => { trap_name => "systemInformationConfigurationFailure", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_31" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.45" => { trap_name => "tr069NotDetected", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_45" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.10" => { trap_name => "overTheAirSynchronizationLost", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_10" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.8" => { trap_name => "cpuCyclesLimitExceeded", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_8" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.40" => { trap_name => "administrativeReboot", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_40" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.29" => { trap_name => "synchronizationLostWithAllSources", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_29" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.23" => { trap_name => "pciCollision", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_23" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.38" => { trap_name => "operatorCertificateExpired", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_38" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.6" => { trap_name => "dbArbiterConnectionAlarm", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_6" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.2" => { trap_name => "l2NotDetected", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_2" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.7" => { trap_name => "errorAccessingFile", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_7" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.1" => { trap_name => "memoryUsageIsHigh", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_1" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.19" => { trap_name => "outOfMemory", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_19" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.49" => { trap_name => "cCMSServerConnectionFailure", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_49" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.1" => { trap_name => "l3NotDetected", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_1" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.15" => { trap_name => "cpuTemperatureUnacceptable", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_15" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.44" => { trap_name => "dnsResolutionFailure", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_44" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.50" => { trap_name => "aAeMSConnectionNoResponse", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_50" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.34" => { trap_name => "singleMmeConnectionIsDown", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_34" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.24" => { trap_name => "pciConfusion", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_24" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.18" => { trap_name => "configurationOrCustomizingErrror", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_18" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.12" => { trap_name => "cellSynchronizationFailure", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_12" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.21" => { trap_name => "thresholdCrossedLowSINR", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_21" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.25" => { trap_name => "killSwitch", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_25" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.3" => { trap_name => "hardDiskUsageIsHigh", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_3" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.11" => { trap_name => "radioOnAlarm", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_11" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.43" => { trap_name => "rebootLoop", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_43" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.7" => { trap_name => "networkInterfaceAlarm", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_7" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.46" => { trap_name => "watchdogNotDetected", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_46" },
        "1.3.6.1.4.1.20858.10.104.101.2.1.4" => { trap_name => "haCommunicationAlarm", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_1_4" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.9" => { trap_name => "reTransmissionRateExcessive", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_9" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.42" => { trap_name => "maxMMEAttemptsExceeded", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_42" },
        "1.3.6.1.4.1.20858.10.104.101.2.2.22" => { trap_name => "paBiasingFailure", subroutine => "ABR::aaems_car::_1_3_6_1_4_1_20858_10_104_101_2_2_22" },
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
