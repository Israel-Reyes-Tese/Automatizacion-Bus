package ABR::agente_snmp;

use warnings;
use strict;
use Digest::MurmurHash qw(murmur_hash);
use ABR::llenaComun;
my $llena = ABR::llenaComun->new();
use ABR::CorrectiveFilter;
my $cf = ABR::CorrectiveFilter->new(split_filter1 => '\<&&\>', split_filter2 => '\<\>');

my $dat_MO;

sub ifexists {
    my $variable = shift;
    return defined $variable && $variable ne "";
}

sub ifExistsAndNumber {
    my $variable = shift;
    return defined $variable && $variable ne "" && $variable =~ /^[-+]?[0-9]*\.?[0-9]+$/;
}

sub HostRegex {
    my ($configHost_ref, $ip_address) = @_;
    my $salida = "";
    if (ifexists($configHost_ref)) {
        foreach my $k ($configHost_ref->keys) {
            if ($ip_address =~ /\$k/) {
                $salida = $configHost_ref->get($k);
            }
        }
    }
    return $salida;
}

sub get_managed_object {
    my ($hostname, $agent_address, $dat_managed_object) = @_;
    my $dat_MO = "";
    if (ifexists($hostname)) {
        if (ifexists($dat_managed_object)) {
            $dat_MO = $hostname . " " . $dat_managed_object;
        } else {
            $dat_MO = $hostname;
        }
    } elsif (ifexists($dat_managed_object)) {
        $dat_MO = "HostND " . $agent_address . " " . $dat_managed_object;
    } else {
        $dat_MO = "HostND " . $agent_address;
    }
    if (ifexists($dat_MO)) {
        $dat_MO =~ s/"//g;
        $dat_MO = "\" . $dat_MO . "\"";
    }
    return $dat_MO;
}

sub FuncAdditionalInfo {
    my ($entrada, $tp_name) = @_;
    my $add_info = " | AddInfo: trap name=" . $tp_name . ", ";
    foreach my $k (keys %$entrada) {
        unless ($k =~ /^(IPADDR|EOID|SPEC_TRAP|GEN_TRAP|1.3.6.1.2.1.1.3|1.3.6.1.6.3.1.1.4.1)$/) {
            if (ifexists($entrada->{$k})) {
                $add_info .= " " . $k . ": " . $entrada->{$k} . ";";
            }
        }
    }
    return $add_info;
}

sub CorrectiveFilter {
    my ($hashAlarm_ref, $config_ref, $action, $var, $c) = @_;
    my $output = $cf->ProcessingCF($hashAlarm_ref, $config_ref, $action, $c);
    if (ifexists($output)) {
        return $output;
    } elsif ($var =~ "MO") {
        return $hashAlarm_ref->{"MO"};
    } elsif ($var =~ "AddTxt") {
        return $hashAlarm_ref->{"AddTxt"};
    } elsif ($var =~ "PS") {
        return $hashAlarm_ref->{"PS"};
    }
}

sub trapSeverity {
    my $vSeverity = shift;
    my $severity = "";
    if ($vSeverity eq "5") { $severity = "Clear"; }
    if ($vSeverity eq "4") { $severity = "Critical"; }
    if ($vSeverity eq "3") { $severity = "Major"; }
    if ($vSeverity eq "1") { $severity = "Warning"; }
    if ($vSeverity eq "0") { $severity = "Clear"; }
    if ($vSeverity eq "2") { $severity = "Minor"; }
    if ($vSeverity eq "6") { $severity = "0"; }
    return $severity;
}

# eriAlarmAppendAlertInfo
sub _1_3_6_1_4_1_193_183_4_2_0_15 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmMinor
sub _1_3_6_1_4_1_193_183_4_2_0_3 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmAppendInfo
sub _1_3_6_1_4_1_193_183_4_2_0_8 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXWarning
sub _1_3_6_1_4_1_193_183_6_2_0_2 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmMinorAlert
sub _1_3_6_1_4_1_193_183_4_2_0_12 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXCleared
sub _1_3_6_1_4_1_193_183_6_2_0_7 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmCleared
sub _1_3_6_1_4_1_193_183_4_2_0_7 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmIndAlert
sub _1_3_6_1_4_1_193_183_4_2_0_10 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmMajorAlert
sub _1_3_6_1_4_1_193_183_4_2_0_13 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXCriticalAlert
sub _1_3_6_1_4_1_193_183_6_2_0_14 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmIndeterminate
sub _1_3_6_1_4_1_193_183_4_2_0_1 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXHeartBeatNotif
sub _1_3_6_1_4_1_193_183_6_2_0_20 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmWarning
sub _1_3_6_1_4_1_193_183_4_2_0_2 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmCriticalAlert
sub _1_3_6_1_4_1_193_183_4_2_0_14 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmMajor
sub _1_3_6_1_4_1_193_183_4_2_0_4 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXIndAlert
sub _1_3_6_1_4_1_193_183_6_2_0_10 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmCritical
sub _1_3_6_1_4_1_193_183_4_2_0_5 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXMajorAlert
sub _1_3_6_1_4_1_193_183_6_2_0_13 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXMajor
sub _1_3_6_1_4_1_193_183_6_2_0_4 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXAppendInfo
sub _1_3_6_1_4_1_193_183_6_2_0_8 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmHeartBeatNotif
sub _1_3_6_1_4_1_193_183_4_2_0_20 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXIndeterminate
sub _1_3_6_1_4_1_193_183_6_2_0_1 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXMinor
sub _1_3_6_1_4_1_193_183_6_2_0_3 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXCritical
sub _1_3_6_1_4_1_193_183_6_2_0_5 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXWarnAlert
sub _1_3_6_1_4_1_193_183_6_2_0_11 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXAppendAlertInfo
sub _1_3_6_1_4_1_193_183_6_2_0_15 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmWarnAlert
sub _1_3_6_1_4_1_193_183_4_2_0_11 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmXMinorAlert
sub _1_3_6_1_4_1_193_183_6_2_0_12 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;
    my $dat_specific_problem = "";
    my $dat_severity = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_managed_object;
    my $dat_additional_text;
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

