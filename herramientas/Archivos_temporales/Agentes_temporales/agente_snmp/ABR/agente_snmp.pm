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

# eriAlarmXAppendInfo
sub _1_3_6_1_4_1_193_183_6_2_0_8 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1300;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmXActiveYangNodeInstance = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmXActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.14"})) {
        $dat_additional_text .= "\neriAlarmXActiveResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.7"})) {
        $dat_additional_text .= "\neriAlarmXNObjAppendedAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmXActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmMinor
sub _1_3_6_1_4_1_193_183_4_2_0_3 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1301;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmActiveEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmActiveSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmActiveManagedObject = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.9"})) {
        $dat_additional_text .= "\neriAlarmActiveProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"})) {
        $dat_additional_text .= "\neriAlarmActiveLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmActiveEventType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.6"})) {
        $dat_additional_text .= "\neriAlarmNObjRecordType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmWarnAlert
sub _1_3_6_1_4_1_193_183_4_2_0_11 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1302;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.8"})) {
        $dat_additional_text .= "\neriAlarmAlertProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmAlertEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmAlertEventType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmAlertMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmAlertSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.3"})) {
        $dat_additional_text .= "\neriAlarmAlertLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmAlertManagedObject = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmAlertMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.3"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmXWarnAlert
sub _1_3_6_1_4_1_193_183_6_2_0_11 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1303;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmXAlertSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmXAlertEventType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.8"})) {
        $dat_additional_text .= "\neriAlarmXAlertProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmXAlertYangNodeInstance = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmXAlertMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmXAlertEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.3"})) {
        $dat_additional_text .= "\neriAlarmXAlertLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmXNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmXAlertMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmIndeterminate
sub _1_3_6_1_4_1_193_183_4_2_0_1 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1304;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmActiveEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmActiveSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmActiveManagedObject = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.9"})) {
        $dat_additional_text .= "\neriAlarmActiveProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"})) {
        $dat_additional_text .= "\neriAlarmActiveLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmActiveEventType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.6"})) {
        $dat_additional_text .= "\neriAlarmNObjRecordType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmMinorAlert
sub _1_3_6_1_4_1_193_183_4_2_0_12 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1305;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.8"})) {
        $dat_additional_text .= "\neriAlarmAlertProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmAlertEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmAlertEventType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmAlertMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmAlertSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.3"})) {
        $dat_additional_text .= "\neriAlarmAlertLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmAlertManagedObject = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmAlertMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.3"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmWarning
sub _1_3_6_1_4_1_193_183_4_2_0_2 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1306;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.6"})) {
        $dat_additional_text .= "\neriAlarmNObjRecordType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.9"})) {
        $dat_additional_text .= "\neriAlarmActiveProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"})) {
        $dat_additional_text .= "\neriAlarmActiveLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmActiveEventType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmActiveSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmActiveEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmActiveManagedObject = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmXWarning
sub _1_3_6_1_4_1_193_183_6_2_0_2 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1307;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmXActiveSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmXActiveYangNodeInstance = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.3"})) {
        $dat_additional_text .= "\neriAlarmXActiveLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmXNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmXActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmXActiveEventType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.9"})) {
        $dat_additional_text .= "\neriAlarmXActiveProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmXActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmXActiveEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.6"})) {
        $dat_additional_text .= "\neriAlarmXNObjRecordType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.6"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmXMinorAlert
sub _1_3_6_1_4_1_193_183_6_2_0_12 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1308;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.3"})) {
        $dat_additional_text .= "\neriAlarmXAlertLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmXNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmXAlertMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmXAlertSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmXAlertEventType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.8"})) {
        $dat_additional_text .= "\neriAlarmXAlertProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmXAlertEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmXAlertMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmXAlertYangNodeInstance = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.5"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmXIndAlert
sub _1_3_6_1_4_1_193_183_6_2_0_10 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1309;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmXAlertMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmXNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.3"})) {
        $dat_additional_text .= "\neriAlarmXAlertLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmXAlertMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmXAlertYangNodeInstance = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmXAlertEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.8"})) {
        $dat_additional_text .= "\neriAlarmXAlertProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmXAlertSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmXAlertEventType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.6"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmXCritical
sub _1_3_6_1_4_1_193_183_6_2_0_5 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1310;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmXActiveEventType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.9"})) {
        $dat_additional_text .= "\neriAlarmXActiveProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmXActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.6"})) {
        $dat_additional_text .= "\neriAlarmXNObjRecordType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmXActiveEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmXActiveSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmXActiveYangNodeInstance = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.3"})) {
        $dat_additional_text .= "\neriAlarmXActiveLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmXNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmXActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmXHeartBeatNotif
sub _1_3_6_1_4_1_193_183_6_2_0_20 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1311;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.4"})) {
        $dat_additional_text .= "\neriAlarmXActiveTableURL = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmXMinor
sub _1_3_6_1_4_1_193_183_6_2_0_3 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1312;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmXActiveYangNodeInstance = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmXActiveSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.3"})) {
        $dat_additional_text .= "\neriAlarmXActiveLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmXNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmXActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmXActiveEventType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmXActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.9"})) {
        $dat_additional_text .= "\neriAlarmXActiveProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.6"})) {
        $dat_additional_text .= "\neriAlarmXNObjRecordType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmXActiveEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.7"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmHeartBeatNotif
sub _1_3_6_1_4_1_193_183_4_2_0_20 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1313;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"})) {
        $dat_additional_text .= "\neriAlarmActiveLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.2"})) {
        $dat_additional_text .= "\neriAlarmAlertLastChanged = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.2"})) {
        $dat_additional_text .= "\neriAlarmActiveLastChanged = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.3"})) {
        $dat_additional_text .= "\neriAlarmAlertLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.3"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmCleared
sub _1_3_6_1_4_1_193_183_4_2_0_7 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1314;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmActiveEventType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.9"})) {
        $dat_additional_text .= "\neriAlarmActiveProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"})) {
        $dat_additional_text .= "\neriAlarmActiveLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmActiveManagedObject = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmActiveEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmActiveSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.4"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmXCleared
sub _1_3_6_1_4_1_193_183_6_2_0_7 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1315;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmXActiveYangNodeInstance = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmXActiveSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmXNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmXActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.3"})) {
        $dat_additional_text .= "\neriAlarmXActiveLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmXActiveEventType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmXActiveEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.9"})) {
        $dat_additional_text .= "\neriAlarmXActiveProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmXActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmAppendInfo
sub _1_3_6_1_4_1_193_183_4_2_0_8 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1316;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.14"})) {
        $dat_additional_text .= "\neriAlarmActiveResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmActiveManagedObject = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.7"})) {
        $dat_additional_text .= "\neriAlarmNObjAppendedAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmXAppendAlertInfo
sub _1_3_6_1_4_1_193_183_6_2_0_15 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1317;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.11"})) {
        $dat_additional_text .= "\neriAlarmXAlertResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmXAlertYangNodeInstance = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmXAlertMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.7"})) {
        $dat_additional_text .= "\neriAlarmXNObjAppendedAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmXAlertMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.2"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmCritical
sub _1_3_6_1_4_1_193_183_4_2_0_5 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1318;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmActiveManagedObject = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmActiveSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmActiveEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmActiveEventType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.9"})) {
        $dat_additional_text .= "\neriAlarmActiveProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"})) {
        $dat_additional_text .= "\neriAlarmActiveLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.6"})) {
        $dat_additional_text .= "\neriAlarmNObjRecordType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmMajor
sub _1_3_6_1_4_1_193_183_4_2_0_4 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1319;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.6"})) {
        $dat_additional_text .= "\neriAlarmNObjRecordType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmActiveManagedObject = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmActiveEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmActiveSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmActiveEventType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.9"})) {
        $dat_additional_text .= "\neriAlarmActiveProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.5.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"})) {
        $dat_additional_text .= "\neriAlarmActiveLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.3.3"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmCriticalAlert
sub _1_3_6_1_4_1_193_183_4_2_0_14 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1320;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmAlertEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.8"})) {
        $dat_additional_text .= "\neriAlarmAlertProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmAlertSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmAlertMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmAlertEventType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmAlertMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmAlertManagedObject = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.3"})) {
        $dat_additional_text .= "\neriAlarmAlertLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.3"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmMajorAlert
sub _1_3_6_1_4_1_193_183_4_2_0_13 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1321;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmAlertSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmAlertMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmAlertEventType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmAlertMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmAlertManagedObject = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.3"})) {
        $dat_additional_text .= "\neriAlarmAlertLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmAlertEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.8"})) {
        $dat_additional_text .= "\neriAlarmAlertProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmAppendAlertInfo
sub _1_3_6_1_4_1_193_183_4_2_0_15 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1322;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmAlertManagedObject = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmAlertMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.7"})) {
        $dat_additional_text .= "\neriAlarmNObjAppendedAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmAlertMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.11"})) {
        $dat_additional_text .= "\neriAlarmAlertResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.11"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmXCriticalAlert
sub _1_3_6_1_4_1_193_183_6_2_0_14 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1323;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.8"})) {
        $dat_additional_text .= "\neriAlarmXAlertProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmXAlertSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmXAlertEventType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmXAlertEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmXAlertYangNodeInstance = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmXAlertMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmXNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.3"})) {
        $dat_additional_text .= "\neriAlarmXAlertLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmXAlertMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmXMajor
sub _1_3_6_1_4_1_193_183_6_2_0_4 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1324;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmXActiveSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmXActiveYangNodeInstance = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.3"})) {
        $dat_additional_text .= "\neriAlarmXActiveLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmXNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmXActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmXActiveEventType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.9"})) {
        $dat_additional_text .= "\neriAlarmXActiveProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmXActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmXActiveEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.6"})) {
        $dat_additional_text .= "\neriAlarmXNObjRecordType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.6"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmXIndeterminate
sub _1_3_6_1_4_1_193_183_6_2_0_1 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1325;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmXActiveMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmXNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.3"})) {
        $dat_additional_text .= "\neriAlarmXActiveLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmXActiveSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmXActiveYangNodeInstance = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmXActiveEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.6"})) {
        $dat_additional_text .= "\neriAlarmXNObjRecordType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.9"})) {
        $dat_additional_text .= "\neriAlarmXActiveProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmXActiveMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmXActiveEventType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.3.5.1.6"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmXMajorAlert
sub _1_3_6_1_4_1_193_183_6_2_0_13 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1326;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmXNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.3"})) {
        $dat_additional_text .= "\neriAlarmXAlertLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmXAlertMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmXNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmXNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifier = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.8"})) {
        $dat_additional_text .= "\neriAlarmXAlertProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"})) {
        $dat_additional_text .= "\neriAlarmXNObjSourceIdentifierType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.2.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmXAlertEventType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmXAlertSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmXAlertEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmXAlertMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmXAlertYangNodeInstance = " . $entrada->{"1.3.6.1.4.1.193.183.6.1.4.5.1.5"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
# eriAlarmIndAlert
sub _1_3_6_1_4_1_193_183_4_2_0_10 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $dat_severity = ;
    my $dat_specific_problem = ;
    my $dat_probable_cause = ;
    my $dat_event_type = ;
    my $dat_managed_object = ;
    my $dat_additional_text = "";
    
    my $dat_notification_id = 1327;
    my $dat_correlated_notification_id = "";

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.6"})) {
        $dat_additional_text .= "\neriAlarmAlertEventType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.2"})) {
        $dat_additional_text .= "\neriAlarmAlertMajorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.4"})) {
        $dat_additional_text .= "\neriAlarmAlertSpecificProblem = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.3"})) {
        $dat_additional_text .= "\neriAlarmAlertLastSequenceNo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.5"})) {
        $dat_additional_text .= "\neriAlarmAlertManagedObject = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.3"})) {
        $dat_additional_text .= "\neriAlarmAlertMinorType = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalText = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"})) {
        $dat_additional_text .= "\neriAlarmNObjAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"})) {
        $dat_additional_text .= "\neriAlarmNObjResourceId = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"})) {
        $dat_additional_text .= "\neriAlarmNObjMoreAdditionalInfo = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.8"})) {
        $dat_additional_text .= "\neriAlarmAlertProbableCause = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.7"})) {
        $dat_additional_text .= "\neriAlarmAlertEventTime = " . $entrada->{"1.3.6.1.4.1.193.183.4.1.4.5.1.7"} . ",\n";
    }
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    $llena->llenaMO("MO:" . $dat_managed_object) if (ifexists($dat_managed_object));
    $llena->llenaPC("PC:" . $dat_probable_cause) if (ifexists($dat_probable_cause));
    $llena->llenaSP("SP:" . $dat_specific_problem) if (ifexists($dat_specific_problem));
    $llena->llenaPS("PS:" . $dat_severity) if (ifexists($dat_severity));
    $llena->llenaNI("NID:" . $dat_notification_id) if (ifexists($dat_notification_id));
    $llena->llenaAT("AddTxt:" . $dat_additional_text) if (ifexists($dat_additional_text));
    $llena->EventTime("ETime:" . $dat_event_time) if (ifexists($dat_event_time));
    $llena->EventType("EType:" . $dat_event_type) if (ifexists($dat_event_type));

    $alarm_txt = ${ $llena->{mensaje_x733} };
    $llena->vacia_mensaje_x733();
    $alarm_txt = "###START###" . $alarm_txt . "###END###";

    return $alarm_txt;
}

1;
