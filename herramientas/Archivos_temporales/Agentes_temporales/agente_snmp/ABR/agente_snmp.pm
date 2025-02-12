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
        $dat_MO = "\"" . $dat_MO . "\"";
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

# alarmSyncEnd
sub _1_3_6_1_4_1_3902_4101_1_4_1_12
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "This notification is sent after send all alarmSync trap to nms.\nTrapName = alarmSyncEnd,\n";
    
    my $dat_notification_id = 1300;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.6"})) {
        $dat_additional_text .= "\nsyncUniqueId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"})) {
        $dat_additional_text .= "\nsystemDN = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"} . ",\n";
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

# heartbeatNotification
sub _1_3_6_1_4_1_3902_4101_4_2_1_1
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "If the value of csIRPHeartbeatPeriod equals 0,then  no heartbeat notification will be generated. If the value of csIRPHeartbeatPeriod is bigger than 0 ,the heartbeat notification should be issued when the inner timer of heartbeat has reached ,and the timer  would be resetted.\nTrapName = heartbeatNotification,\n";
    
    my $dat_notification_id = 1301;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.4.1.2"})) {
        $dat_additional_text .= "\ncsIRPHeartbeatPeriod = " . $entrada->{"1.3.6.1.4.1.3902.4101.4.1.2"} . ",\n";
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

# alarmListRebuild
sub _1_3_6_1_4_1_3902_4101_1_4_1_5
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "This notification is sent when ems re-establish the connection to nms.\nTrapName = alarmListRebuild,\n";
    
    my $dat_notification_id = 1302;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"})) {
        $dat_additional_text .= "\nsystemDN = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"} . ",\n";
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

# alarmCommentChange
sub _1_3_6_1_4_1_3902_4101_1_4_1_4
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "This notification is sent when alarm's content of comment was changed.\nTrapName = alarmCommentChange,\n";
    
    my $dat_notification_id = 1303;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"})) {
        $dat_additional_text .= "\ncleiCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstanceName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"})) {
        $dat_additional_text .= "\nalarmAdditionalText = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"})) {
        $dat_additional_text .= "\nalarmSystemType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"})) {
        $dat_additional_text .= "\nalarmMocObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"})) {
        $dat_additional_text .= "\nalarmIndex = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"})) {
        $dat_additional_text .= "\nalarmCodeName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"})) {
        $dat_additional_text .= "\nsendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"})) {
        $dat_additional_text .= "\nid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"})) {
        $dat_additional_text .= "\nalarmEventTime = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"})) {
        $dat_additional_text .= "\nalarmEventType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"})) {
        $dat_additional_text .= "\nalarmProbableCause = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"})) {
        $dat_additional_text .= "\ntimeZoneID = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"})) {
        $dat_additional_text .= "\naid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"})) {
        $dat_additional_text .= "\nalarmAck = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"})) {
        $dat_additional_text .= "\nalarmPerceivedSeverity = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"})) {
        $dat_additional_text .= "\nalarmId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"})) {
        $dat_additional_text .= "\nsystemDN = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"})) {
        $dat_additional_text .= "\nalarmCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"})) {
        $dat_additional_text .= "\nalarmComment = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"})) {
        $dat_additional_text .= "\nlastSendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"})) {
        $dat_additional_text .= "\nalarmSpecificProblem = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"})) {
        $dat_additional_text .= "\ntimeZoneOffset = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"})) {
        $dat_additional_text .= "\nalarmOtherInfo = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"})) {
        $dat_additional_text .= "\nalarmNeIP = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"})) {
        $dat_additional_text .= "\ndSTSaving = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"})) {
        $dat_additional_text .= "\nalarmNetype = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"} . ",\n";
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

# messageInfo
sub _1_3_6_1_4_1_3902_4101_1_4_1_7
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "This notification is sent when ems on an abnormal situation.\nTrapName = messageInfo,\n";
    
    my $dat_notification_id = 1304;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.5"})) {
        $dat_additional_text .= "\nmessageCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"})) {
        $dat_additional_text .= "\nsystemDN = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"} . ",\n";
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

# alarmServiceChange
sub _1_3_6_1_4_1_3902_4101_1_4_1_10
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "This notification is sent when alarm's path was changed.\nTrapName = alarmServiceChange,\n";
    
    my $dat_notification_id = 1305;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"})) {
        $dat_additional_text .= "\nalarmCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"})) {
        $dat_additional_text .= "\nalarmComment = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"})) {
        $dat_additional_text .= "\nalarmSpecificProblem = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"})) {
        $dat_additional_text .= "\nlastSendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"})) {
        $dat_additional_text .= "\nalarmAck = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"})) {
        $dat_additional_text .= "\nalarmId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"})) {
        $dat_additional_text .= "\nalarmPerceivedSeverity = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"})) {
        $dat_additional_text .= "\nsystemDN = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"})) {
        $dat_additional_text .= "\ndSTSaving = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"})) {
        $dat_additional_text .= "\nalarmNetype = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"})) {
        $dat_additional_text .= "\ntimeZoneOffset = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"})) {
        $dat_additional_text .= "\nalarmOtherInfo = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"})) {
        $dat_additional_text .= "\nalarmNeIP = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"})) {
        $dat_additional_text .= "\nalarmMocObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"})) {
        $dat_additional_text .= "\nalarmIndex = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"})) {
        $dat_additional_text .= "\nalarmSystemType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"})) {
        $dat_additional_text .= "\nalarmCodeName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"})) {
        $dat_additional_text .= "\nid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"})) {
        $dat_additional_text .= "\nsendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"})) {
        $dat_additional_text .= "\ncleiCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstanceName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"})) {
        $dat_additional_text .= "\nalarmAdditionalText = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"})) {
        $dat_additional_text .= "\ntimeZoneID = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"})) {
        $dat_additional_text .= "\naid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"})) {
        $dat_additional_text .= "\nalarmEventTime = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"})) {
        $dat_additional_text .= "\nalarmProbableCause = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"})) {
        $dat_additional_text .= "\nalarmEventType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"} . ",\n";
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

# alarmAckChange
sub _1_3_6_1_4_1_3902_4101_1_4_1_3
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "This notification is sent when alarm's status was changed,acknowledged or unacknowledged.\nTrapName = alarmAckChange,\n";
    
    my $dat_notification_id = 1306;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"})) {
        $dat_additional_text .= "\nalarmEventTime = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"})) {
        $dat_additional_text .= "\nalarmEventType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"})) {
        $dat_additional_text .= "\nalarmProbableCause = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"})) {
        $dat_additional_text .= "\ntimeZoneID = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"})) {
        $dat_additional_text .= "\naid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstanceName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"})) {
        $dat_additional_text .= "\nalarmAdditionalText = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"})) {
        $dat_additional_text .= "\ncleiCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"})) {
        $dat_additional_text .= "\nalarmCodeName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"})) {
        $dat_additional_text .= "\nid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"})) {
        $dat_additional_text .= "\nsendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"})) {
        $dat_additional_text .= "\nalarmIndex = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"})) {
        $dat_additional_text .= "\nalarmMocObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"})) {
        $dat_additional_text .= "\nalarmSystemType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"})) {
        $dat_additional_text .= "\nalarmOtherInfo = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"})) {
        $dat_additional_text .= "\nalarmNeIP = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"})) {
        $dat_additional_text .= "\ntimeZoneOffset = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"})) {
        $dat_additional_text .= "\ndSTSaving = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"})) {
        $dat_additional_text .= "\nalarmNetype = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"})) {
        $dat_additional_text .= "\nalarmId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"})) {
        $dat_additional_text .= "\nalarmPerceivedSeverity = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"})) {
        $dat_additional_text .= "\nsystemDN = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"})) {
        $dat_additional_text .= "\nalarmAck = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"})) {
        $dat_additional_text .= "\nalarmSpecificProblem = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"})) {
        $dat_additional_text .= "\nlastSendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"})) {
        $dat_additional_text .= "\nalarmCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"})) {
        $dat_additional_text .= "\nalarmComment = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"} . ",\n";
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

# alarmNew
sub _1_3_6_1_4_1_3902_4101_1_4_1_1
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "This notification is sent when a new Alarm is  generated and stored in the Active Alarm Table.  Note that the notification does not include all objects for the corresponding entry in the Alarm  Table. The reason is that some environments may have  problems with large PDUs. Thus, the notification  receiver must get the missing objects from the Active Alarm Table. The value 'cleared' for the PerceivedSeverity is not allowed for an alarm notification.\nTrapName = alarmNew,\n";
    
    my $dat_notification_id = 1307;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"})) {
        $dat_additional_text .= "\ntimeZoneOffset = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"})) {
        $dat_additional_text .= "\nalarmNeIP = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"})) {
        $dat_additional_text .= "\nalarmOtherInfo = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"})) {
        $dat_additional_text .= "\ndSTSaving = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"})) {
        $dat_additional_text .= "\nalarmNetype = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"})) {
        $dat_additional_text .= "\nalarmAck = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"})) {
        $dat_additional_text .= "\nalarmPerceivedSeverity = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"})) {
        $dat_additional_text .= "\nalarmId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"})) {
        $dat_additional_text .= "\nsystemDN = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"})) {
        $dat_additional_text .= "\nalarmCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"})) {
        $dat_additional_text .= "\nalarmComment = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"})) {
        $dat_additional_text .= "\nlastSendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"})) {
        $dat_additional_text .= "\nalarmSpecificProblem = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"})) {
        $dat_additional_text .= "\nalarmEventTime = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"})) {
        $dat_additional_text .= "\nalarmProbableCause = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"})) {
        $dat_additional_text .= "\nalarmEventType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"})) {
        $dat_additional_text .= "\ntimeZoneID = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"})) {
        $dat_additional_text .= "\naid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"})) {
        $dat_additional_text .= "\ncleiCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstanceName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"})) {
        $dat_additional_text .= "\nalarmAdditionalText = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"})) {
        $dat_additional_text .= "\nalarmSystemType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"})) {
        $dat_additional_text .= "\nalarmIndex = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"})) {
        $dat_additional_text .= "\nalarmMocObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"})) {
        $dat_additional_text .= "\nalarmCodeName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"})) {
        $dat_additional_text .= "\nsendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"})) {
        $dat_additional_text .= "\nid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"} . ",\n";
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

# alarmCleared
sub _1_3_6_1_4_1_3902_4101_1_4_1_2
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "This notification is generated when an alarm is  cleared. A cleared alarm is removed from the  Active Alarm Table and is no longer accessible. It's impossible to retrieve an cleared alarm from Active Alarm Table any more.\nTrapName = alarmCleared,\n";
    
    my $dat_notification_id = 1308;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"})) {
        $dat_additional_text .= "\ndSTSaving = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"})) {
        $dat_additional_text .= "\nalarmNetype = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"})) {
        $dat_additional_text .= "\ntimeZoneOffset = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"})) {
        $dat_additional_text .= "\nalarmOtherInfo = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"})) {
        $dat_additional_text .= "\nalarmNeIP = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"})) {
        $dat_additional_text .= "\nalarmCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"})) {
        $dat_additional_text .= "\nalarmComment = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"})) {
        $dat_additional_text .= "\nlastSendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"})) {
        $dat_additional_text .= "\nalarmSpecificProblem = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"})) {
        $dat_additional_text .= "\nalarmAck = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"})) {
        $dat_additional_text .= "\nalarmPerceivedSeverity = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"})) {
        $dat_additional_text .= "\nalarmId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"})) {
        $dat_additional_text .= "\nsystemDN = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"})) {
        $dat_additional_text .= "\ntimeZoneID = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"})) {
        $dat_additional_text .= "\naid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"})) {
        $dat_additional_text .= "\nalarmEventTime = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"})) {
        $dat_additional_text .= "\nalarmEventType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"})) {
        $dat_additional_text .= "\nalarmProbableCause = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"})) {
        $dat_additional_text .= "\nalarmSystemType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"})) {
        $dat_additional_text .= "\nalarmIndex = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"})) {
        $dat_additional_text .= "\nalarmMocObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"})) {
        $dat_additional_text .= "\nalarmCodeName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"})) {
        $dat_additional_text .= "\nsendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"})) {
        $dat_additional_text .= "\nid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"})) {
        $dat_additional_text .= "\ncleiCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstanceName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"})) {
        $dat_additional_text .= "\nalarmAdditionalText = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"} . ",\n";
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

# alarmManagedObjectInstanceNameChange
sub _1_3_6_1_4_1_3902_4101_1_4_1_9
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "This notification is sent when alarm's subname1 was changed.\nTrapName = alarmManagedObjectInstanceNameChange,\n";
    
    my $dat_notification_id = 1309;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"})) {
        $dat_additional_text .= "\nalarmOtherInfo = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"})) {
        $dat_additional_text .= "\nalarmNeIP = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"})) {
        $dat_additional_text .= "\ntimeZoneOffset = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"})) {
        $dat_additional_text .= "\ndSTSaving = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"})) {
        $dat_additional_text .= "\nalarmNetype = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"})) {
        $dat_additional_text .= "\nalarmPerceivedSeverity = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"})) {
        $dat_additional_text .= "\nalarmId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"})) {
        $dat_additional_text .= "\nsystemDN = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"})) {
        $dat_additional_text .= "\nalarmAck = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"})) {
        $dat_additional_text .= "\nlastSendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"})) {
        $dat_additional_text .= "\nalarmSpecificProblem = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"})) {
        $dat_additional_text .= "\nalarmCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"})) {
        $dat_additional_text .= "\nalarmComment = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"})) {
        $dat_additional_text .= "\nalarmEventTime = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"})) {
        $dat_additional_text .= "\nalarmEventType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"})) {
        $dat_additional_text .= "\nalarmProbableCause = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"})) {
        $dat_additional_text .= "\ntimeZoneID = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"})) {
        $dat_additional_text .= "\naid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstanceName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"})) {
        $dat_additional_text .= "\nalarmAdditionalText = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"})) {
        $dat_additional_text .= "\ncleiCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"})) {
        $dat_additional_text .= "\nalarmCodeName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"})) {
        $dat_additional_text .= "\nsendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"})) {
        $dat_additional_text .= "\nid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"})) {
        $dat_additional_text .= "\nalarmSystemType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"})) {
        $dat_additional_text .= "\nalarmMocObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"})) {
        $dat_additional_text .= "\nalarmIndex = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"} . ",\n";
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

# alarmSyncStart
sub _1_3_6_1_4_1_3902_4101_1_4_1_11
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "This notification is sent before send alarmSync trap to nms.\nTrapName = alarmSyncStart,\n";
    
    my $dat_notification_id = 1310;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.6"})) {
        $dat_additional_text .= "\nsyncUniqueId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"})) {
        $dat_additional_text .= "\nsystemDN = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"} . ",\n";
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

# ntsNotificationNew
sub _1_3_6_1_4_1_3902_4101_10_2_1_1
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "This notification is sent when a new notification is generated.\nTrapName = ntsNotificationNew,\n";
    
    my $dat_notification_id = 1311;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.23"})) {
        $dat_additional_text .= "\nnotifyCustomAttr6 = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.23"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.14"})) {
        $dat_additional_text .= "\nnotifyDSTSaving = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.22"})) {
        $dat_additional_text .= "\nnotifyCustomAttr5 = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.22"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.3"})) {
        $dat_additional_text .= "\nnotifyManagedObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"})) {
        $dat_additional_text .= "\nsystemDN = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.16"})) {
        $dat_additional_text .= "\nnotifyId = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.16"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.19"})) {
        $dat_additional_text .= "\nnotifyCustomAttr2 = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.19"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.20"})) {
        $dat_additional_text .= "\nnotifyCustomAttr3 = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.20"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.25"})) {
        $dat_additional_text .= "\nnotifyCustomAttr8 = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.25"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"})) {
        $dat_additional_text .= "\nlastSendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.9"})) {
        $dat_additional_text .= "\nnotifyManagedObjectInstanceName = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.2"})) {
        $dat_additional_text .= "\nnotifyCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.1"})) {
        $dat_additional_text .= "\nnotifyEventTime = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.6"})) {
        $dat_additional_text .= "\nnotifyAdditionalText = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.21"})) {
        $dat_additional_text .= "\nnotifyCustomAttr4 = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.21"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.17"})) {
        $dat_additional_text .= "\nnotifyMocObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.17"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.15"})) {
        $dat_additional_text .= "\nnotifyAid = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.15"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.24"})) {
        $dat_additional_text .= "\nnotifyCustomAttr7 = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.24"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.7"})) {
        $dat_additional_text .= "\nnotifyNetype = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.4"})) {
        $dat_additional_text .= "\nnotifyProbableCause = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.5"})) {
        $dat_additional_text .= "\nnotifySpecificProblem = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"})) {
        $dat_additional_text .= "\nsendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.26"})) {
        $dat_additional_text .= "\nnotifyCustomAttr9 = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.26"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.18"})) {
        $dat_additional_text .= "\nnotifyCustomAttr1 = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.18"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.13"})) {
        $dat_additional_text .= "\nnotifyTimeZoneOffset = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.13"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.27"})) {
        $dat_additional_text .= "\nnotifyCustomAttr10 = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.27"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.12"})) {
        $dat_additional_text .= "\nnotifyTimeZoneID = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.11"})) {
        $dat_additional_text .= "\nnotifyNeIP = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.8"})) {
        $dat_additional_text .= "\nnotifyCodeName = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.10.1.10"})) {
        $dat_additional_text .= "\nnotifySystemType = " . $entrada->{"1.3.6.1.4.1.3902.4101.10.1.10"} . ",\n";
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

# alarmSeverityChange
sub _1_3_6_1_4_1_3902_4101_1_4_1_8
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "This notification is sent when alarm's severity was changed.\nTrapName = alarmSeverityChange,\n";
    
    my $dat_notification_id = 1312;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"})) {
        $dat_additional_text .= "\naid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"})) {
        $dat_additional_text .= "\ntimeZoneID = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"})) {
        $dat_additional_text .= "\nalarmEventType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"})) {
        $dat_additional_text .= "\nalarmProbableCause = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"})) {
        $dat_additional_text .= "\nalarmEventTime = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"})) {
        $dat_additional_text .= "\nsendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"})) {
        $dat_additional_text .= "\nid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"})) {
        $dat_additional_text .= "\nalarmCodeName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"})) {
        $dat_additional_text .= "\nalarmSystemType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"})) {
        $dat_additional_text .= "\nalarmIndex = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"})) {
        $dat_additional_text .= "\nalarmMocObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"})) {
        $dat_additional_text .= "\nalarmAdditionalText = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstanceName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"})) {
        $dat_additional_text .= "\ncleiCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"})) {
        $dat_additional_text .= "\nalarmNetype = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"})) {
        $dat_additional_text .= "\ndSTSaving = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"})) {
        $dat_additional_text .= "\nalarmNeIP = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"})) {
        $dat_additional_text .= "\nalarmOtherInfo = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"})) {
        $dat_additional_text .= "\ntimeZoneOffset = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"})) {
        $dat_additional_text .= "\nlastSendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"})) {
        $dat_additional_text .= "\nalarmSpecificProblem = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"})) {
        $dat_additional_text .= "\nalarmComment = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"})) {
        $dat_additional_text .= "\nalarmCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"})) {
        $dat_additional_text .= "\nsystemDN = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"})) {
        $dat_additional_text .= "\nalarmPerceivedSeverity = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"})) {
        $dat_additional_text .= "\nalarmId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"})) {
        $dat_additional_text .= "\nalarmAck = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"} . ",\n";
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

# alarmSync
sub _1_3_6_1_4_1_3902_4101_1_4_1_6
{
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;

    my $alarm_txt;

    my $agent_address = $entrada->{"IPADDR"};
    my $dat_event_time = $llena->fecha();
    

    my $dat_severity = 2;
    my $dat_specific_problem = 0;
    my $dat_probable_cause = 0;
    my $dat_event_type = 10;
    my $dat_additional_text = "This notification is generated when set syncAlarm successfully.  The alarmManagedObjectInstance of all alarms are in line with user setting.\nTrapName = alarmSync,\n";
    
    my $dat_notification_id = 1313;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"})) {
        $dat_additional_text .= "\nalarmSystemType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.16"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"})) {
        $dat_additional_text .= "\nalarmIndex = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"})) {
        $dat_additional_text .= "\nalarmMocObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.26"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"})) {
        $dat_additional_text .= "\nsendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"})) {
        $dat_additional_text .= "\nid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.24"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"})) {
        $dat_additional_text .= "\nalarmCodeName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"})) {
        $dat_additional_text .= "\ncleiCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.19"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"})) {
        $dat_additional_text .= "\nalarmAdditionalText = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstanceName = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.15"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"})) {
        $dat_additional_text .= "\naid = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.23"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"})) {
        $dat_additional_text .= "\ntimeZoneID = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.20"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"})) {
        $dat_additional_text .= "\nalarmEventType = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"})) {
        $dat_additional_text .= "\nalarmProbableCause = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"})) {
        $dat_additional_text .= "\nalarmEventTime = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"})) {
        $dat_additional_text .= "\nalarmComment = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"})) {
        $dat_additional_text .= "\nalarmCode = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"})) {
        $dat_additional_text .= "\nlastSendNotificationId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"})) {
        $dat_additional_text .= "\nalarmSpecificProblem = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"})) {
        $dat_additional_text .= "\nalarmAck = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.18"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"})) {
        $dat_additional_text .= "\nalarmManagedObjectInstance = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"})) {
        $dat_additional_text .= "\nsystemDN = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"})) {
        $dat_additional_text .= "\nalarmPerceivedSeverity = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"})) {
        $dat_additional_text .= "\nalarmId = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"})) {
        $dat_additional_text .= "\nalarmNetype = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"})) {
        $dat_additional_text .= "\ndSTSaving = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.22"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"})) {
        $dat_additional_text .= "\ntimeZoneOffset = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.21"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"})) {
        $dat_additional_text .= "\nalarmOtherInfo = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.25"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"})) {
        $dat_additional_text .= "\nalarmNeIP = " . $entrada->{"1.3.6.1.4.1.3902.4101.1.3.1.17"} . ",\n";
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
