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

# sonusDSICommFtpLoginErrNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_37
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
    my $dat_additional_text = "The DSI has experienced a Transporter Ftp Login Error. Cleared  when login error is resolved.\nTrapName = sonusDSICommFtpLoginErrNotification,\n";
    
    my $dat_notification_id = 1300;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDSINodeConnectedNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_46
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
    my $dat_additional_text = "The DSI had a node disconnected (with remote node name). Automatically clears when node connects .\nTrapName = sonusDSINodeConnectedNotification,\n";
    
    my $dat_notification_id = 1301;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDsiTransporterIOWriteErrorNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_8
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterIOWriteErrorNotification,\n";
    
    my $dat_notification_id = 1302;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
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

# sonusDSIDiskReadStatusNotificatin
sub _1_3_6_1_4_1_2879_2_1_9_2_0_16
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
    my $dat_additional_text = " \nTrapName = sonusDSIDiskReadStatusNotificatin,\n";
    
    my $dat_notification_id = 1303;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.3"})) {
        $dat_additional_text .= "\nsonusDSIhrStorageReadFailures = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.25.2.3.1.1"})) {
        $dat_additional_text .= "\nhrStorageIndex = " . $entrada->{"1.3.6.1.2.1.25.2.3.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDSINodeDisconnectedNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_45
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
    my $dat_additional_text = "The DSI had a node disconnected (with remote node name). Automatically clears with sonusDSINodeConnectedNotification .\nTrapName = sonusDSINodeDisconnectedNotification,\n";
    
    my $dat_notification_id = 1304;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDSINoOutputActivityNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_54
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
    my $dat_additional_text = "The DSI has not output activity in \%s since \%s Operator clears when  neccesary.\nTrapName = sonusDSINoOutputActivityNotification,\n";
    
    my $dat_notification_id = 1305;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDsiTransporterIOOpenErrorNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_6
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterIOOpenErrorNotification,\n";
    
    my $dat_notification_id = 1306;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
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

# sonusDsiTransporterFtpDownNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_3
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterFtpDownNotification,\n";
    
    my $dat_notification_id = 1307;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
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

# sonusDSIDDIProtocolGenericStatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_14
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
    my $dat_additional_text = "This trap is a warning to indicate that the DSI has detected an  FTP protocol error during an AMA file pull session. Value of SonusDSIAlarmStatus indecates whether it is to set or clear.\nTrapName = sonusDSIDDIProtocolGenericStatusNotification,\n";
    
    my $dat_notification_id = 1308;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDSIFilePullStatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_9
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
    my $dat_additional_text = "This trap is a warning to indicate that the DM of the DSI has  failed to transfer an AMA file to the DM. Value of SonusDSIAlarmStatus indecates whether it is to set or clear.\nTrapName = sonusDSIFilePullStatusNotification,\n";
    
    my $dat_notification_id = 1309;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDsiFileServicesFileSourceFailNotificationV6
sub _1_3_6_1_4_1_2879_2_1_9_2_0_98
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
    my $dat_additional_text = "FileServices cannot correctly handle a single source and/or source's files. The source is identified by sonusDSIFileSourceInetAddress.\nTrapName = sonusDsiFileServicesFileSourceFailNotificationV6,\n";
    
    my $dat_notification_id = 1310;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.9"})) {
        $dat_additional_text .= "\nsonusDSIFileSourceAddressType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.33"})) {
        $dat_additional_text .= "\nsonusDSIFileSourceInetAddress = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.33"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDsiMasterSwitchoverNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_73
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
    my $dat_additional_text = "Switchover to <newMaster>\nTrapName = sonusDsiMasterSwitchoverNotification,\n";
    
    my $dat_notification_id = 1311;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.14"})) {
        $dat_additional_text .= "\nsonusDSINewMaster = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDsiBECommDownNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_61
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
    my $dat_additional_text = "The Backend Stream Server is shut down.\nTrapName = sonusDsiBECommDownNotification,\n";
    
    my $dat_notification_id = 1312;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDsiBEAmaClosingNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_74
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
    my $dat_additional_text = "AMA file closing for (\%1\$s) status (\%2\$s)\nTrapName = sonusDsiBEAmaClosingNotification,\n";
    
    my $dat_notification_id = 1313;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.16"})) {
        $dat_additional_text .= "\nsonusDsiBEAmaClosingStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.16"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.17"})) {
        $dat_additional_text .= "\nsonusDsiBEAmaClosingFileName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.17"} . ",\n";
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

# sonusDSIConfigChangeFailureNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_51
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
    my $dat_additional_text = "The DSI has a Configuration change failed (with which command on which node). Automatically clears when configurations are upto date.\nTrapName = sonusDSIConfigChangeFailureNotification,\n";
    
    my $dat_notification_id = 1314;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDSIPriAMAOccuThresExcededNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_2
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
    my $dat_additional_text = "This trap with SonusDSIAlarmStatus=set indicates that the DSI has  used 90 percent of the disk space assigned to it. With  SonusDSIAlarmStatus=clear it indicates that the disk no longer  90 percent full, the value of amaStoragePriOccuThres=90\%\nTrapName = sonusDSIPriAMAOccuThresExcededNotification,\n";
    
    my $dat_notification_id = 1315;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.25.3.2.1.1"})) {
        $dat_additional_text .= "\nhrDeviceIndex = " . $entrada->{"1.3.6.1.2.1.25.3.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.2.4.1.1.3"})) {
        $dat_additional_text .= "\namaStoragePriOccuThres = " . $entrada->{"1.3.6.1.4.1.148.1.7.2.4.1.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusHostMemUsageRisingThrshldNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_7
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
    my $dat_additional_text = "Reports memory usage of the host exceeds a  given threshold value.\nTrapName = sonusHostMemUsageRisingThrshldNotification,\n";
    
    my $dat_notification_id = 1316;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
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

# sonusNetMgmtClientInformReqQueueFlushedNotification
sub _1_3_6_1_4_1_2879_2_1_5_2_0_1
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
    my $dat_additional_text = "The specified number of InformRequest PDUs destined to the specified Management Client were flushed from the InformRequest PDU queue because no Response PDUs were were received from the Management Client. This situtation could occur if the Management Client cannot quickly process and respond to InformRequest PDUs that it receives, or if communications is lost with the Management Client. If this situation occurs occasionally, it is recommended to increase the InformRequest PDU timeout and/or retry values (see sonusNetMgmtClientInformReqRspTimeout and sonusNetMgmtClientInformReqRetries.) If this situation occurs repeatedly, it is an indication that communications is lost with the Management Client, either because of network problems, or because the Management Client is no longer operational. It is recommended that this device be configured to send a Trap PDU, not an InformRequest PDU, for this Notification to all Management Clients, thus bypassing a problematic InformRequest PDU queue and allowing the situation to be quickly identified and resolved.\nTrapName = sonusNetMgmtClientInformReqQueueFlushedNotification,\n";
    
    my $dat_notification_id = 1317;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.1.1.1.2.1.2"})) {
        $dat_additional_text .= "\nsonusNetMgmtClientName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.1.1.1.2.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.9"})) {
        $dat_additional_text .= "\nsonusSequenceId = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.11"})) {
        $dat_additional_text .= "\nsonusNetMgmtInformReqDiscards = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusHostCpuAvgUsageFallingThresholdNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_4
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
    my $dat_additional_text = "Report average CPU usage falls below a threshold  value.\nTrapName = sonusHostCpuAvgUsageFallingThresholdNotification,\n";
    
    my $dat_notification_id = 1318;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDSIDDIProtocolDM1StatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_10
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
    my $dat_additional_text = "This trap is a warning to indicate that the DSI has detected an FTP protocol error during an AMA file pull session. Value of  SonusDSIAlarmStatus indecates whether it is to set or clear.\nTrapName = sonusDSIDDIProtocolDM1StatusNotification,\n";
    
    my $dat_notification_id = 1319;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDsiMemHiWatermarkNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_82
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
    my $dat_additional_text = "Health Monitor detected process memory growth reached high watermark:(\%1\$s)\nTrapName = sonusDsiMemHiWatermarkNotification,\n";
    
    my $dat_notification_id = 1320;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.29"})) {
        $dat_additional_text .= "\nsonusDsiMemInfo = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.29"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusHostFsUsageFallingThresholdNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_6
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
    my $dat_additional_text = "Reports usage of a file system falls below  a predefined threshold value.\nTrapName = sonusHostFsUsageFallingThresholdNotification,\n";
    
    my $dat_notification_id = 1321;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.3"})) {
        $dat_additional_text .= "\nsonusHostFileSystemPath = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDSIFtpFailedAuthenRemoteNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_20
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
    my $dat_additional_text = "The DSI failed an FTP session authentication attempt by the DPMS. Automatically clears when the next FTP session authentication is completed successfully.\nTrapName = sonusDSIFtpFailedAuthenRemoteNotification,\n";
    
    my $dat_notification_id = 1322;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.2.5.1.6"})) {
        $dat_additional_text .= "\nsessionFtpAuthenFailRem = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.2.5.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"})) {
        $dat_additional_text .= "\nsessionCompIndex = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDSIFtpFailedAuthenNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_19
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
    my $dat_additional_text = "The DSI received a notification of FTP session authentication failure from the DPMS. Automatically clears when the next FTP session authentication is completed successfully.\nTrapName = sonusDSIFtpFailedAuthenNotification,\n";
    
    my $dat_notification_id = 1323;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.2.5.1.4"})) {
        $dat_additional_text .= "\nsessionFtpAuthenFailLoc = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.2.5.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"})) {
        $dat_additional_text .= "\nsessionCompIndex = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDSIClearIdleTimeThresholdReachedNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_93
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
    my $dat_additional_text = "Clear Health Monitor Idle time threshold crossed alarm:(\%1\$s)\nTrapName = sonusDSIClearIdleTimeThresholdReachedNotification,\n";
    
    my $dat_notification_id = 1324;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.25"})) {
        $dat_additional_text .= "\nsonusDSIClearIdleTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.25"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDSIFtpOutPriFileMissNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_21
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
    my $dat_additional_text = "The DSI detected missing primary AMA files, which should have been sent to the DPMS. Automatically clears when the next FTP session is completed successfully.\nTrapName = sonusDSIFtpOutPriFileMissNotification,\n";
    
    my $dat_notification_id = 1325;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.2.2.1.1.14"})) {
        $dat_additional_text .= "\namaOutPriFilesMiss = " . $entrada->{"1.3.6.1.4.1.148.1.7.2.2.1.1.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"})) {
        $dat_additional_text .= "\nsessionCompIndex = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"} . ",\n";
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

# sonusDsiOutOfSynchNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_77
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
    my $dat_additional_text = "M-nodes may be out of synch\nTrapName = sonusDsiOutOfSynchNotification,\n";
    
    my $dat_notification_id = 1326;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDSISequenceRestartNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_32
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
    my $dat_additional_text = "The DSI lost the AMA sequence and has restarted.  Requires a manual clear.\nTrapName = sonusDSISequenceRestartNotification,\n";
    
    my $dat_notification_id = 1327;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"})) {
        $dat_additional_text .= "\nsessionCompIndex = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDSINoOperatingLicenseNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_59
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
    my $dat_additional_text = "The system does not have a license to operate.\nTrapName = sonusDSINoOperatingLicenseNotification,\n";
    
    my $dat_notification_id = 1328;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDSINodeInServiceNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_50
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
    my $dat_additional_text = "The DSI has a node out of service (with proc name). Automatically clears when node is in-service .\nTrapName = sonusDSINodeInServiceNotification,\n";
    
    my $dat_notification_id = 1329;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDSISaiConnStatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_58
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
    my $dat_additional_text = "The DSI SAI Server has detected a change of the connection status from the Transporter client.\nTrapName = sonusDSISaiConnStatusNotification,\n";
    
    my $dat_notification_id = 1330;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.7"})) {
        $dat_additional_text .= "\nsonusDSISaiConnStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusHostCpuUsageFallingThresholdNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_2
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
    my $dat_additional_text = "Reports a CPU usage falls below a predefind  threshold value.\nTrapName = sonusHostCpuUsageFallingThresholdNotification,\n";
    
    my $dat_notification_id = 1331;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.1"})) {
        $dat_additional_text .= "\nsonusHostCpuID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
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

# sonusDsiBECommErrorNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_62
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
    my $dat_additional_text = "The Backend Stream Server has experienced a  problem when communicating with the BPA.\nTrapName = sonusDsiBECommErrorNotification,\n";
    
    my $dat_notification_id = 1332;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.8"})) {
        $dat_additional_text .= "\nsonusDSIBECommErrorReason = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDsiFileServicesSwitchoverNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_66
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
    my $dat_additional_text = "FileServices detected that a source has failed over to  the other FileServices peer process.\nTrapName = sonusDsiFileServicesSwitchoverNotification,\n";
    
    my $dat_notification_id = 1333;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDSIIdleTimeThresholdReachedNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_92
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
    my $dat_additional_text = "Health Monitor Idle time threshold crossed: (\%1\$s)\nTrapName = sonusDSIIdleTimeThresholdReachedNotification,\n";
    
    my $dat_notification_id = 1334;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.24"})) {
        $dat_additional_text .= "\nsonusDSIIdleTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.24"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDSIFileTimeErrNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_39
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
    my $dat_additional_text = "The DSI has experienced a File Time Error. Cleared  when File Time error is resolved.\nTrapName = sonusDSIFileTimeErrNotification,\n";
    
    my $dat_notification_id = 1335;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDSIDiskWriteStatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_5
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
    my $dat_additional_text = "This trap is a warning to indicate that the DSI has failed  to write to the disk. Value of SonusDSIAlarmStatus indecates whether it is to set or clear.\nTrapName = sonusDSIDiskWriteStatusNotification,\n";
    
    my $dat_notification_id = 1336;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.2"})) {
        $dat_additional_text .= "\nsonusDSIhrStorageWriteFailures = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.25.2.3.1.1"})) {
        $dat_additional_text .= "\nhrStorageIndex = " . $entrada->{"1.3.6.1.2.1.25.2.3.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
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

# sonusDSICdrFileDuplicateNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_86
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
    my $dat_additional_text = "The DSI IMDS Merger accumulates CDR records and generates CDR file in the temporary directory before moving the final CDR file to the CDR storage directory. If the CDR file with the same file name is present in the CDR storage, the alarm is raised.\nTrapName = sonusDSICdrFileDuplicateNotification,\n";
    
    my $dat_notification_id = 1337;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDSICDRSequenceStatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_8
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
    my $dat_additional_text = "This trap is a warning to indicate that the DSI has detected  a missing CDR. Value of SonusDSIAlarmStatus indecates whether it is to set or clear.\nTrapName = sonusDSICDRSequenceStatusNotification,\n";
    
    my $dat_notification_id = 1338;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDSIShutdownNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_34
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
    my $dat_additional_text = "The DSI has shutdown.  Automatically clears when DSI is   restarted.\nTrapName = sonusDSIShutdownNotification,\n";
    
    my $dat_notification_id = 1339;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"})) {
        $dat_additional_text .= "\nsessionCompIndex = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDSICDRRecordStatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_7
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
    my $dat_additional_text = "This trap is a warning to indicate that the DSI has detected a bad CDR record. Value of SonusDSIAlarmStatus indecates whether it is to set or clear.\nTrapName = sonusDSICDRRecordStatusNotification,\n";
    
    my $dat_notification_id = 1340;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDsiUnprocessedFilesNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_70
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
    my $dat_additional_text = "Unprocessed files found in miscFiles directory. File count = <count>.\nTrapName = sonusDsiUnprocessedFilesNotification,\n";
    
    my $dat_notification_id = 1341;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.13"})) {
        $dat_additional_text .= "\nsonusDSIUnprocessedFileCount = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.13"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDsiBERtTransferNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_76
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
    my $dat_additional_text = "Real-time transfer status has changed to (\%1\$s)\nTrapName = sonusDsiBERtTransferNotification,\n";
    
    my $dat_notification_id = 1342;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.20"})) {
        $dat_additional_text .= "\nsonusDsiBERtTransferStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.20"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
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

# sonusDsiUnsupportedVersionError
sub _1_3_6_1_4_1_2879_2_1_9_2_0_69
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
    my $dat_additional_text = "The file <filename> has unsupported version in the header.\nTrapName = sonusDsiUnsupportedVersionError,\n";
    
    my $dat_notification_id = 1343;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.12"})) {
        $dat_additional_text .= "\nsonusDSIVersionErrorFileName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDsiTransporterCAMFileSeqErrorNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_11
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterCAMFileSeqErrorNotification,\n";
    
    my $dat_notification_id = 1344;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDSISAIRetransmittedCDRReceivedNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_97
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
    my $dat_additional_text = "Retransmitted CDR received by SAI server from TC, Requires operator to take appropriate action.: (\%1\$s)\nTrapName = sonusDSISAIRetransmittedCDRReceivedNotification,\n";
    
    my $dat_notification_id = 1345;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.28"})) {
        $dat_additional_text .= "\nsonusDSISAIRetransmittedCDR = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.28"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDsiTransporterCAMFileSizeErrorNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_12
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterCAMFileSizeErrorNotification,\n";
    
    my $dat_notification_id = 1346;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusHostCpuAvgUsageRisingThresholdNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_3
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
    my $dat_additional_text = "Report average CPU usage exceeds a threshold  value.\nTrapName = sonusHostCpuAvgUsageRisingThresholdNotification,\n";
    
    my $dat_notification_id = 1347;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
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

# sonusDSIInterfaceDownNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_24
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
    my $dat_additional_text = "The operational status of the interface has just been changed to  down(2) by HA Monitor. Automatically clears when the interface is up again.\nTrapName = sonusDSIInterfaceDownNotification,\n";
    
    my $dat_notification_id = 1348;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.2.2.1.1"})) {
        $dat_additional_text .= "\nifIndex = " . $entrada->{"1.3.6.1.2.1.2.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.2.2.1.8"})) {
        $dat_additional_text .= "\nifOperStatus = " . $entrada->{"1.3.6.1.2.1.2.2.1.8"} . ",\n";
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

# sonusDSICDRRecordDropNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_88
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
    my $dat_additional_text = "TP Processing detected Originating TrunkType field Mismatch, dropped record to (\%1\$s) file\nTrapName = sonusDSICDRRecordDropNotification,\n";
    
    my $dat_notification_id = 1349;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.22"})) {
        $dat_additional_text .= "\nsonusDSIDropFileName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.22"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDSIFailoverEventNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_27
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
    my $dat_additional_text = "A system fail-over (from an active server to a standby server) occurred,  Must be cleared manually.\nTrapName = sonusDSIFailoverEventNotification,\n";
    
    my $dat_notification_id = 1350;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.25.3.2.1.1"})) {
        $dat_additional_text .= "\nhrDeviceIndex = " . $entrada->{"1.3.6.1.2.1.25.3.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDSIDDIProtocolDM2StatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_11
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
    my $dat_additional_text = "This trap is a warning to indicate that the DSI has detected an FTP protocol error during an AMA file pull session. Value of SonusDSIAlarmStatus indecates whether it is to set or clear.\nTrapName = sonusDSIDDIProtocolDM2StatusNotification,\n";
    
    my $dat_notification_id = 1351;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDSIClearNoInputActivityNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_53
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
    my $dat_additional_text = "The DSI has resumed input activity in \%s since \%s Clears No Input activity alarm.\nTrapName = sonusDSIClearNoInputActivityNotification,\n";
    
    my $dat_notification_id = 1352;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusHostApplMemUsageRisingThresholdNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_17
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
    my $dat_additional_text = "Reports an application instance's memory usage exceeds a given threshold value.\nTrapName = sonusHostApplMemUsageRisingThresholdNotification,\n";
    
    my $dat_notification_id = 1353;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.4"})) {
        $dat_additional_text .= "\nsonusHostProcessID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"})) {
        $dat_additional_text .= "\nsonusHostExecName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"} . ",\n";
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

# sonusDSIDBNotAccessibleNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_43
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
    my $dat_additional_text = "The DSI had a critical DB Not Accessible error.  Automatically clears when DB is accessible.\nTrapName = sonusDSIDBNotAccessibleNotification,\n";
    
    my $dat_notification_id = 1354;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDSIFileHiWatermarkNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_87
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
    my $dat_additional_text = "The DSI Health Monitor periodically checks for presence of files in the configured directory. If the number of files present is equal to or more than the configured high watermark, the alarm is raised:(\%1\$s)\nTrapName = sonusDSIFileHiWatermarkNotification,\n";
    
    my $dat_notification_id = 1355;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.32"})) {
        $dat_additional_text .= "\nsonusDsiFileInfo = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.32"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusHostApplCpuUsageRisingThresholdNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_15
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
    my $dat_additional_text = "Reports an application's instance usage exceeds  a given threhold value.\nTrapName = sonusHostApplCpuUsageRisingThresholdNotification,\n";
    
    my $dat_notification_id = 1356;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"})) {
        $dat_additional_text .= "\nsonusHostExecName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.4"})) {
        $dat_additional_text .= "\nsonusHostProcessID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDSIDisk75PercentFullNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_3
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
    my $dat_additional_text = "This trap with SonusDSIAlarmStatus=set indicates that the DSI has used 75 percent of the disk space assigned to it. with SonusDSIAlarmStatus=clear it indicates that the disk  no longer 75 percent full.\nTrapName = sonusDSIDisk75PercentFullNotification,\n";
    
    my $dat_notification_id = 1357;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDSIStorageAllocFailureNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_29
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
    my $dat_additional_text = "The DSI failed to allocate needed storage on a disk drive.  Requires a manual clear.\nTrapName = sonusDSIStorageAllocFailureNotification,\n";
    
    my $dat_notification_id = 1358;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"})) {
        $dat_additional_text .= "\nsessionCompIndex = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDSIDupRecordErrNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_40
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
    my $dat_additional_text = "The DSI has experienced a Duplicate Record Error. Cleared  when the error is resolved.\nTrapName = sonusDSIDupRecordErrNotification,\n";
    
    my $dat_notification_id = 1359;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusHostDiskMonSMARTWarnNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_23
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
    my $dat_additional_text = "SMARTmon warning was reported.  Detailed message is specified in sonusEventDescription.\nTrapName = sonusHostDiskMonSMARTWarnNotification,\n";
    
    my $dat_notification_id = 1360;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDsiTransporterIOCloseErrorNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_15
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterIOCloseErrorNotification,\n";
    
    my $dat_notification_id = 1361;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusHostFsUsageRisingThresholdNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_5
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
    my $dat_additional_text = "Reports usage of a file system exceeds a predefined threshold value.\nTrapName = sonusHostFsUsageRisingThresholdNotification,\n";
    
    my $dat_notification_id = 1362;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.3"})) {
        $dat_additional_text .= "\nsonusHostFileSystemPath = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusHostApplicationRuntimeErrorNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_11
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
    my $dat_additional_text = "Reports runtime errors occur by detecting the number of application running instances  does not match the expected number.\nTrapName = sonusHostApplicationRuntimeErrorNotification,\n";
    
    my $dat_notification_id = 1363;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"})) {
        $dat_additional_text .= "\nsonusHostExecName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.2"})) {
        $dat_additional_text .= "\nsonusHostExpectedInstanceCount = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.3"})) {
        $dat_additional_text .= "\nsonusHostSampleInstanceCount = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDsiFileToRecoveryNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_85
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
    my $dat_additional_text = "Maintainer detected a failed job, moved job file (\%1\$s) to recovery\nTrapName = sonusDsiFileToRecoveryNotification,\n";
    
    my $dat_notification_id = 1364;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.21"})) {
        $dat_additional_text .= "\nsonusDSIRecoveryFileName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.21"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDsiFileServicesFileSourceFailNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_67
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
    my $dat_additional_text = "FileServices cannot correctly handle a single source  and/or source's files. The source is identified by  sonusDSIFileSourceAddress.\nTrapName = sonusDsiFileServicesFileSourceFailNotification,\n";
    
    my $dat_notification_id = 1365;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.10"})) {
        $dat_additional_text .= "\nsonusDSIFileSourceAddress = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.9"})) {
        $dat_additional_text .= "\nsonusDSIFileSourceAddressType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
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

# sonusDSIIORemoveErrNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_42
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
    my $dat_additional_text = "The DSI has experienced an IO Error when removing the file. Cleared when error is resolved.\nTrapName = sonusDSIIORemoveErrNotification,\n";
    
    my $dat_notification_id = 1366;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDsiDBFailoverEventNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_78
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
    my $dat_additional_text = "ORACLE Failover event occuring: status in description\nTrapName = sonusDsiDBFailoverEventNotification,\n";
    
    my $dat_notification_id = 1367;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusIpCacPlusLimitClearNotification
sub _1_3_6_1_4_1_2879_2_1_5_2_0_4
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
    my $dat_additional_text = "This trap indicates that IP CAC Limit is cleared.\nTrapName = sonusIpCacPlusLimitClearNotification,\n";
    
    my $dat_notification_id = 1368;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.9"})) {
        $dat_additional_text .= "\nsonusSequenceId = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDSINodeOutOfServiceNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_49
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
    my $dat_additional_text = "The DSI has a node out of service (with proc name). Automatically clears with sonusDSINodeInServiceNotification  .\nTrapName = sonusDSINodeOutOfServiceNotification,\n";
    
    my $dat_notification_id = 1369;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDSIMismatchedOperatingLicenseNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_60
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
    my $dat_additional_text = "An attempt was made to use an unlicensed feature.\nTrapName = sonusDSIMismatchedOperatingLicenseNotification,\n";
    
    my $dat_notification_id = 1370;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDsiTransporterIORemoveErrorNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_10
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterIORemoveErrorNotification,\n";
    
    my $dat_notification_id = 1371;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDSITelnetFailedAuthenNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_28
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
    my $dat_additional_text = "The DSI received a notification of cli telnet authentication failure.  Requires a manual clear.\nTrapName = sonusDSITelnetFailedAuthenNotification,\n";
    
    my $dat_notification_id = 1372;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"})) {
        $dat_additional_text .= "\nsessionCompIndex = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
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

# sonusDSIStorageWriteFailureNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_30
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
    my $dat_additional_text = "The DSI failed to write to needed storage on a disk drive.  Requires a manual clear.\nTrapName = sonusDSIStorageWriteFailureNotification,\n";
    
    my $dat_notification_id = 1373;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"})) {
        $dat_additional_text .= "\nsessionCompIndex = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDsiClearOracleErrorNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_81
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
    my $dat_additional_text = "Clearing ORACLE error\nTrapName = sonusDsiClearOracleErrorNotification,\n";
    
    my $dat_notification_id = 1374;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusHostDiskMonTransportErrorNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_21
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
    my $dat_additional_text = "Reports that the transport error count for the disk  identified by sonusHostDiskDevName has increased by  the value of sonusHostDiskErrorCount since the   last poll.\nTrapName = sonusHostDiskMonTransportErrorNotification,\n";
    
    my $dat_notification_id = 1375;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.9"})) {
        $dat_additional_text .= "\nsonusHostDiskErrorCount = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.8"})) {
        $dat_additional_text .= "\nsonusHostDiskDevName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDSIStorageReadFailureNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_31
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
    my $dat_additional_text = "The DSI failed to read needed storage on a disk drive.  Requires a manual clear.\nTrapName = sonusDSIStorageReadFailureNotification,\n";
    
    my $dat_notification_id = 1376;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"})) {
        $dat_additional_text .= "\nsessionCompIndex = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDSIDDIProtocolDM4StatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_13
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
    my $dat_additional_text = "This trap is a warning to indicate that the DSI has detected an FTP protocol error during an AMA file pull session. Value of SonusDSIAlarmStatus indecates whether it is to set or clear.\nTrapName = sonusDSIDDIProtocolDM4StatusNotification,\n";
    
    my $dat_notification_id = 1377;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDsiBEDatTransferNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_75
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
    my $dat_additional_text = "DAT transfer request (\%1\$s) status (\%2\$s)\nTrapName = sonusDsiBEDatTransferNotification,\n";
    
    my $dat_notification_id = 1378;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.19"})) {
        $dat_additional_text .= "\nsonusDsiBEDatTransferFileName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.19"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.18"})) {
        $dat_additional_text .= "\nsonusDsiBEDatTransferStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.18"} . ",\n";
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

# sonusDSIClearNoOutputActivityNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_55
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
    my $dat_additional_text = "The DSI has resumed output activity in \%s since \%s Clear No Output activity alarm.\nTrapName = sonusDSIClearNoOutputActivityNotification,\n";
    
    my $dat_notification_id = 1379;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDSIIORenameErrNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_41
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
    my $dat_additional_text = "The DSI has experienced an IO Error when renaming the file. Cleared  when error is resolved.\nTrapName = sonusDSIIORenameErrNotification,\n";
    
    my $dat_notification_id = 1380;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDSINodeRejectedNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_48
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
    my $dat_additional_text = "The DSI rejected a node (with reason and node name). Automatically clears when node is accepted .\nTrapName = sonusDSINodeRejectedNotification,\n";
    
    my $dat_notification_id = 1381;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDsiMaintStartedNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_72
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
    my $dat_additional_text = "Maintenance started.\nTrapName = sonusDsiMaintStartedNotification,\n";
    
    my $dat_notification_id = 1382;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDsiTransporterConnDownNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_2
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterConnDownNotification,\n";
    
    my $dat_notification_id = 1383;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
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

# sonusDSIStorageStatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_25
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
    my $dat_additional_text = "HA Monitor detected a storage (disk) error occurred, Automatically clears when the storage is working without any error again.\nTrapName = sonusDSIStorageStatusNotification,\n";
    
    my $dat_notification_id = 1384;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.25.2.3.1.1"})) {
        $dat_additional_text .= "\nhrStorageIndex = " . $entrada->{"1.3.6.1.2.1.25.2.3.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
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

# sonusDSIFtpSessionFailNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_17
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
    my $dat_additional_text = "An attempt to establish FTP session failed. Automatically clears when the next FTP session is completed successfully, or when a Persistent FTP session failure alarm is issued.\nTrapName = sonusDSIFtpSessionFailNotification,\n";
    
    my $dat_notification_id = 1385;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"})) {
        $dat_additional_text .= "\nsessionCompIndex = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.2.5.1.10"})) {
        $dat_additional_text .= "\nsessionFtpSessionFail = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.2.5.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
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

# sonusDsiTransporterIORenameErrorNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_9
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterIORenameErrorNotification,\n";
    
    my $dat_notification_id = 1386;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusIpCacPlusLimitSetNotification
sub _1_3_6_1_4_1_2879_2_1_5_2_0_3
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
    my $dat_additional_text = "This trap indicates that IP CAC Limit is set.\nTrapName = sonusIpCacPlusLimitSetNotification,\n";
    
    my $dat_notification_id = 1387;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.9"})) {
        $dat_additional_text .= "\nsonusSequenceId = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDSIApplicationFailureNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_26
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
    my $dat_additional_text = "HA Monitor detected a DSI software failure, Automatically clears when the DSI software is running successfully again.\nTrapName = sonusDSIApplicationFailureNotification,\n";
    
    my $dat_notification_id = 1388;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.2.1.25.3.2.1.1"})) {
        $dat_additional_text .= "\nhrDeviceIndex = " . $entrada->{"1.3.6.1.2.1.25.3.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDSICDRFileReadStatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_6
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
    my $dat_additional_text = "This trap is a warning to indicate that the DSI has failed to  open or read a CDR file. Value of SonusDSIAlarmStatus indecates whether it is to set or clear.\nTrapName = sonusDSICDRFileReadStatusNotification,\n";
    
    my $dat_notification_id = 1389;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusHostCpuUsageRisingThresholdNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_1
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
    my $dat_additional_text = "Reports a CPU usage exceeds a predefind  threshold value.\nTrapName = sonusHostCpuUsageRisingThresholdNotification,\n";
    
    my $dat_notification_id = 1390;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.1"})) {
        $dat_additional_text .= "\nsonusHostCpuID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.1"} . ",\n";
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

# sonusDsiFileServicesProcessingFailNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_63
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
    my $dat_additional_text = "FileServices has encountered a possibly-global error  while manipulating directories or files.\nTrapName = sonusDsiFileServicesProcessingFailNotification,\n";
    
    my $dat_notification_id = 1391;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDSISaiBPAConnStatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_57
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
    my $dat_additional_text = "The DSI SAI Server has detected a change of  the connection status from the BPA.\nTrapName = sonusDSISaiBPAConnStatusNotification,\n";
    
    my $dat_notification_id = 1392;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.6"})) {
        $dat_additional_text .= "\nsonusDSIBPAConnStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDSIAppValidationFailedNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_94
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
    my $dat_additional_text = "Health Monitor App File validation failed: (\%1\$s)\nTrapName = sonusDSIAppValidationFailedNotification,\n";
    
    my $dat_notification_id = 1393;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.26"})) {
        $dat_additional_text .= "\nsonusDSIAppValidation = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.26"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDsiOracleErrorNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_80
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
    my $dat_additional_text = "ORACLE generated error code & msg in description\nTrapName = sonusDsiOracleErrorNotification,\n";
    
    my $dat_notification_id = 1394;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDSINoInputActivityNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_52
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
    my $dat_additional_text = "The DSI has a No input activity in \%s since \%s Operator clears when  neccesary.\nTrapName = sonusDSINoInputActivityNotification,\n";
    
    my $dat_notification_id = 1395;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDsiCoreHiWatermarkNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_84
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
    my $dat_additional_text = "Health Monitor detected number of core files reached high watermark:(\%1\$s)\nTrapName = sonusDsiCoreHiWatermarkNotification,\n";
    
    my $dat_notification_id = 1396;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.31"})) {
        $dat_additional_text .= "\nsonusDsiCoreInfo = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.31"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDSITestAlarmNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_15
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
    my $dat_additional_text = "This trap indicates that the DSI has received a Test Alarm command from the CLI. Value of SonusDSIAlarmStatus indecates whether it is to set or clear.\nTrapName = sonusDSITestAlarmNotification,\n";
    
    my $dat_notification_id = 1397;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDSIStrandedFileFoundNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_91
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
    my $dat_additional_text = "Health Monitor found Stranded file,duration crossed high watermark: (\%1\$s)\nTrapName = sonusDSIStrandedFileFoundNotification,\n";
    
    my $dat_notification_id = 1398;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.23"})) {
        $dat_additional_text .= "\nsonusDSIStrandedFile = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.23"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
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

# sonusDsiFileServicesSoftwareFailNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_64
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
    my $dat_additional_text = "FileServices encountered an error while processing  configuration parameters or invoking a filter.\nTrapName = sonusDsiFileServicesSoftwareFailNotification,\n";
    
    my $dat_notification_id = 1399;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusHostApplCpuUsageFallingThresholdNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_16
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
    my $dat_additional_text = "Reports an application's instance usage falling  a given threhold value.\nTrapName = sonusHostApplCpuUsageFallingThresholdNotification,\n";
    
    my $dat_notification_id = 1400;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.4"})) {
        $dat_additional_text .= "\nsonusHostProcessID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"})) {
        $dat_additional_text .= "\nsonusHostExecName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusHostApplicationStartupNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_14
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
    my $dat_additional_text = "Informs an application just starts up.\nTrapName = sonusHostApplicationStartupNotification,\n";
    
    my $dat_notification_id = 1401;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"})) {
        $dat_additional_text .= "\nsonusHostExecName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.4"})) {
        $dat_additional_text .= "\nsonusHostProcessID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDSIFileSizeErrNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_38
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
    my $dat_additional_text = "The DSI has experienced a File Size Error. Cleared  when File Size error is resolved.\nTrapName = sonusDSIFileSizeErrNotification,\n";
    
    my $dat_notification_id = 1402;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusHostApplMemUsageFallingThresholdNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_18
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
    my $dat_additional_text = "Reports an application instance's memory usage falls below a given threshold value.\nTrapName = sonusHostApplMemUsageFallingThresholdNotification,\n";
    
    my $dat_notification_id = 1403;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.4"})) {
        $dat_additional_text .= "\nsonusHostProcessID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"})) {
        $dat_additional_text .= "\nsonusHostExecName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
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

# sonusDSIDDIProtocolDM3StatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_12
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
    my $dat_additional_text = "This trap is a warning to indicate that the DSI has detected an FTP protocol error during an AMA file pull session. Value of  SonusDSIAlarmStatus indecates whether it is to set or clear.\nTrapName = sonusDSIDDIProtocolDM3StatusNotification,\n";
    
    my $dat_notification_id = 1404;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDSIDeviceStatusNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_23
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
    my $dat_additional_text = "HA Monitor detected a device error occurred. Automatically clears when the  device is working without any error again.\nTrapName = sonusDSIDeviceStatusNotification,\n";
    
    my $dat_notification_id = 1405;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.25.3.2.1.6"})) {
        $dat_additional_text .= "\nhrDeviceErrors = " . $entrada->{"1.3.6.1.2.1.25.3.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.25.3.2.1.1"})) {
        $dat_additional_text .= "\nhrDeviceIndex = " . $entrada->{"1.3.6.1.2.1.25.3.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDSIFtpPersSessionFailNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_18
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
    my $dat_additional_text = "When FTP Session Failure counter reaches the value of the sessionFtpMaxConsecRetries. Automatically clears when the next FTP session is completed successfully.\nTrapName = sonusDSIFtpPersSessionFailNotification,\n";
    
    my $dat_notification_id = 1406;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.2.5.1.18"})) {
        $dat_additional_text .= "\nsessionFtpMSessionsFail = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.2.5.1.18"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"})) {
        $dat_additional_text .= "\nsessionCompIndex = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.2.3"})) {
        $dat_additional_text .= "\nsessionFtpMaxConsecRetries = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusHostSwapUsageFallingThresholdNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_10
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
    my $dat_additional_text = "Reports the swap space usage exceeds a given  threshold.\nTrapName = sonusHostSwapUsageFallingThresholdNotification,\n";
    
    my $dat_notification_id = 1407;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDSIInPriFilesMissNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_22
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
    my $dat_additional_text = "The DSI detected missing primary AMA/CDR files, which were not received from the GSX/PSX. Automatically clears when the next AMA/CDR files is received successfully by FCP.\nTrapName = sonusDSIInPriFilesMissNotification,\n";
    
    my $dat_notification_id = 1408;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.2.1.1.1.13"})) {
        $dat_additional_text .= "\namaInPriFilesMiss = " . $entrada->{"1.3.6.1.4.1.148.1.7.2.1.1.1.13"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"})) {
        $dat_additional_text .= "\nsessionCompIndex = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusHostDiskMonSMARTErrorNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_22
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
    my $dat_additional_text = "SMARTmon error was reported.  Detailed error is specified in sonusEventDescription.\nTrapName = sonusHostDiskMonSMARTErrorNotification,\n";
    
    my $dat_notification_id = 1409;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDSICommFtpErrNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_36
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
    my $dat_additional_text = "The DSI has experienced a Transporter Ftp Session Error. Cleared  when session error is resolved.\nTrapName = sonusDSICommFtpErrNotification,\n";
    
    my $dat_notification_id = 1410;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
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

# sonusDsiDiskHiWatermarkNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_83
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
    my $dat_additional_text = "Health Monitor detected disk usage reached high watermark:(\%1\$s)\nTrapName = sonusDsiDiskHiWatermarkNotification,\n";
    
    my $dat_notification_id = 1411;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.30"})) {
        $dat_additional_text .= "\nsonusDsiDiskInfo = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.30"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDSITransporterAbortNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_95
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
    my $dat_additional_text = "Transporter aborted file transfer to all hosts\nTrapName = sonusDSITransporterAbortNotification,\n";
    
    my $dat_notification_id = 1412;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
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

# sonusHostDiskMonSoftErrorNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_19
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
    my $dat_additional_text = "Reports that the soft error count for the disk  identified by sonusHostDiskDevName has increased by  the value of sonusHostDiskErrorCount since the   last poll.\nTrapName = sonusHostDiskMonSoftErrorNotification,\n";
    
    my $dat_notification_id = 1413;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.9"})) {
        $dat_additional_text .= "\nsonusHostDiskErrorCount = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.8"})) {
        $dat_additional_text .= "\nsonusHostDiskDevName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusHostApplicationExitNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_13
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
    my $dat_additional_text = "Reports a previously running application  exits.\nTrapName = sonusHostApplicationExitNotification,\n";
    
    my $dat_notification_id = 1414;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"})) {
        $dat_additional_text .= "\nsonusHostExecName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.4"})) {
        $dat_additional_text .= "\nsonusHostProcessID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDSISNMPRestartNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_35
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
    my $dat_additional_text = "The DSI SNMP Agent has restarted.  Automatically clears when DSI  SNMP Agent has recovered.\nTrapName = sonusDSISNMPRestartNotification,\n";
    
    my $dat_notification_id = 1415;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDSIConnectionAttemptFailNotifiction
sub _1_3_6_1_4_1_2879_2_1_9_2_0_44
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
    my $dat_additional_text = "The DSI had a node connection attempt failed (Local \%s, Remote \%s, Reason \%s)  Automatically clears when node connects .\nTrapName = sonusDSIConnectionAttemptFailNotifiction,\n";
    
    my $dat_notification_id = 1416;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusHostSwapUsageRisingThresholdNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_9
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
    my $dat_additional_text = "Reports the swap space usage exceeds a given  threshold.\nTrapName = sonusHostSwapUsageRisingThresholdNotification,\n";
    
    my $dat_notification_id = 1417;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDsiLoadPolicyChangeNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_71
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
    my $dat_additional_text = "Load distribution policy changed to <newPolicy>\nTrapName = sonusDsiLoadPolicyChangeNotification,\n";
    
    my $dat_notification_id = 1418;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.15"})) {
        $dat_additional_text .= "\nsonusDSINewLoadPolicy = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.15"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDsiTransporterFtpLoginFailedNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_4
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterFtpLoginFailedNotification,\n";
    
    my $dat_notification_id = 1419;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
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

# sonusDsiTransporterCAMFileTimeErrorNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_13
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterCAMFileTimeErrorNotification,\n";
    
    my $dat_notification_id = 1420;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDSIDisk100PercentFullNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_1
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
    my $dat_additional_text = "This trap with SonusDSIAlarmStatus=set indicates that the DSI has used all the disk space assigned to it. with SonusDSIAlarmStatus=clear it indicates that the disk  no longer full.\nTrapName = sonusDSIDisk100PercentFullNotification,\n";
    
    my $dat_notification_id = 1421;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.25.2.3.1.1"})) {
        $dat_additional_text .= "\nhrStorageIndex = " . $entrada->{"1.3.6.1.2.1.25.2.3.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.25.2.3.1.7"})) {
        $dat_additional_text .= "\nhrStorageAllocationFailures = " . $entrada->{"1.3.6.1.2.1.25.2.3.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusHostDiskMonHardErrorNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_20
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
    my $dat_additional_text = "Reports that the soft error count for the disk  identified by sonusHostDiskDevName has increased by  the value of sonusHostDiskErrorCount since the   last poll.\nTrapName = sonusHostDiskMonHardErrorNotification,\n";
    
    my $dat_notification_id = 1422;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.9"})) {
        $dat_additional_text .= "\nsonusHostDiskErrorCount = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.8"})) {
        $dat_additional_text .= "\nsonusHostDiskDevName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDSISaiAuthErrNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_56
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
    my $dat_additional_text = "The DSI SAI Server has received an invalid  authentication response from the BPA.\nTrapName = sonusDSISaiAuthErrNotification,\n";
    
    my $dat_notification_id = 1423;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDSINodeNotAccessibleNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_47
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
    my $dat_additional_text = "The DSI had a node not accessible (with remote node name). Automatically clears when node is accessible .\nTrapName = sonusDSINodeNotAccessibleNotification,\n";
    
    my $dat_notification_id = 1424;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDsiTransporterIOReadErrorNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_7
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterIOReadErrorNotification,\n";
    
    my $dat_notification_id = 1425;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDsiTransporterDownNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_1
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterDownNotification,\n";
    
    my $dat_notification_id = 1426;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDsiFileServicesPeerCommFailNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_65
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
    my $dat_additional_text = "FileServices cannot communicate with its peer process  on the specified server.\nTrapName = sonusDsiFileServicesPeerCommFailNotification,\n";
    
    my $dat_notification_id = 1427;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDSISoftwareErrorNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_33
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
    my $dat_additional_text = "The DSI had a critical software error.  Requires a manual clear.\nTrapName = sonusDSISoftwareErrorNotification,\n";
    
    my $dat_notification_id = 1428;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"})) {
        $dat_additional_text .= "\nsessionCompIndex = " . $entrada->{"1.3.6.1.4.1.148.1.7.1.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
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

# sonusDSISAIDuplicateCDRNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_96
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
    my $dat_additional_text = "Duplicate CDR received by SAI server from TC.: (\%1\$s)\nTrapName = sonusDSISAIDuplicateCDRNotification,\n";
    
    my $dat_notification_id = 1429;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.27"})) {
        $dat_additional_text .= "\nsonusDSISAIDuplicateCDR = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.27"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
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

# sonusHostMemUsageFallingThrshldNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_8
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
    my $dat_additional_text = "Reports memory usage of the host falls below a given threshold value.\nTrapName = sonusHostMemUsageFallingThrshldNotification,\n";
    
    my $dat_notification_id = 1430;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"})) {
        $dat_additional_text .= "\nsonusHostThresholdSampleValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"})) {
        $dat_additional_text .= "\nsonusHostThresholdTriggerValue = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"})) {
        $dat_additional_text .= "\nsonusHostClrSet = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"})) {
        $dat_additional_text .= "\nsonusHostThresholdName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDsiTransporterCAMFileDupRecordNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_14
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterCAMFileDupRecordNotification,\n";
    
    my $dat_notification_id = 1431;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
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

# sonusDsiTransporterFtpTransferFailedNotification
sub _1_3_6_1_4_1_2879_2_5_23_2_0_5
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
    my $dat_additional_text = ".\nTrapName = sonusDsiTransporterFtpTransferFailedNotification,\n";
    
    my $dat_notification_id = 1432;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusDSIDisk50PercentFullNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_4
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
    my $dat_additional_text = "This trap with SonusDSIAlarmStatus=set indicates that the DSI has used 50 percent of the disk space assigned to it. with SonusDSIAlarmStatus=clear it indicates that the disk  no longer 50 percent full.\nTrapName = sonusDSIDisk50PercentFullNotification,\n";
    
    my $dat_notification_id = 1433;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"})) {
        $dat_additional_text .= "\nsonusDSIAlarmStatus = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
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

# sonusDsiDBClearFailoverEventNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_79
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
    my $dat_additional_text = "Clearing ORACLE Failover event occuring: status in description\nTrapName = sonusDsiDBClearFailoverEventNotification,\n";
    
    my $dat_notification_id = 1434;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
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

# sonusDsiOperatingModeErrorNotification
sub _1_3_6_1_4_1_2879_2_1_9_2_0_68
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
    my $dat_additional_text = "The process raising the alarm is not allowed to run  under the current operating mode settings. The name  of the process and the current operating mode settings  are included in the description.\nTrapName = sonusDsiOperatingModeErrorNotification,\n";
    
    my $dat_notification_id = 1435;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"})) {
        $dat_additional_text .= "\nsonusDSIClusterName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"})) {
        $dat_additional_text .= "\nsonusDSINodeType = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.11"})) {
        $dat_additional_text .= "\nsonusDSIProcessName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.9.2.1.11"} . ",\n";
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

# sonusNetMgmtClientInformReqQueueFullNotification
sub _1_3_6_1_4_1_2879_2_1_5_2_0_2
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
    my $dat_additional_text = "The specified number of InformRequest PDUs destined to the specified Management Client were discard because its InformRequest PDU queue was full. This situtation could occur if the Management Client cannot quickly process and respond to InformRequest PDUs that it receives, or if communications is lost with the Management Client. If this situation occurs occasionally, it is recommended to increase the InformRequest PDU queue size (see sonusNetMgmtClientInformReqMaxQueue.) If this situation occurs repeatedly, it is an indication that communications is lost with the Management Client, either because of network problems, or because the Management Client is no longer operational. It is recommended that this device be configured to send a Trap PDU, not an InformRequest PDU, for this Notification to all Management Clients, thus bypassing a problematic InformRequest PDU queue and allowing the situation to be quickly identified and resolved.\nTrapName = sonusNetMgmtClientInformReqQueueFullNotification,\n";
    
    my $dat_notification_id = 1436;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.11"})) {
        $dat_additional_text .= "\nsonusNetMgmtInformReqDiscards = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.1.1.1.2.1.2"})) {
        $dat_additional_text .= "\nsonusNetMgmtClientName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.1.1.1.2.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.9"})) {
        $dat_additional_text .= "\nsonusSequenceId = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
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

# sonusHostApplicationRuntimeErrorRecoverNotification
sub _1_3_6_1_4_1_2879_2_1_12_2_0_12
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
    my $dat_additional_text = "Informs the runtime errors report previously  is recovered.\nTrapName = sonusHostApplicationRuntimeErrorRecoverNotification,\n";
    
    my $dat_notification_id = 1437;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"})) {
        $dat_additional_text .= "\nsonusEventLevel = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"})) {
        $dat_additional_text .= "\nsonusEventDescription = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.3"})) {
        $dat_additional_text .= "\nsonusHostSampleInstanceCount = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.2"})) {
        $dat_additional_text .= "\nsonusHostExpectedInstanceCount = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"})) {
        $dat_additional_text .= "\nsonusHostID = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.4.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"})) {
        $dat_additional_text .= "\nsonusHostExecName = " . $entrada->{"1.3.6.1.4.1.2879.2.1.12.3.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"})) {
        $dat_additional_text .= "\nsonusEventTime = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"})) {
        $dat_additional_text .= "\nsonusEventClass = " . $entrada->{"1.3.6.1.4.1.2879.2.1.5.2.1.7"} . ",\n";
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
