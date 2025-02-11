package ABR::concord_mex;

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

# nhLiveResetExceptions
sub _1_3_6_1_4_1_149_25
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
    my $dat_additional_text = "The LiveExceptions server has restarted. All LiveExceptions alarms  and exceptions sent before this time will NOT be cleared automatically. All trap  destinations should reset any pre-existing eHealth exceptions  and alarms by setting them to a clear state or unhighlighting any icons.\nTrapName = nhLiveResetExceptions,\n";
    
    my $dat_notification_id = 1300;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.2"})) {
        $dat_additional_text .= "\nnhServerName = " . $entrada->{"1.3.6.1.4.1.149.2.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.1"})) {
        $dat_additional_text .= "\nnhServerIp = " . $entrada->{"1.3.6.1.4.1.149.2.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.3"})) {
        $dat_additional_text .= "\nnhServerPort = " . $entrada->{"1.3.6.1.4.1.149.2.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.13"})) {
        $dat_additional_text .= "\nnhResetTime = " . $entrada->{"1.3.6.1.4.1.149.2.3.13"} . ",\n";
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

# netHealthInfo
sub _1_3_6_1_4_1_149_15
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
    my $dat_additional_text = "An event (not an error) has occurred in eHealth. This trap is an informational message from the eHealth  Diagnostic Monitor. No action is required.\nTrapName = netHealthInfo,\n";
    
    my $dat_notification_id = 1301;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.1.1"})) {
        $dat_additional_text .= "\nnhdServerIp = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.2"})) {
        $dat_additional_text .= "\nnhdErrorTime = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.5"})) {
        $dat_additional_text .= "\nnhdErrorMessage = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.3"})) {
        $dat_additional_text .= "\nnhElementId = " . $entrada->{"1.3.6.1.4.1.149.2.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.1"})) {
        $dat_additional_text .= "\nnhdErrorDate = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.3"})) {
        $dat_additional_text .= "\nnhServerPort = " . $entrada->{"1.3.6.1.4.1.149.2.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.3"})) {
        $dat_additional_text .= "\nnhdErrorCode = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.1.2"})) {
        $dat_additional_text .= "\nnhdServerName = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.1.2"} . ",\n";
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

# netHealthReset
sub _1_3_6_1_4_1_149_17
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
    my $dat_additional_text = "A system critical error has occurred in eHealth. Polling may not occur. Restart the eHealth servers as soon as possible. This trap is sent from the eHealth  Diagnostic Monitor.\nTrapName = netHealthReset,\n";
    
    my $dat_notification_id = 1302;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.1"})) {
        $dat_additional_text .= "\nnhdErrorDate = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.1.1"})) {
        $dat_additional_text .= "\nnhdServerIp = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.2"})) {
        $dat_additional_text .= "\nnhdErrorTime = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.5"})) {
        $dat_additional_text .= "\nnhdErrorMessage = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.3"})) {
        $dat_additional_text .= "\nnhdErrorCode = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.1.2"})) {
        $dat_additional_text .= "\nnhdServerName = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.1.2"} . ",\n";
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

# nhLiveAlarm
sub _1_3_6_1_4_1_149_21
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
    my $dat_additional_text = "A eHealth alarm has occurred. This trap sends detailed information about an alarm.\nTrapName = nhLiveAlarm,\n";
    
    my $dat_notification_id = 1303;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.2"})) {
        $dat_additional_text .= "\nnhServerName = " . $entrada->{"1.3.6.1.4.1.149.2.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.17"})) {
        $dat_additional_text .= "\nnhEventCarrier = " . $entrada->{"1.3.6.1.4.1.149.2.3.17"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.5"})) {
        $dat_additional_text .= "\nnhExceptionType = " . $entrada->{"1.3.6.1.4.1.149.2.3.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.4"})) {
        $dat_additional_text .= "\nnhStartTime = " . $entrada->{"1.3.6.1.4.1.149.2.3.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.22"})) {
        $dat_additional_text .= "\nnhProfileId = " . $entrada->{"1.3.6.1.4.1.149.2.3.22"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.2"})) {
        $dat_additional_text .= "\nnhElementName = " . $entrada->{"1.3.6.1.4.1.149.2.3.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.6"})) {
        $dat_additional_text .= "\nnhVariable = " . $entrada->{"1.3.6.1.4.1.149.2.3.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.1"})) {
        $dat_additional_text .= "\nnhElementIp = " . $entrada->{"1.3.6.1.4.1.149.2.3.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.20"})) {
        $dat_additional_text .= "\nnhDescription = " . $entrada->{"1.3.6.1.4.1.149.2.3.20"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.11.2.17.2.5"})) {
        $dat_additional_text .= "\nopenViewSeverity = " . $entrada->{"1.3.6.1.4.1.11.2.17.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.19"})) {
        $dat_additional_text .= "\nnhComponent = " . $entrada->{"1.3.6.1.4.1.149.2.3.19"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.7"})) {
        $dat_additional_text .= "\nnhSeverity = " . $entrada->{"1.3.6.1.4.1.149.2.3.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.21"})) {
        $dat_additional_text .= "\nnhAlarmOccurId = " . $entrada->{"1.3.6.1.4.1.149.2.3.21"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.11"})) {
        $dat_additional_text .= "\nnhExceptionId = " . $entrada->{"1.3.6.1.4.1.149.2.3.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.8"})) {
        $dat_additional_text .= "\nnhGroup = " . $entrada->{"1.3.6.1.4.1.149.2.3.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.3"})) {
        $dat_additional_text .= "\nnhElementId = " . $entrada->{"1.3.6.1.4.1.149.2.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.10"})) {
        $dat_additional_text .= "\nnhDisplayStr = " . $entrada->{"1.3.6.1.4.1.149.2.3.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.12"})) {
        $dat_additional_text .= "\nnhTechType = " . $entrada->{"1.3.6.1.4.1.149.2.3.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.1"})) {
        $dat_additional_text .= "\nnhServerIp = " . $entrada->{"1.3.6.1.4.1.149.2.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.3"})) {
        $dat_additional_text .= "\nnhServerPort = " . $entrada->{"1.3.6.1.4.1.149.2.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.14"})) {
        $dat_additional_text .= "\nnhProfile = " . $entrada->{"1.3.6.1.4.1.149.2.3.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.23"})) {
        $dat_additional_text .= "\nnhElementBasetype = " . $entrada->{"1.3.6.1.4.1.149.2.3.23"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.9"})) {
        $dat_additional_text .= "\nnhGroupList = " . $entrada->{"1.3.6.1.4.1.149.2.3.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.18"})) {
        $dat_additional_text .= "\nnhElementAlias = " . $entrada->{"1.3.6.1.4.1.149.2.3.18"} . ",\n";
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

# nhLiveClearAlarm
sub _1_3_6_1_4_1_149_23
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
    my $dat_additional_text = "A eHealth alarm has been cleared. The conditions causing the corresponding alarm no longer exist.\nTrapName = nhLiveClearAlarm,\n";
    
    my $dat_notification_id = 1304;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.10"})) {
        $dat_additional_text .= "\nnhDisplayStr = " . $entrada->{"1.3.6.1.4.1.149.2.3.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.1"})) {
        $dat_additional_text .= "\nnhServerIp = " . $entrada->{"1.3.6.1.4.1.149.2.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.9"})) {
        $dat_additional_text .= "\nnhGroupList = " . $entrada->{"1.3.6.1.4.1.149.2.3.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.18"})) {
        $dat_additional_text .= "\nnhElementAlias = " . $entrada->{"1.3.6.1.4.1.149.2.3.18"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.2"})) {
        $dat_additional_text .= "\nnhElementName = " . $entrada->{"1.3.6.1.4.1.149.2.3.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.5"})) {
        $dat_additional_text .= "\nnhExceptionType = " . $entrada->{"1.3.6.1.4.1.149.2.3.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.3"})) {
        $dat_additional_text .= "\nnhElementId = " . $entrada->{"1.3.6.1.4.1.149.2.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.11.2.17.2.5"})) {
        $dat_additional_text .= "\nopenViewSeverity = " . $entrada->{"1.3.6.1.4.1.11.2.17.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.20"})) {
        $dat_additional_text .= "\nnhDescription = " . $entrada->{"1.3.6.1.4.1.149.2.3.20"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.1"})) {
        $dat_additional_text .= "\nnhElementIp = " . $entrada->{"1.3.6.1.4.1.149.2.3.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.7"})) {
        $dat_additional_text .= "\nnhSeverity = " . $entrada->{"1.3.6.1.4.1.149.2.3.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.21"})) {
        $dat_additional_text .= "\nnhAlarmOccurId = " . $entrada->{"1.3.6.1.4.1.149.2.3.21"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.19"})) {
        $dat_additional_text .= "\nnhComponent = " . $entrada->{"1.3.6.1.4.1.149.2.3.19"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.3"})) {
        $dat_additional_text .= "\nnhServerPort = " . $entrada->{"1.3.6.1.4.1.149.2.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.12"})) {
        $dat_additional_text .= "\nnhTechType = " . $entrada->{"1.3.6.1.4.1.149.2.3.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.16"})) {
        $dat_additional_text .= "\nnhProblemDuration = " . $entrada->{"1.3.6.1.4.1.149.2.3.16"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.14"})) {
        $dat_additional_text .= "\nnhProfile = " . $entrada->{"1.3.6.1.4.1.149.2.3.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.4"})) {
        $dat_additional_text .= "\nnhStartTime = " . $entrada->{"1.3.6.1.4.1.149.2.3.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.6"})) {
        $dat_additional_text .= "\nnhVariable = " . $entrada->{"1.3.6.1.4.1.149.2.3.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.17"})) {
        $dat_additional_text .= "\nnhEventCarrier = " . $entrada->{"1.3.6.1.4.1.149.2.3.17"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.2"})) {
        $dat_additional_text .= "\nnhServerName = " . $entrada->{"1.3.6.1.4.1.149.2.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.8"})) {
        $dat_additional_text .= "\nnhGroup = " . $entrada->{"1.3.6.1.4.1.149.2.3.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.11"})) {
        $dat_additional_text .= "\nnhExceptionId = " . $entrada->{"1.3.6.1.4.1.149.2.3.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.15"})) {
        $dat_additional_text .= "\nnhProblemStartTime = " . $entrada->{"1.3.6.1.4.1.149.2.3.15"} . ",\n";
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

# netHealthUrgent
sub _1_3_6_1_4_1_149_18
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
    my $dat_additional_text = "A system critical error has occurred in eHealth. Polling may not occur. System administrator intervention  is required. This trap is sent from the eHealth  Diagnostic Monitor.\nTrapName = netHealthUrgent,\n";
    
    my $dat_notification_id = 1305;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.1.1"})) {
        $dat_additional_text .= "\nnhdServerIp = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.2"})) {
        $dat_additional_text .= "\nnhdErrorTime = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.5"})) {
        $dat_additional_text .= "\nnhdErrorMessage = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.1"})) {
        $dat_additional_text .= "\nnhdErrorDate = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.3"})) {
        $dat_additional_text .= "\nnhdErrorCode = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.1.2"})) {
        $dat_additional_text .= "\nnhdServerName = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.1.2"} . ",\n";
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

# nhLiveClearException
sub _1_3_6_1_4_1_149_22
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
    my $dat_additional_text = "A eHealth exception has been cleared. The conditions causing the corresponding exception no longer exist. Deprecated in eHealth 5.6 Release.\nTrapName = nhLiveClearException,\n";
    
    my $dat_notification_id = 1306;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.3"})) {
        $dat_additional_text .= "\nnhElementId = " . $entrada->{"1.3.6.1.4.1.149.2.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.8"})) {
        $dat_additional_text .= "\nnhGroup = " . $entrada->{"1.3.6.1.4.1.149.2.3.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.7"})) {
        $dat_additional_text .= "\nnhSeverity = " . $entrada->{"1.3.6.1.4.1.149.2.3.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.15"})) {
        $dat_additional_text .= "\nnhProblemStartTime = " . $entrada->{"1.3.6.1.4.1.149.2.3.15"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.11"})) {
        $dat_additional_text .= "\nnhExceptionId = " . $entrada->{"1.3.6.1.4.1.149.2.3.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.1"})) {
        $dat_additional_text .= "\nnhElementIp = " . $entrada->{"1.3.6.1.4.1.149.2.3.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.2"})) {
        $dat_additional_text .= "\nnhElementName = " . $entrada->{"1.3.6.1.4.1.149.2.3.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.4"})) {
        $dat_additional_text .= "\nnhStartTime = " . $entrada->{"1.3.6.1.4.1.149.2.3.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.2"})) {
        $dat_additional_text .= "\nnhServerName = " . $entrada->{"1.3.6.1.4.1.149.2.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.16"})) {
        $dat_additional_text .= "\nnhProblemDuration = " . $entrada->{"1.3.6.1.4.1.149.2.3.16"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.9"})) {
        $dat_additional_text .= "\nnhGroupList = " . $entrada->{"1.3.6.1.4.1.149.2.3.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.14"})) {
        $dat_additional_text .= "\nnhProfile = " . $entrada->{"1.3.6.1.4.1.149.2.3.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.3"})) {
        $dat_additional_text .= "\nnhServerPort = " . $entrada->{"1.3.6.1.4.1.149.2.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.1"})) {
        $dat_additional_text .= "\nnhServerIp = " . $entrada->{"1.3.6.1.4.1.149.2.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.12"})) {
        $dat_additional_text .= "\nnhTechType = " . $entrada->{"1.3.6.1.4.1.149.2.3.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.10"})) {
        $dat_additional_text .= "\nnhDisplayStr = " . $entrada->{"1.3.6.1.4.1.149.2.3.10"} . ",\n";
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

# nhLiveException
sub _1_3_6_1_4_1_149_20
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
    my $dat_additional_text = "A eHealth exception has occurred. This trap sends generic information about an exception when it first becomes active. Deprecated in eHealth 5.6 Release.\nTrapName = nhLiveException,\n";
    
    my $dat_notification_id = 1307;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.3"})) {
        $dat_additional_text .= "\nnhServerPort = " . $entrada->{"1.3.6.1.4.1.149.2.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.4"})) {
        $dat_additional_text .= "\nnhStartTime = " . $entrada->{"1.3.6.1.4.1.149.2.3.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.2"})) {
        $dat_additional_text .= "\nnhElementName = " . $entrada->{"1.3.6.1.4.1.149.2.3.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.2"})) {
        $dat_additional_text .= "\nnhServerName = " . $entrada->{"1.3.6.1.4.1.149.2.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.10"})) {
        $dat_additional_text .= "\nnhDisplayStr = " . $entrada->{"1.3.6.1.4.1.149.2.3.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.12"})) {
        $dat_additional_text .= "\nnhTechType = " . $entrada->{"1.3.6.1.4.1.149.2.3.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.1"})) {
        $dat_additional_text .= "\nnhServerIp = " . $entrada->{"1.3.6.1.4.1.149.2.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.8"})) {
        $dat_additional_text .= "\nnhGroup = " . $entrada->{"1.3.6.1.4.1.149.2.3.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.9"})) {
        $dat_additional_text .= "\nnhGroupList = " . $entrada->{"1.3.6.1.4.1.149.2.3.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.3"})) {
        $dat_additional_text .= "\nnhElementId = " . $entrada->{"1.3.6.1.4.1.149.2.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.1"})) {
        $dat_additional_text .= "\nnhElementIp = " . $entrada->{"1.3.6.1.4.1.149.2.3.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.14"})) {
        $dat_additional_text .= "\nnhProfile = " . $entrada->{"1.3.6.1.4.1.149.2.3.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.7"})) {
        $dat_additional_text .= "\nnhSeverity = " . $entrada->{"1.3.6.1.4.1.149.2.3.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.11"})) {
        $dat_additional_text .= "\nnhExceptionId = " . $entrada->{"1.3.6.1.4.1.149.2.3.11"} . ",\n";
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

# netHealthException
sub _1_3_6_1_4_1_149_19
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
    my $dat_additional_text = "A scheduled eHealth report has detected one or more health exceptions for an element.\nTrapName = netHealthException,\n";
    
    my $dat_notification_id = 1308;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.1.1"})) {
        $dat_additional_text .= "\nnhdServerIp = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.2"})) {
        $dat_additional_text .= "\nnhdErrorTime = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.5"})) {
        $dat_additional_text .= "\nnhdErrorMessage = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.3"})) {
        $dat_additional_text .= "\nnhElementId = " . $entrada->{"1.3.6.1.4.1.149.2.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.1"})) {
        $dat_additional_text .= "\nnhdErrorDate = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.3"})) {
        $dat_additional_text .= "\nnhServerPort = " . $entrada->{"1.3.6.1.4.1.149.2.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.3"})) {
        $dat_additional_text .= "\nnhdErrorCode = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.1"})) {
        $dat_additional_text .= "\nnhServerIp = " . $entrada->{"1.3.6.1.4.1.149.2.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.1.2"})) {
        $dat_additional_text .= "\nnhdServerName = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.1.2"} . ",\n";
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

# netHealthWarning
sub _1_3_6_1_4_1_149_16
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
    my $dat_additional_text = "An error has occurred in eHealth. Polling will continue, please investigate as  soon as possible. This trap is sent from the eHealth  Diagnostic Monitor.\nTrapName = netHealthWarning,\n";
    
    my $dat_notification_id = 1309;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.1.1"})) {
        $dat_additional_text .= "\nnhdServerIp = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.2"})) {
        $dat_additional_text .= "\nnhdErrorTime = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.5"})) {
        $dat_additional_text .= "\nnhdErrorMessage = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.1.2"})) {
        $dat_additional_text .= "\nnhdServerName = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.1"})) {
        $dat_additional_text .= "\nnhdErrorDate = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.1.1.2.3"})) {
        $dat_additional_text .= "\nnhdErrorCode = " . $entrada->{"1.3.6.1.4.1.149.2.1.1.2.3"} . ",\n";
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

# nhLiveUpdateException
sub _1_3_6_1_4_1_149_24
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
    my $dat_additional_text = "The severity of a eHealth exception has changed.  Deprecated in eHealth 5.6 Release.\nTrapName = nhLiveUpdateException,\n";
    
    my $dat_notification_id = 1310;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.3"})) {
        $dat_additional_text .= "\nnhElementId = " . $entrada->{"1.3.6.1.4.1.149.2.3.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.9"})) {
        $dat_additional_text .= "\nnhGroupList = " . $entrada->{"1.3.6.1.4.1.149.2.3.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.8"})) {
        $dat_additional_text .= "\nnhGroup = " . $entrada->{"1.3.6.1.4.1.149.2.3.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.11"})) {
        $dat_additional_text .= "\nnhExceptionId = " . $entrada->{"1.3.6.1.4.1.149.2.3.11"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.7"})) {
        $dat_additional_text .= "\nnhSeverity = " . $entrada->{"1.3.6.1.4.1.149.2.3.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.1"})) {
        $dat_additional_text .= "\nnhElementIp = " . $entrada->{"1.3.6.1.4.1.149.2.3.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.14"})) {
        $dat_additional_text .= "\nnhProfile = " . $entrada->{"1.3.6.1.4.1.149.2.3.14"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.2"})) {
        $dat_additional_text .= "\nnhElementName = " . $entrada->{"1.3.6.1.4.1.149.2.3.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.4"})) {
        $dat_additional_text .= "\nnhStartTime = " . $entrada->{"1.3.6.1.4.1.149.2.3.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.3"})) {
        $dat_additional_text .= "\nnhServerPort = " . $entrada->{"1.3.6.1.4.1.149.2.2.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.1"})) {
        $dat_additional_text .= "\nnhServerIp = " . $entrada->{"1.3.6.1.4.1.149.2.2.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.12"})) {
        $dat_additional_text .= "\nnhTechType = " . $entrada->{"1.3.6.1.4.1.149.2.3.12"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.3.10"})) {
        $dat_additional_text .= "\nnhDisplayStr = " . $entrada->{"1.3.6.1.4.1.149.2.3.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.149.2.2.2"})) {
        $dat_additional_text .= "\nnhServerName = " . $entrada->{"1.3.6.1.4.1.149.2.2.2"} . ",\n";
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
