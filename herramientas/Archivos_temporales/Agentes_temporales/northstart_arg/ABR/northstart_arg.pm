package ABR::northstart_arg;

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

# linkDown
sub _1_3_6_1_6_3_1_1_5_3
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
    my $dat_additional_text = "A linkDown trap signifies that the SNMP entity, acting in an agent role, has detected that the ifOperStatus object for one of its communication links is about to enter the down state from some other state (but not from the notPresent state).  This other state is indicated by the included value of ifOperStatus.\nTrapName = linkDown,\n";
    
    my $dat_notification_id = 1300;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.2.1.2.2.1.7"})) {
        $dat_additional_text .= "\nifAdminStatus = " . $entrada->{"1.3.6.1.2.1.2.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.2.2.1.1"})) {
        $dat_additional_text .= "\nifIndex = " . $entrada->{"1.3.6.1.2.1.2.2.1.1"} . ",\n";
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

# mteTriggerFalling
sub _1_3_6_1_2_1_88_2_0_3
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
    my $dat_additional_text = "Notification that the falling threshold was met for triggers with mteTriggerType 'threshold'.\nTrapName = mteTriggerFalling,\n";
    
    my $dat_notification_id = 1301;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.3"})) {
        $dat_additional_text .= "\nmteHotContextName = " . $entrada->{"1.3.6.1.2.1.88.2.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.1"})) {
        $dat_additional_text .= "\nmteHotTrigger = " . $entrada->{"1.3.6.1.2.1.88.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.4"})) {
        $dat_additional_text .= "\nmteHotOID = " . $entrada->{"1.3.6.1.2.1.88.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.2"})) {
        $dat_additional_text .= "\nmteHotTargetName = " . $entrada->{"1.3.6.1.2.1.88.2.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.5"})) {
        $dat_additional_text .= "\nmteHotValue = " . $entrada->{"1.3.6.1.2.1.88.2.1.5"} . ",\n";
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

# mteTriggerFailure
sub _1_3_6_1_2_1_88_2_0_4
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
    my $dat_additional_text = "Notification that an attempt to check a trigger has failed. The network manager must enable this notification only with a certain fear and trembling, as it can easily crowd out more important information.  It should be used only to help diagnose a problem that has appeared in the error counters and can not be found otherwise.\nTrapName = mteTriggerFailure,\n";
    
    my $dat_notification_id = 1302;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.6"})) {
        $dat_additional_text .= "\nmteFailedReason = " . $entrada->{"1.3.6.1.2.1.88.2.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.2"})) {
        $dat_additional_text .= "\nmteHotTargetName = " . $entrada->{"1.3.6.1.2.1.88.2.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.4"})) {
        $dat_additional_text .= "\nmteHotOID = " . $entrada->{"1.3.6.1.2.1.88.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.3"})) {
        $dat_additional_text .= "\nmteHotContextName = " . $entrada->{"1.3.6.1.2.1.88.2.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.1"})) {
        $dat_additional_text .= "\nmteHotTrigger = " . $entrada->{"1.3.6.1.2.1.88.2.1.1"} . ",\n";
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

# authenticationFailure
sub _1_3_6_1_6_3_1_1_5_5
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
    my $dat_additional_text = "An authenticationFailure trap signifies that the SNMP entity has received a protocol message that is not properly authenticated.  While all implementations of SNMP entities MAY be capable of generating this trap, the snmpEnableAuthenTraps object indicates whether this trap will be generated.\nTrapName = authenticationFailure,\n";
    
    my $dat_notification_id = 1303;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
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

# warmStart
sub _1_3_6_1_6_3_1_1_5_2
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
    my $dat_additional_text = "A warmStart trap signifies that the SNMP entity, supporting a notification originator application, is reinitializing itself such that its configuration is unaltered.\nTrapName = warmStart,\n";
    
    my $dat_notification_id = 1304;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
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

# ucdShutdown
sub _1_3_6_1_4_1_2021_251_2
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
    my $dat_additional_text = "This trap is sent when the agent terminates\nTrapName = ucdShutdown,\n";
    
    my $dat_notification_id = 1305;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
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

# linkUp
sub _1_3_6_1_6_3_1_1_5_4
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
    my $dat_additional_text = "A linkUp trap signifies that the SNMP entity, acting in an agent role, has detected that the ifOperStatus object for one of its communication links left the down state and transitioned into some other state (but not into the notPresent state).  This other state is indicated by the included value of ifOperStatus.\nTrapName = linkUp,\n";
    
    my $dat_notification_id = 1306;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.2.1.2.2.1.7"})) {
        $dat_additional_text .= "\nifAdminStatus = " . $entrada->{"1.3.6.1.2.1.2.2.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.2.2.1.1"})) {
        $dat_additional_text .= "\nifIndex = " . $entrada->{"1.3.6.1.2.1.2.2.1.1"} . ",\n";
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

# mteTriggerRising
sub _1_3_6_1_2_1_88_2_0_2
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
    my $dat_additional_text = "Notification that the rising threshold was met for triggers with mteTriggerType 'threshold'.\nTrapName = mteTriggerRising,\n";
    
    my $dat_notification_id = 1307;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.2"})) {
        $dat_additional_text .= "\nmteHotTargetName = " . $entrada->{"1.3.6.1.2.1.88.2.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.5"})) {
        $dat_additional_text .= "\nmteHotValue = " . $entrada->{"1.3.6.1.2.1.88.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.1"})) {
        $dat_additional_text .= "\nmteHotTrigger = " . $entrada->{"1.3.6.1.2.1.88.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.3"})) {
        $dat_additional_text .= "\nmteHotContextName = " . $entrada->{"1.3.6.1.2.1.88.2.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.4"})) {
        $dat_additional_text .= "\nmteHotOID = " . $entrada->{"1.3.6.1.2.1.88.2.1.4"} . ",\n";
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

# the
sub _1_3_6_1_2_1_88_1_4_3_1_1
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
    my $dat_additional_text = "No se encontro la descripción\nTrapName = the,\n";
    
    my $dat_notification_id = 1308;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
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

# coldStart
sub _1_3_6_1_6_3_1_1_5_1
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
    my $dat_additional_text = "A coldStart trap signifies that the SNMP entity, supporting a notification originator application, is reinitializing itself and that its configuration may have been altered.\nTrapName = coldStart,\n";
    
    my $dat_notification_id = 1309;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
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

# ucdStart
sub _1_3_6_1_4_1_2021_251_1
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
    my $dat_additional_text = "This trap could in principle be sent when the agent start\nTrapName = ucdStart,\n";
    
    my $dat_notification_id = 1310;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
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

# mteTriggerFired
sub _1_3_6_1_2_1_88_2_0_1
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
    my $dat_additional_text = "Notification that the trigger indicated by the object instances has fired, for triggers with mteTriggerType 'boolean' or 'existence'.\nTrapName = mteTriggerFired,\n";
    
    my $dat_notification_id = 1311;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.5"})) {
        $dat_additional_text .= "\nmteHotValue = " . $entrada->{"1.3.6.1.2.1.88.2.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.2"})) {
        $dat_additional_text .= "\nmteHotTargetName = " . $entrada->{"1.3.6.1.2.1.88.2.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.4"})) {
        $dat_additional_text .= "\nmteHotOID = " . $entrada->{"1.3.6.1.2.1.88.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.1"})) {
        $dat_additional_text .= "\nmteHotTrigger = " . $entrada->{"1.3.6.1.2.1.88.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.3"})) {
        $dat_additional_text .= "\nmteHotContextName = " . $entrada->{"1.3.6.1.2.1.88.2.1.3"} . ",\n";
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

# mteEventSetFailure
sub _1_3_6_1_2_1_88_2_0_5
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
    my $dat_additional_text = "Notification that an attempt to do a set in response to an event has failed. The network manager must enable this notification only with a certain fear and trembling, as it can easily crowd out more important information.  It should be used only to help diagnose a problem that has appeared in the error counters and can not be found otherwise.\nTrapName = mteEventSetFailure,\n";
    
    my $dat_notification_id = 1312;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.3"})) {
        $dat_additional_text .= "\nmteHotContextName = " . $entrada->{"1.3.6.1.2.1.88.2.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.1"})) {
        $dat_additional_text .= "\nmteHotTrigger = " . $entrada->{"1.3.6.1.2.1.88.2.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.4"})) {
        $dat_additional_text .= "\nmteHotOID = " . $entrada->{"1.3.6.1.2.1.88.2.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.2"})) {
        $dat_additional_text .= "\nmteHotTargetName = " . $entrada->{"1.3.6.1.2.1.88.2.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.2.1.88.2.1.6"})) {
        $dat_additional_text .= "\nmteFailedReason = " . $entrada->{"1.3.6.1.2.1.88.2.1.6"} . ",\n";
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
