package ABR::aaems_car;

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

# haCommunicationAlarm
sub _1_3_6_1_4_1_20858_10_104_101_2_1_4
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
    my $dat_additional_text = "AeMS HA communication alarm\nTrapName = haCommunicationAlarm,\n";
    
    my $dat_notification_id = 1300;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
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

# holdoverPeriodExpiration
sub _1_3_6_1_4_1_20858_10_104_101_2_2_39
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
    my $dat_additional_text = "L3 process raises the alarm when the eNB is working for all the holdover time without re-synchronizing\nTrapName = holdoverPeriodExpiration,\n";
    
    my $dat_notification_id = 1301;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
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

# ipsecTunnelExpiry
sub _1_3_6_1_4_1_20858_10_104_101_2_2_36
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
    my $dat_additional_text = "System monitors IPsec tunnel and raises the alarm when the tunnel rekeying fails\nTrapName = ipsecTunnelExpiry,\n";
    
    my $dat_notification_id = 1302;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# reTransmissionRateExcessive
sub _1_3_6_1_4_1_20858_10_104_101_2_2_9
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
    my $dat_additional_text = "The MAC has an excessive rate of NACKs\nTrapName = reTransmissionRateExcessive,\n";
    
    my $dat_notification_id = 1303;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
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

# criticalConfigurationFailure
sub _1_3_6_1_4_1_20858_10_104_101_2_2_47
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
    my $dat_additional_text = "L3 process detects this situation and raises alarm if mandatory EPC configuration parameters are not configured\nTrapName = criticalConfigurationFailure,\n";
    
    my $dat_notification_id = 1304;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# invalidPhyOrRfConfiguration
sub _1_3_6_1_4_1_20858_10_104_101_2_2_30
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
    my $dat_additional_text = "Invalid PHY or RF configuration\nTrapName = invalidPhyOrRfConfiguration,\n";
    
    my $dat_notification_id = 1305;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
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

# rebootLoop
sub _1_3_6_1_4_1_20858_10_104_101_2_2_43
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
    my $dat_additional_text = "System raises this alarm upon detection of several continious reboots in a short period of time\nTrapName = rebootLoop,\n";
    
    my $dat_notification_id = 1306;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# pciConfusion
sub _1_3_6_1_4_1_20858_10_104_101_2_2_24
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
    my $dat_additional_text = "The eNB detects that it is configurted with the same PCI as another neighbor of second ring cell\nTrapName = pciConfusion,\n";
    
    my $dat_notification_id = 1307;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
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

# cpuCyclesLimitExceeded
sub _1_3_6_1_4_1_20858_10_104_101_2_2_8
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
    my $dat_additional_text = "CPU usage exceeds defined threshold\nTrapName = cpuCyclesLimitExceeded,\n";
    
    my $dat_notification_id = 1308;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# administrativeReboot
sub _1_3_6_1_4_1_20858_10_104_101_2_2_40
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
    my $dat_additional_text = "OAM process will send this informational alarm upon administrative reboot\nTrapName = administrativeReboot,\n";
    
    my $dat_notification_id = 1309;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# l1StartTimeout
sub _1_3_6_1_4_1_20858_10_104_101_2_2_26
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
    my $dat_additional_text = "the protocol stack cannot start L1 process in DSPs\nTrapName = l1StartTimeout,\n";
    
    my $dat_notification_id = 1310;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# singleMmeConnectionIsDown
sub _1_3_6_1_4_1_20858_10_104_101_2_2_34
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
    my $dat_additional_text = "Single MME connection is down\nTrapName = singleMmeConnectionIsDown,\n";
    
    my $dat_notification_id = 1311;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# configurationOrCustomizingErrror
sub _1_3_6_1_4_1_20858_10_104_101_2_2_18
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
    my $dat_additional_text = "The configuration received from OAM interfaces (EMS, CLI, HTTP etc) is wrong\nTrapName = configurationOrCustomizingErrror,\n";
    
    my $dat_notification_id = 1312;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# l2NotDetected
sub _1_3_6_1_4_1_20858_10_104_101_2_2_2
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
    my $dat_additional_text = "L2 not detected\nTrapName = l2NotDetected,\n";
    
    my $dat_notification_id = 1313;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# errorAccessingFile
sub _1_3_6_1_4_1_20858_10_104_101_2_2_7
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
    my $dat_additional_text = "Error accessing file\nTrapName = errorAccessingFile,\n";
    
    my $dat_notification_id = 1314;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# cCMSServerConnectionFailure
sub _1_3_6_1_4_1_20858_10_104_101_2_2_49
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
    my $dat_additional_text = "System raises the alarm when the Operator certificate server cannot be connected. This alarm has been deprecated on AeMS.\nTrapName = cCMSServerConnectionFailure,\n";
    
    my $dat_notification_id = 1315;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# maxMMEAttemptsExceeded
sub _1_3_6_1_4_1_20858_10_104_101_2_2_42
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
    my $dat_additional_text = "L3 process is responsible to handle connection with MME, so it raises the alarm if the connection is lost with all MMEs and the maximum number of retries is reached\nTrapName = maxMMEAttemptsExceeded,\n";
    
    my $dat_notification_id = 1316;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# dbArbiterConnectionAlarm
sub _1_3_6_1_4_1_20858_10_104_101_2_1_6
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
    my $dat_additional_text = "AeMS DB arbiter connection alarm\nTrapName = dbArbiterConnectionAlarm,\n";
    
    my $dat_notification_id = 1317;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
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

# deviceOnlineAlarm
sub _1_3_6_1_4_1_20858_10_104_101_2_1_9
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
    my $dat_additional_text = "Small Cell online alarm\nTrapName = deviceOnlineAlarm,\n";
    
    my $dat_notification_id = 1318;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
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

# casaHeMSHeartBeatMsg
sub _1_3_6_1_4_1_20858_10_104_101_2_4
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
    my $dat_additional_text = "Casa HeMS HeartBeat Msg\nTrapName = casaHeMSHeartBeatMsg,\n";
    
    my $dat_notification_id = 1319;
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

# cellOffAlarm
sub _1_3_6_1_4_1_20858_10_104_101_2_1_12
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
    my $dat_additional_text = "Small Cell cellOff alarm\nTrapName = cellOffAlarm,\n";
    
    my $dat_notification_id = 1320;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# dspOrPhyCrash
sub _1_3_6_1_4_1_20858_10_104_101_2_2_27
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
    my $dat_additional_text = "the DSPs running the PHY crashes\nTrapName = dspOrPhyCrash,\n";
    
    my $dat_notification_id = 1321;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
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

# cpuUsageIsHigh
sub _1_3_6_1_4_1_20858_10_104_101_2_1_2
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
    my $dat_additional_text = "AeMS CPU usage is high\nTrapName = cpuUsageIsHigh,\n";
    
    my $dat_notification_id = 1322;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
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

# watchdogNotDetected
sub _1_3_6_1_4_1_20858_10_104_101_2_2_46
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
    my $dat_additional_text = "Linux system monitorize system self-healing agent and reboots the eNB\nTrapName = watchdogNotDetected,\n";
    
    my $dat_notification_id = 1323;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# cpuTemperatureUnacceptable
sub _1_3_6_1_4_1_20858_10_104_101_2_2_15
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
    my $dat_additional_text = "CPU Temperature exceeds defined threshold\nTrapName = cpuTemperatureUnacceptable,\n";
    
    my $dat_notification_id = 1324;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
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

# networkInterfaceAlarm
sub _1_3_6_1_4_1_20858_10_104_101_2_1_7
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
    my $dat_additional_text = "AeMS Network interface alarm\nTrapName = networkInterfaceAlarm,\n";
    
    my $dat_notification_id = 1325;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
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

# remoteAeMSsStatusAlarm
sub _1_3_6_1_4_1_20858_10_104_101_2_1_15
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
    my $dat_additional_text = "Remote AeMSs down\nTrapName = remoteAeMSsStatusAlarm,\n";
    
    my $dat_notification_id = 1326;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# sctpFailure
sub _1_3_6_1_4_1_20858_10_104_101_2_2_13
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
    my $dat_additional_text = "SCTP connection failure\nTrapName = sctpFailure,\n";
    
    my $dat_notification_id = 1327;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# tr069NotDetected
sub _1_3_6_1_4_1_20858_10_104_101_2_2_45
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
    my $dat_additional_text = "Self-healing agent monitors processes and raises alarm if it detects the process dying\nTrapName = tr069NotDetected,\n";
    
    my $dat_notification_id = 1328;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
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

# radioOnAlarm
sub _1_3_6_1_4_1_20858_10_104_101_2_1_11
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
    my $dat_additional_text = "Small Cell radioOn alarm\nTrapName = radioOnAlarm,\n";
    
    my $dat_notification_id = 1329;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
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

# hardDiskUsageIsHigh
sub _1_3_6_1_4_1_20858_10_104_101_2_1_3
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
    my $dat_additional_text = "AeMS Hard disk usage is high\nTrapName = hardDiskUsageIsHigh,\n";
    
    my $dat_notification_id = 1330;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# ipsecTunnelIsDown
sub _1_3_6_1_4_1_20858_10_104_101_2_2_35
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
    my $dat_additional_text = "System monitors IPsec tunnel and raises the alarm when the tunnel fails\nTrapName = ipsecTunnelIsDown,\n";
    
    my $dat_notification_id = 1331;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
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

# radioOffAlarm
sub _1_3_6_1_4_1_20858_10_104_101_2_1_10
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
    my $dat_additional_text = "Small Cell radioOff alarm\nTrapName = radioOffAlarm,\n";
    
    my $dat_notification_id = 1332;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# thresholdCrossedLowSINR
sub _1_3_6_1_4_1_20858_10_104_101_2_2_21
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
    my $dat_additional_text = "The MAC has too many low SINR events\nTrapName = thresholdCrossedLowSINR,\n";
    
    my $dat_notification_id = 1333;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
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

# memoryUsageIsHigh
sub _1_3_6_1_4_1_20858_10_104_101_2_1_1
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
    my $dat_additional_text = "AeMS Memory usage is high\nTrapName = memoryUsageIsHigh,\n";
    
    my $dat_notification_id = 1334;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# kpiAgentNotDetected
sub _1_3_6_1_4_1_20858_10_104_101_2_2_3
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
    my $dat_additional_text = "KPI Agent not detected\nTrapName = kpiAgentNotDetected,\n";
    
    my $dat_notification_id = 1335;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# cellOnAlarm
sub _1_3_6_1_4_1_20858_10_104_101_2_1_13
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
    my $dat_additional_text = "Small Cell cellOn alarm\nTrapName = cellOnAlarm,\n";
    
    my $dat_notification_id = 1336;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
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

# paBiasingFailure
sub _1_3_6_1_4_1_20858_10_104_101_2_2_22
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
    my $dat_additional_text = "The PA board was not able to properly biasing\nTrapName = paBiasingFailure,\n";
    
    my $dat_notification_id = 1337;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
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

# l3NotDetected
sub _1_3_6_1_4_1_20858_10_104_101_2_2_1
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
    my $dat_additional_text = "L3 not detected\nTrapName = l3NotDetected,\n";
    
    my $dat_notification_id = 1338;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# failedBackingUpConfigurationFile
sub _1_3_6_1_4_1_20858_10_104_101_2_2_32
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
    my $dat_additional_text = "Any process of eNB raises this alarm if it gets error while backing up a file\nTrapName = failedBackingUpConfigurationFile,\n";
    
    my $dat_notification_id = 1339;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# killSwitch
sub _1_3_6_1_4_1_20858_10_104_101_2_2_25
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
    my $dat_additional_text = "An external signal is activated when detetecting power supply outage, and this signal reaches the self-healing process, which raises alarm and gracefully halts the eNB\nTrapName = killSwitch,\n";
    
    my $dat_notification_id = 1340;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
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

# failedRestoringConfigurationFile
sub _1_3_6_1_4_1_20858_10_104_101_2_2_33
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
    my $dat_additional_text = "Any process of eNB raises this alarm if it gets error while restoring a corrupted configuration file\nTrapName = failedRestoringConfigurationFile,\n";
    
    my $dat_notification_id = 1341;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
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

# flashMemoryUsage
sub _1_3_6_1_4_1_20858_10_104_101_2_2_4
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
    my $dat_additional_text = "Flash memory usage\nTrapName = flashMemoryUsage,\n";
    
    my $dat_notification_id = 1342;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
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

# operatorCertificateExpired
sub _1_3_6_1_4_1_20858_10_104_101_2_2_38
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
    my $dat_additional_text = "System raises the alarm when the Operator certificate cannot be renewed\nTrapName = operatorCertificateExpired,\n";
    
    my $dat_notification_id = 1343;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
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

# casaHeMSSmallCellGWAlarm
sub _1_3_6_1_4_1_20858_10_104_101_2_3
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
    my $dat_additional_text = "Casa HeMS SmallCell-GW Alarm\nTrapName = casaHeMSSmallCellGWAlarm,\n";
    
    my $dat_notification_id = 1344;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
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

# aAeMSConnectionNoResponse
sub _1_3_6_1_4_1_20858_10_104_101_2_2_50
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
    my $dat_additional_text = "System raises the alarm when the eNB cannot connect to AeMS server\nTrapName = aAeMSConnectionNoResponse,\n";
    
    my $dat_notification_id = 1345;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
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

# unauthorisedAccessAttempt
sub _1_3_6_1_4_1_20858_10_104_101_2_2_17
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
    my $dat_additional_text = "Someone or some process did attempt unsuccesfully to login the web interface\nTrapName = unauthorisedAccessAttempt,\n";
    
    my $dat_notification_id = 1346;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# systemInformationConfigurationFailure
sub _1_3_6_1_4_1_20858_10_104_101_2_2_31
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
    my $dat_additional_text = "System information configuration failure\nTrapName = systemInformationConfigurationFailure,\n";
    
    my $dat_notification_id = 1347;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# paTemperatureUnacceptable
sub _1_3_6_1_4_1_20858_10_104_101_2_2_16
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
    my $dat_additional_text = "The tempeature in the PA exceeds the defined threshold\nTrapName = paTemperatureUnacceptable,\n";
    
    my $dat_notification_id = 1348;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# cellSynchronizationFailure
sub _1_3_6_1_4_1_20858_10_104_101_2_2_12
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
    my $dat_additional_text = "Cell synchronization failure\nTrapName = cellSynchronizationFailure,\n";
    
    my $dat_notification_id = 1349;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# outOfMemory
sub _1_3_6_1_4_1_20858_10_104_101_2_2_19
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
    my $dat_additional_text = "RAM usage is high and surpassed the defined threshold\nTrapName = outOfMemory,\n";
    
    my $dat_notification_id = 1350;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# pciCollision
sub _1_3_6_1_4_1_20858_10_104_101_2_2_23
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
    my $dat_additional_text = "The eNB is configured with the same PCI as another neighbor cell\nTrapName = pciCollision,\n";
    
    my $dat_notification_id = 1351;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# congestion
sub _1_3_6_1_4_1_20858_10_104_101_2_2_6
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
    my $dat_additional_text = "RRM overload\nTrapName = congestion,\n";
    
    my $dat_notification_id = 1352;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
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

# forcedReboot
sub _1_3_6_1_4_1_20858_10_104_101_2_2_41
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
    my $dat_additional_text = "Self-healing agent raises this alarm upon detection of major failure requiring a reboot\nTrapName = forcedReboot,\n";
    
    my $dat_notification_id = 1353;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
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

# overTheAirSynchronizationLost
sub _1_3_6_1_4_1_20858_10_104_101_2_2_10
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
    my $dat_additional_text = "Syncrhonization with the macro OTA is lost\nTrapName = overTheAirSynchronizationLost,\n";
    
    my $dat_notification_id = 1354;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# thresholdCrossedRLF
sub _1_3_6_1_4_1_20858_10_104_101_2_2_20
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
    my $dat_additional_text = "The MAC has too many RLF s\nTrapName = thresholdCrossedRLF,\n";
    
    my $dat_notification_id = 1355;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
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

# mmeConnectionIsDown
sub _1_3_6_1_4_1_20858_10_104_101_2_2_5
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
    my $dat_additional_text = "MME connection is down\nTrapName = mmeConnectionIsDown,\n";
    
    my $dat_notification_id = 1356;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# synchronizationLostWithAllSources
sub _1_3_6_1_4_1_20858_10_104_101_2_2_29
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
    my $dat_additional_text = "the synchornization is lost and the eNB passes to holdover mode\nTrapName = synchronizationLostWithAllSources,\n";
    
    my $dat_notification_id = 1357;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
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

# clockSynchronizationProblem
sub _1_3_6_1_4_1_20858_10_104_101_2_2_28
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
    my $dat_additional_text = "Cell not synchronized\nTrapName = clockSynchronizationProblem,\n";
    
    my $dat_notification_id = 1358;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# ipsecTunnelIkeSaExpiry
sub _1_3_6_1_4_1_20858_10_104_101_2_2_37
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
    my $dat_additional_text = "System monitors IPsec tunnel and raises the alarm when the IKE rekeying fails\nTrapName = ipsecTunnelIkeSaExpiry,\n";
    
    my $dat_notification_id = 1359;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# dbSlaveConnectionAlarm
sub _1_3_6_1_4_1_20858_10_104_101_2_1_5
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
    my $dat_additional_text = "AeMS DB slave connection alarm\nTrapName = dbSlaveConnectionAlarm,\n";
    
    my $dat_notification_id = 1360;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
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

# gpsSynchronizationLost
sub _1_3_6_1_4_1_20858_10_104_101_2_2_11
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
    my $dat_additional_text = "GPS synchronization lost\nTrapName = gpsSynchronizationLost,\n";
    
    my $dat_notification_id = 1361;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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

# deviceOfflineAlarm
sub _1_3_6_1_4_1_20858_10_104_101_2_1_8
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
    my $dat_additional_text = "Small Cell offline alarm\nTrapName = deviceOfflineAlarm,\n";
    
    my $dat_notification_id = 1362;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# lanError
sub _1_3_6_1_4_1_20858_10_104_101_2_2_14
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
    my $dat_additional_text = "Ethernet error\nTrapName = lanError,\n";
    
    my $dat_notification_id = 1363;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
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

# dnsResolutionFailure
sub _1_3_6_1_4_1_20858_10_104_101_2_2_44
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
    my $dat_additional_text = "System raises this alarm upon failure to resolve the IP addresses of a FQDN\nTrapName = dnsResolutionFailure,\n";
    
    my $dat_notification_id = 1364;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
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

# oOAMProxyRestarted
sub _1_3_6_1_4_1_20858_10_104_101_2_2_48
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
    my $dat_additional_text = "Kill OAM proxy process to force the generation of the alarm\nTrapName = oOAMProxyRestarted,\n";
    
    my $dat_notification_id = 1365;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
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

# dbReplicationAlarm
sub _1_3_6_1_4_1_20858_10_104_101_2_1_14
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
    my $dat_additional_text = "DB replication failed\nTrapName = dbReplicationAlarm,\n";
    
    my $dat_notification_id = 1366;
    my $dat_correlated_notification_id = "";

    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"});

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"})) {
        $dat_additional_text .= "\nalarmID = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.2"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"})) {
        $dat_additional_text .= "\nneIdentity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.1"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"})) {
        $dat_additional_text .= "\nspecificProblem = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.6"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"})) {
        $dat_additional_text .= "\nprobableCause = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.5"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"})) {
        $dat_additional_text .= "\neventType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.4"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"})) {
        $dat_additional_text .= "\neventTime = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.10"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"})) {
        $dat_additional_text .= "\nadditionalInformation = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.9"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"})) {
        $dat_additional_text .= "\nnotificationType = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.3"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"})) {
        $dat_additional_text .= "\nperceivedSeverity = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.7"} . ",\n";
    }
    if (ifexists($entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"})) {
        $dat_additional_text .= "\nadditionalText = " . $entrada->{"1.3.6.1.4.1.20858.10.104.101.1.8"} . ",\n";
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
