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

# eriAlarmXWarning
sub _1_3_6_1_4_1_193_183_6_2_0_2 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alarm state with severity warning. The notification is also used to change severity, additional text and/or additional info of an alarm. The eriAlarmXNObjRecordType varbind will indicate whether this is a new alarm instance or a change to an existing alarm instance. The combination of YangNodeInstance and  MajorType/MinorType is always unique and can be used by management systems to correlate alarm, alarm change, and alarm clear. A corresponding row will be created in the Alarm Table, (eriAlarmXActiveAlarmTable). The sequence number will increase for every notification and can be used to detect lost notifications. A management system should be prepared for appending text to additional text, indicated by the eriAlarmXNObjMoreAdditionalText varbind, and sent with eriAlarmXAppendInfo. (Note do not confuse this with a change of additional text.) A management system should be prepared for appending text to additional info, indicated by the eriAlarmXNObjMoreAdditionalInfo varbind, and sent with eriAlarmXAppendInfo.  (Note do not confuse this with a change of additional info.) A management system should also be prepared to receive a resource ID (OID) identifying the alarming resource if the system sending the notification can provide that information.  In that case, eriAlarmXNObjResourceId will be set to 'true' and the resource ID will be sent in an eriAlarmXAppendInfo notification.\nTrapName = eriAlarmXWarning,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1300";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a cleared alarm state. The combination of YangNodeInstance and MajorType/MinorType is always unique and shall be used by management systems to correlate alarm and alarm clear.  The corresponding row in the alarm table will be deleted, (eriAlarmXActiveAlarmTable). The sequence number will increase for every notification and can be used to detect lost notifications.  Note that it should not be required to send an append trap for a cleared alarm. Those varbinds which flag that an append trap will follow are  kept here for backward compatibility reasons.\nTrapName = eriAlarmXCleared,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1301";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alarm state with severity critical. The notification is also used to change severity, additional text and/or additional info of an alarm. The eriAlarmNObjRecordType varbind will indicate whether this is a new alarm instance or a change to an existing alarm instance. The combination of ManagedObject and MajorType/MinorType is always unique and can used by management systems to correlate alarm, alarm change, and alarm clear. A corresponding row will be created in the Alarm Table, (eriAlarmActiveAlarmTable). The sequence number will increase for every notification and can be used to detect lost notifications. A management system should be prepared for appending text to additional text, indicated by the eriAlarmNObjMoreAdditionalText varbind, and sent with eriAlarmAppendInfo. (Note do not confuse this with a change of additional text.) A management system should be prepared for appending text to additional info, indicated by the eriAlarmNObjMoreAdditionalInfo varbind, and sent with eriAlarmAppendInfo. (Note do not confuse this with a change of additional info.) A management system should also be prepared to receive a resource ID (OID) identifying the alarming resource if the system sending the notification can provide that information. In that case, eriAlarmNObjResourceId will be set to 'true' and the resource ID will be sent in an eriAlarmAppendInfo notification.\nTrapName = eriAlarmCritical,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1302";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a cleared alarm state. The combination of ManagedObject and MajorType/MinorType is always unique and shall be used by management systems to correlate alarm and alarm clear. The corresponding row in the alarm table will be deleted, (eriAlarmActiveAlarmTable). The sequence number will increase for every notification and can be used to detect lost notifications. Note that it should not be required to send an append trap for a cleared alarm. Those varbinds which flag that an append trap will follow are kept here for backward compatibility reasons.\nTrapName = eriAlarmCleared,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1303";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

# eriAlarmAppendAlertInfo
sub _1_3_6_1_4_1_193_183_4_2_0_15 {
    my $entrada = shift;
    my $trap_name = shift;
    my $config_ref = shift;
    my %config = %$config_ref;
    my $alarm_txt;

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent in order to append further info to an alert notification. It might be additional text or a resource ID (OID) identifying the alarming resource using an OID. This complements information sent in a previous notification. If additional text/info is sent, do not confuse this with an actual change of additional text/info which is reported using the eriAlarmAlert<severity> notification. A zero-length string value for eriAlarmNObjAdditionalText means that no additional text is being sent in this notification. A zero-length string value for eriAlarmNObjAppendedAdditionalInfo means that no additional info is being sent in this notification. A null OID (0.0) value for eriAlarmAlertResourceId means that no resource ID is being sent in this notification.\nTrapName = eriAlarmAppendAlertInfo,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1304";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent in order to append further info to an alarm notification. It might be additional text, additional info or a resource ID (OID) identifying the alarming resource using an OID. If additional text/info is sent, do not confuse this with an actual change of additional text/info which is reported using the eriAlarm<severity> notification. A zero-length string value for eriAlarmNObjAdditionalText means that no additional text is being sent in this notification. A zero-length string value for eriAlarmNObjAppendedAdditionalInfo means that no appended additional info is being sent in this notification. A null OID (0.0) value for eriAlarmActiveResourceId means that no resource ID is being sent in this notification.\nTrapName = eriAlarmAppendInfo,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1305";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alarm state with severity major. The notification is also used to change severity, additional text and/or additional info of an alarm. The eriAlarmXNObjRecordType varbind will indicate whether this is a new alarm instance or a change to an existing alarm instance. The combination of YangNodeInstance and  MajorType/MinorType is always unique and can be used by management systems to correlate alarm, alarm change, and alarm clear. A corresponding row will be created in the Alarm Table, (eriAlarmXActiveAlarmTable). The sequence number will increase for every notification and can be used to detect lost notifications. A management system should be prepared for appending text to additional text, indicated by the eriAlarmXNObjMoreAdditionalText varbind, and sent with eriAlarmXAppendInfo. (Note do not confuse this with a change of additional text.) A management system should be prepared for appending text to additional info, indicated by the eriAlarmXNObjMoreAdditionalInfo varbind, and sent with eriAlarmXAppendInfo.  (Note do not confuse this with a change of additional info.) A management system should also be prepared to receive a resource ID (OID) identifying the alarming resource if the system sending the notification can provide that information.  In that case, eriAlarmXNObjResourceId will be set to 'true' and the resource ID will be sent in an eriAlarmXAppendInfo notification.\nTrapName = eriAlarmXMajor,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1306";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alert with severity indeterminate. A corresponding row will be created in the Alert Table. The sequence number will increase for every notification and can be used to detect lost notifications.\nTrapName = eriAlarmIndAlert,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1307";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alert with severity warning. A corresponding row will be created in the Alert Table. The sequence number will increase for every notification and can be used to detect lost notifications.\nTrapName = eriAlarmXWarnAlert,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1308";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alarm state with severity minor. The notification is also used to change severity, additional text and/or additional info of an alarm. The eriAlarmXNObjRecordType varbind will indicate whether this is a new alarm instance or a change to an existing alarm instance. The combination of YangNodeInstance and  MajorType/MinorType is always unique and can be used by management systems to correlate alarm, alarm change, and alarm clear. A corresponding row will be created in the Alarm Table, (eriAlarmXActiveAlarmTable). The sequence number will increase for every notification and can be used to detect lost notifications. A management system should be prepared for appending text to additional text, indicated by the eriAlarmXNObjMoreAdditionalText varbind, and sent with eriAlarmXAppendInfo. (Note do not confuse this with a change of additional text.) A management system should be prepared for appending text to additional info, indicated by the eriAlarmXNObjMoreAdditionalInfo varbind, and sent with eriAlarmXAppendInfo.  (Note do not confuse this with a change of additional info.) A management system should also be prepared to receive a resource ID (OID) identifying the alarming resource if the system sending the notification can provide that information.  In that case, eriAlarmXNObjResourceId will be set to 'true' and the resource ID will be sent in an eriAlarmXAppendInfo notification.\nTrapName = eriAlarmXMinor,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1309";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alert with severity indeterminate. A corresponding row will be created in the Alert Table. The sequence number will increase for every notification and can be used to detect lost notifications.\nTrapName = eriAlarmXIndAlert,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1310";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alarm state with severity major. The notification is also used to change severity, additional text and/or additional info of an alarm. The eriAlarmNObjRecordType varbind will indicate whether this is a new alarm instance or a change to an existing alarm instance. The combination of ManagedObject and MajorType/MinorType is always unique and can used by management systems to correlate alarm, alarm change, and alarm clear. A corresponding row will be created in the Alarm Table, (eriAlarmActiveAlarmTable). The sequence number will increase for every notification and can be used to detect lost notifications. A management system should be prepared for appending text to additional text, indicated by the eriAlarmNObjMoreAdditionalText varbind, and sent with eriAlarmAppendInfo. (Note do not confuse this with a change of additional text.) A management system should be prepared for appending text to additional info, indicated by the eriAlarmNObjMoreAdditionalInfo varbind, and sent with eriAlarmAppendInfo. (Note do not confuse this with a change of additional info.) A management system should also be prepared to receive a resource ID (OID) identifying the alarming resource if the system sending the notification can provide that information. In that case, eriAlarmNObjResourceId will be set to 'true' and the resource ID will be sent in an eriAlarmAppendInfo notification.\nTrapName = eriAlarmMajor,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1311";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alarm state with severity minor. The notification is also used to change severity, additional text and/or additional info of an alarm. The eriAlarmNObjRecordType varbind will indicate whether this is a new alarm instance or a change to an existing alarm instance. The combination of ManagedObject and MajorType/MinorType is always unique and can used by management systems to correlate alarm, alarm change, and alarm clear. A corresponding row will be created in the Alarm Table, (eriAlarmActiveAlarmTable). The sequence number will increase for every notification and can be used to detect lost notifications. A management system should be prepared for appending text to additional text, indicated by the eriAlarmNObjMoreAdditionalText varbind, and sent with eriAlarmAppendInfo. (Note do not confuse this with a change of additional text.) A management system should be prepared for appending text to additional info, indicated by the eriAlarmNObjMoreAdditionalInfo varbind, and sent with eriAlarmAppendInfo. (Note do not confuse this with a change of additional info.) A management system should also be prepared to receive a resource ID (OID) identifying the alarming resource if the system sending the notification can provide that information. In that case, eriAlarmNObjResourceId will be set to 'true' and the resource ID will be sent in an eriAlarmAppendInfo notification.\nTrapName = eriAlarmMinor,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1312";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alert with severity critical. A corresponding row will be created in the Alert Table. The sequence number will increase for every notification and can be used to detect lost notifications.\nTrapName = eriAlarmCriticalAlert,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1313";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This is a heartbeat notification with interval according to the eriAlarmHbInterval. It contains the last sequence numbers used for alarms and alarm events. These varbinds can be used to detect lost notifications. The notification eriAlarmHeartBeatNotif will be sent every eriAlarmHbInterval. Managers can subscribe to the notification using the SNMP framework MIBS by using the snmpNotifyName 'heartbeat'. (SNMP-NOTIFICATION-MIB, snmpNotifyTable).\nTrapName = eriAlarmHeartBeatNotif,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1314";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alarm state with severity critical. The notification is also used to change severity, additional text and/or additional info of an alarm. The eriAlarmXNObjRecordType varbind will indicate whether this is a new alarm instance or a change to an existing alarm instance. The combination of YangNodeInstance and  MajorType/MinorType is always unique and can be used by management systems to correlate alarm, alarm change, and alarm clear. A corresponding row will be created in the Alarm Table, (eriAlarmXActiveAlarmTable). The sequence number will increase for every notification and can be used to detect lost notifications. A management system should be prepared for appending text to additional text, indicated by the eriAlarmXNObjMoreAdditionalText varbind, and sent with eriAlarmXAppendInfo. (Note do not confuse this with a change of additional text.) A management system should be prepared for appending text to additional info, indicated by the eriAlarmXNObjMoreAdditionalInfo varbind, and sent with eriAlarmXAppendInfo.  (Note do not confuse this with a change of additional info.) A management system should also be prepared to receive a resource ID (OID) identifying the alarming resource if the system sending the notification can provide that information.  In that case, eriAlarmXNObjResourceId will be set to 'true' and the resource ID will be sent in an eriAlarmXAppendInfo notification.\nTrapName = eriAlarmXCritical,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1315";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This is a heartbeat notification with interval according to the eriAlarmXHbInterval. It contains the last sequence numbers used for alarms and alarm events. These varbinds can be used to detect lost notifications. The notification eriAlarmXHeartBeatNotif will be sent every eriAlarmXHbInterval. Managers can subscribe to the notification using the SNMP framework MIBS by using the snmpNotifyName 'heartbeat'. (SNMP-NOTIFICATION-MIB, snmpNotifyTable).\nTrapName = eriAlarmXHeartBeatNotif,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1316";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alarm state with severity indeterminate. The notification is also used to change severity, additional text and/or additional  info of an alarm. The eriAlarmXNObjRecordType varbind will indicate whether this is a new alarm instance or a change to an existing alarm instance. The combination of YangNodeInstance  and MajorType/MinorType is always unique and can be used by management systems to correlate alarm, alarm change, and alarm clear. A corresponding row will be created in the Alarm Table. The sequence number will increase for every notification and can be used to detect lost notifications. A management system should be prepared for appending text to additional text, indicated by the eriAlarmXNObjMoreAdditionalText varbind, and sent with eriAlarmXAppendInfo.  (Note do not confuse this with a change of additional text.) A management system should be prepared for appending text to additional info, indicated by the eriAlarmXNObjMoreAdditionalInfo varbind, and sent with eriAlarmXAppendInfo.  (Note do not confuse this with a change of additional info.) A management system should also be prepared to receive a resource ID (OID) identifying the alarming resource if the system sending the notification can provide that information.  In that case, eriAlarmXNObjResourceId will be set to 'true' and the resource ID will be sent in an eriAlarmXAppendInfo notification.\nTrapName = eriAlarmXIndeterminate,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1317";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alert with severity minor. A corresponding row will be created in the Alert Table. The sequence number will increase for every notification and can be used to detect lost notifications.\nTrapName = eriAlarmMinorAlert,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1318";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alert with severity major. A corresponding row will be created in the Alert Table. The sequence number will increase for every notification and can be used to detect lost notifications.\nTrapName = eriAlarmMajorAlert,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1319";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent in order to append further info to an alarm notification. It might be additional text, additional info or a resource ID  (OID) identifying the alarming resource using an OID. If additional text/info is sent, do not confuse this with an actual change of additional text/info which  is reported using the eriAlarmX<severity> notification.  A zero-length string value for eriAlarmXNObjAdditionalText means that no additional text is being sent in this notification. A zero-length string value for eriAlarmXNObjAppendedAdditionalInfo means that no additional info is being sent in this notification. A null OID (0.0) value for eriAlarmXActiveResourceId means that no resource ID is being sent in this notification.\nTrapName = eriAlarmXAppendInfo,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1320";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alarm state with severity warning. The notification is also used to change severity, additional text and/or additional info of an alarm. The eriAlarmNObjRecordType varbind will indicate whether this is a new alarm instance or a change to an existing alarm instance. The combination of ManagedObject and MajorType/MinorType is always unique and can used by management systems to correlate alarm, alarm change, and alarm clear. A corresponding row will be created in the Alarm Table, (eriAlarmActiveAlarmTable). The sequence number will increase for every notification and can be used to detect lost notifications. A management system should be prepared for appending text to additional text, indicated by the eriAlarmNObjMoreAdditionalText varbind, and sent with eriAlarmAppendInfo. (Note do not confuse this with a change of additional text.) A management system should be prepared for appending text to additional info, indicated by the eriAlarmNObjMoreAdditionalInfo varbind, and sent with eriAlarmAppendInfo. (Note do not confuse this with a change of additional info.) A management system should also be prepared to receive a resource ID (OID) identifying the alarming resource if the system sending the notification can provide that information. In that case, eriAlarmNObjResourceId will be set to 'true' and the resource ID will be sent in an eriAlarmAppendInfo notification.\nTrapName = eriAlarmWarning,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1321";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alert with severity warning. A corresponding row will be created in the Alert Table. The sequence number will increase for every notification and can be used to detect lost notifications.\nTrapName = eriAlarmWarnAlert,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1322";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alert with severity minor. A corresponding row will be created in the Alert Table. The sequence number will increase for every notification and can be used to detect lost notifications.\nTrapName = eriAlarmXMinorAlert,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1323";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alert with severity major. A corresponding row will be created in the Alert Table. The sequence number will increase for every notification and can be used to detect lost notifications.\nTrapName = eriAlarmXMajorAlert,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1324";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alert with severity critical. A corresponding row will be created in the Alert Table. The sequence number will increase for every notification and can be used to detect lost notifications.\nTrapName = eriAlarmXCriticalAlert,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1325";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent in order to append further info to an alert notification. It might be additional text or a resource ID (OID) identifying the alarming resource using an OID. This complements information sent in a previous notification. If additional text/info is sent, do not confuse this with an actual change of additional text/info which is reported using the eriAlarmXAlert<severity> notification. A zero-length string value for eriAlarmXNObjAdditionalText means that no additional text is being sent in this notification. A zero-length string value for eriAlarmXNObjAppendedAdditionalInfo means that no additional info is being sent in this notification. A null OID (0.0) value for eriAlarmXAlertResourceId means that no resource ID is being sent in this notification.\nTrapName = eriAlarmXAppendAlertInfo,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1326";
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

    my $dat_severity = "2";
    my $dat_specific_problem = "0";
    my $dat_probable_cause = "0";
    my $dat_event_type = "10";
    my $dat_managed_object = get_managed_object($hostname, $agent_address, $mo);;
    my $dat_additional_text = "This notification is sent when a resource detects a new alarm state with severity indeterminate. The notification is also used to change severity, additional text and/or additional info of an alarm. The eriAlarmNObjRecordType varbind will indicate whether this is a new alarm instance or a change to an existing alarm instance. The combination of ManagedObject and MajorType/MinorType is always unique and can be used by management systems to correlate alarm, alarm change, and alarm clear. A corresponding row will be created in the Alarm Table. The sequence number will increase for every notification and can be used to detect lost notifications. A management system should be prepared for appending text to additional text, indicated by the eriAlarmNObjMoreAdditionalText varbind, and sent with eriAlarmAppendInfo. (Note do not confuse this with a change of additional text.) A management system should be prepared for appending text to additional info, indicated by the eriAlarmNObjMoreAdditionalInfo varbind, and sent with eriAlarmAppendInfo. (Note do not confuse this with a change of additional info.) A management system should also be prepared to receive a resource ID (OID) identifying the alarming resource if the system sending the notification can provide that information. In that case, eriAlarmNObjResourceId will be set to 'true' and the resource ID will be sent in an eriAlarmAppendInfo notification.\nTrapName = eriAlarmIndeterminate,\n";
    
    my $dat_event_time = $llena->fecha();
    my $dat_notification_id = "1327";
    my $dat_correlated_notification_id = "";
    my $agent_address = $entrada->{"IPADDR"};
    my $hostname = HostRegex($config{"HOST"}, $agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

