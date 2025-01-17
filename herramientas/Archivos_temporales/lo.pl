package ABR::EXAMPLE;

use warnings;
use strict;
use Digest::MurmurHash qw(murmur_hash);

use ABR::llenaComun;
my $llena = ABR::llenaComun       -> new ();

use ABR::CorrectiveFilter;
my $cf    = ABR::CorrectiveFilter -> new (split_filter1 => '\<&&\>',split_filter2 => '\<\>');

my $dat_MO;

sub ifexists
{
 my $variable = shift;
 if (defined $variable && $variable ne ""){
   return 1;
 } else {
   return 0;
 }
}

# Managed Object Function
sub get_managed_object
{
my $hostname=shift;
my $agent_address=shift;
my $dat_managed_object=shift;
my $dat_MO = "";
   if (ifexists($hostname)) {
      if (ifexists $dat_managed_object )  {
          $dat_MO = $hostname . " " . $dat_managed_object;
       } else {
          $dat_MO = $hostname;
       }
   } elsif (ifexists $dat_managed_object) {
       $dat_MO = "HostND" . " " . $agent_address . " " . $dat_managed_object;
   } else {
       $dat_MO = "HostND" . " " . $agent_address;
   }
   if(ifexists $dat_MO){
     $dat_MO =~ s/"//g;
     $dat_MO = "\"" . $dat_MO . "\"";
   }
   return $dat_MO;
}

# Host Function
sub HostRegex{
  my $configHost_ref = shift;
  my $ip_address = shift;
  my $salida = "";
  if(ifexists $configHost_ref){
    foreach my $k($configHost_ref -> keys){
      # print "keys: " . $k . " ";
      if($ip_address =~ /$k/){
        # print "Hice Matc, Regex: " . $k . " Entrada: " . $ip_address . " Salida: " . $configHost{$k} . " ";
        $salida = $configHost_ref -> get($k);
      }
    }
  }
  return $salida;
}

# ifExistsAndNumber
sub ifExistsAndNumber
{
 my $variable = shift;
 if (defined $variable && $variable ne "" && $variable  =~ /^[-+]?[0-9]*\.?[0-9]+$/  ){
   return 1;
 } else {
   return 0;
 }
}

# AdditionalInfo Function
sub FuncAdditionalInfo{
  my $entrada = shift;
	my $tp_name = shift;
  my $add_info = " | AddInfo: trap name=" . $tp_name . ", ";
  my $c = 0;
  foreach my $k (keys %$entrada){
    $c = ($k eq "IPADDR") || ($k eq "EOID") || ($k eq "SPEC_TRAP") || ($k eq "GEN_TRAP") || ($k eq "1.3.6.1.2.1.1.3") || ($k eq "1.3.6.1.6.3.1.1.4.1");
    # print $c . "\n";
    if(!$c){
      # print  $k . "\n";
      if(ifexists $entrada -> {$k}){
        $add_info = $add_info . " " . $k . ": " . $entrada -> {$k} . ";";
      }
    }
  }
  return $add_info;
}

# Corrective Filter Function
sub CorrectiveFilter{
  my $hashAlarm_ref = shift;
  my $config_ref    = shift;
  my $action        = shift;
  my $var           = shift;
  my $c             = shift;
  my $output        = "";
  # print "Funcion CorrectiveFilter\n";
  # print "MO    : " . $hashAlarm_ref -> {"MO"}     . "\n";
  # print "AddTxt: " . $hashAlarm_ref -> {"AddTxt"} . "\n";
  # print "PS    : " . $hashAlarm_ref -> {"PS"}     . "\n";
  $output = $cf -> ProcessingCF($hashAlarm_ref,$config_ref,$action,$c);
  if(ifexists $output){
    return $output;
  }
  elsif($var =~ "MO"){
    return $hashAlarm_ref -> {"MO"};
  }
  elsif($var =~ "AddTxt"){
    return $hashAlarm_ref -> {"AddTxt"};
  }
  elsif($var =~ "PS"){
    return $hashAlarm_ref -> {"PS"};
  }
}

# Severity Function
sub trapSeverity
{
	my $vSeverity = shift;
	my $severity = "";
	if( $vSeverity eq "5"){$severity = "Clear";}
	if( $vSeverity eq "4"){$severity = "Critical";}
	if( $vSeverity eq "3"){$severity = "Major";}
	if( $vSeverity eq "1"){$severity = "Warning";}
	if( $vSeverity eq "0"){$severity = "Clear";}
  if( $vSeverity eq "2"){$severity = "Minor";}
	if( $vSeverity eq "6"){$severity = "0";}
	return $severity;
}


# neAlarm
sub _1_3_6_1_4_1_9070_1_2_1_1_14_24
{
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
  my $dat_event_time = $llena -> fecha();
  my $dat_notification_id = "";
  my $dat_correlated_notification_id = "";
  my $agent_address = $entrada -> {"IPADDR"};
  my $hostname = HostRegex($config{"HOST"},$agent_address);

  ######################################################################################
  ######################### Inicia la personalizacion del trap #########################
  ######################################################################################

  # Severity
	# trapSeverity
	if(ifexists $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.6"}){
		$dat_severity = trapSeverity($entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.6"});
		$dat_severity = $config{"ExternalMap"} -> get($dat_severity);
	}

	# Specific Problem
	# conditionType
	if(ifexists $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.5"}){
		$dat_specific_problem = murmur_hash( $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.5"});
	}

	# AdditionalText
	$dat_additional_text = "";
	# message
	if(ifexists $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.8"}){
		if(ifexists $dat_additional_text){
			$dat_additional_text = $dat_additional_text . " " . $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.8"};
		}else{$dat_additional_text = $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.8"};}
	}
	# eventNeAddress
	if(ifexists $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.4"}){
		if(ifexists $dat_additional_text){
			$dat_additional_text = $dat_additional_text . "| NodeIP: " . $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.4"};
		}else{$dat_additional_text = "| NodeIP: " . $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.4"};}
	}
  # AdditionalInfo - funcion que agrega todos los varbinds en el additional text
  $dat_additional_text = $dat_additional_text . FuncAdditionalInfo($entrada,$trap_name);

  $dat_managed_object = " TEST \"TEMPLATE_AGEN_V3\"";

  #########################################################################################
  #########################  Finaliza la personalizacion del trap #########################
  #########################################################################################

  #---------------------------------- MO ----------------------------------
  $dat_MO=get_managed_object($hostname,$agent_address,$dat_managed_object);

#----------------------------------------------------------------------------- Procesing Corrective Filter -----------------------------------------------------------------------------

#                                       {<------------------------- Hash Alarm ------------------------------->} {<-------------- Key Hash MAP -------------->} {<------ Action ----->} {<Var Name>}
$dat_additional_text = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_SetIncidentType"                 },"SetIncidentType"      ,"AddTTxt");
$dat_additional_text = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_SetIncidentType_NonCascade"      },"SetIncidentType"      ,"AddTTxt","NonCascade");
$dat_additional_text = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_SetGrupos"                       },"SetGrupos"            ,"AddTTxt","NonCascade");
$dat_additional_text = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_SetUserText"                     },"SetUserText"          ,"AddTTxt");
$dat_additional_text = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_PrependAdditionalText"           },"PrependAdditionalText","AddTTxt");
$dat_additional_text = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_PrependAdditionalText_NonCascade"},"PrependAdditionalText","AddTTxt","NonCascade");
$dat_severity        = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_SetEventSeverity"                },"SetEventSeverity"     ,"PS"     );

  #------------------------------------------------------------------------- Procesing Corrective Filter Finished -------------------------------------------------------------------------


  $llena -> llenaMO  ( "MO:"     .  $dat_MO               ) if (ifexists $dat_MO              );
  $llena -> llenaPC  ( "PC:"     .  $dat_probable_cause   ) if (ifexists $dat_probable_cause  );
  $llena -> llenaPS  ( "PS:"     .  $dat_severity         ) if (ifexists $dat_severity        );
  $llena -> llenaSP  ( "SP:"     .  $dat_specific_problem ) if (ifexists $dat_specific_problem);
  $llena -> llenaNI  ( "NID:"    .  $dat_notification_id  ) if (ifexists $dat_notification_id );
  $llena -> llenaAT  ( "AddTxt:" .  $dat_additional_text  ) if (ifexists $dat_additional_text );
  $llena -> EventTime( "ETime:"  .  $dat_event_time       ) if (ifexists $dat_event_time      );
  $llena -> EventType( "EType:"  .  $dat_event_type       ) if (ifexists $dat_event_type      );

  $alarm_txt = ${ $llena -> { mensaje_x733 } };
  $llena -> vacia_mensaje_x733();
  $alarm_txt = "###START###" . $alarm_txt . "###END###";

  return $alarm_txt;
}

# neEvent
sub _1_3_6_1_4_1_9070_1_2_1_1_14_25
{
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
  my $dat_event_time = $llena -> fecha();
  my $dat_notification_id = "";
  my $dat_correlated_notification_id = "";
  my $agent_address = $entrada -> {"IPADDR"};
  my $hostname = HostRegex($config{"HOST"},$agent_address);

  ######################################################################################
  ######################### Inicia la personalizacion del trap #########################
  ######################################################################################

  # Severity
	# trapSeverity
	if(ifexists $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.6"}){
		$dat_severity = trapSeverity($entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.6"});
		$dat_severity = $config{"ExternalMap"} -> get($dat_severity);
	}

  # Specific Problem
	# conditionType
	if(ifexists $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.5"}){
		$dat_specific_problem = murmur_hash( $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.5"});
	}

	# AdditionalText
	$dat_additional_text = "";
	# message
	if(ifexists $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.8"}){
		if(ifexists $dat_additional_text){
			$dat_additional_text = $dat_additional_text . " " . $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.8"};
		}else{$dat_additional_text = $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.8"};}
	}
	# eventNeAddress
	if(ifexists $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.4"}){
		if(ifexists $dat_additional_text){
			$dat_additional_text = $dat_additional_text . "| NodeIP: " . $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.4"};
		}else{$dat_additional_text = "| NodeIP: " . $entrada -> {"1.3.6.1.4.1.9070.1.2.1.1.14.4"};}
	}
  # AdditionalInfo - funcion que agrega todos los varbinds en el additional text
  $dat_additional_text = $dat_additional_text . FuncAdditionalInfo($entrada,$trap_name);

  $dat_managed_object = " TEST \"TEMPLATE_AGEN_V3\"";

  #########################################################################################
  #########################  Finaliza la personalizacion del trap #########################
  #########################################################################################

  #--------------------------------- MO ---------------------------------
  $dat_MO=get_managed_object($hostname,$agent_address,$dat_managed_object);

  #----------------------------------------------------------------------------- Procesing Corrective Filter -----------------------------------------------------------------------------

  #                                       {<------------------------- Hash Alarm ------------------------------->} {<-------------- Key Hash MAP -------------->} {<------ Action ----->} {<Var Name>}
  $dat_additional_text = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_SetIncidentType"                 },"SetIncidentType"      ,"AddTTxt");
  $dat_additional_text = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_SetIncidentType_NonCascade"      },"SetIncidentType"      ,"AddTTxt","NonCascade");
  $dat_additional_text = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_SetGrupos"                       },"SetGrupos"            ,"AddTTxt","NonCascade");
  $dat_additional_text = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_SetUserText"                     },"SetUserText"          ,"AddTTxt");
  $dat_additional_text = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_PrependAdditionalText"           },"PrependAdditionalText","AddTTxt");
  $dat_additional_text = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_PrependAdditionalText_NonCascade"},"PrependAdditionalText","AddTTxt","NonCascade");
  $dat_severity        = CorrectiveFilter({"MO" => $dat_MO,"AddTxt" => $dat_additional_text,"PS" => $dat_severity},$config{"FC_SetEventSeverity"                },"SetEventSeverity"     ,"PS"     );

  #------------------------------------------------------------------------- Procesing Corrective Filter Finished -------------------------------------------------------------------------


  $llena -> llenaMO  ( "MO:"     .  $dat_MO               ) if (ifexists $dat_MO              );
  $llena -> llenaPC  ( "PC:"     .  $dat_probable_cause   ) if (ifexists $dat_probable_cause  );
  $llena -> llenaPS  ( "PS:"     .  $dat_severity         ) if (ifexists $dat_severity        );
  $llena -> llenaSP  ( "SP:"     .  $dat_specific_problem ) if (ifexists $dat_specific_problem);
  $llena -> llenaNI  ( "NID:"    .  $dat_notification_id  ) if (ifexists $dat_notification_id );
  $llena -> llenaAT  ( "AddTxt:" .  $dat_additional_text  ) if (ifexists $dat_additional_text );
  $llena -> EventTime( "ETime:"  .  $dat_event_time       ) if (ifexists $dat_event_time      );
  $llena -> EventType( "EType:"  .  $dat_event_type       ) if (ifexists $dat_event_type      );

  $alarm_txt = ${ $llena -> { mensaje_x733 } };
  $llena -> vacia_mensaje_x733();
  $alarm_txt = "###START###" . $alarm_txt . "###END###";

  return $alarm_txt;
}

1;
