package ABR::CorrectiveFilter;
# Version=6.0
use warnings;
use strict;

use ABR::HashOrder;

sub ifexists
{
 my $variable = shift;
 if (defined $variable && $variable ne ""){
   return 1;
 } else {
   return 0;
 }
}

# Constructor

sub new {
  my $class = shift;
  my $args;
  my $self;

  $args  = {@_};
  $self = { splitFilter1 => $args -> {split_filter1}, splitFilter2 => $args -> {split_filter2} };
  return bless $self,$class;
}

sub ProcessingCF{
  my $self = shift;
  my ($hash_field,$hashref_fc,$action,$cascade) = @_;
  my @splitted_1;
  my @splitted_2;
  my $OrigAddTxt = $hash_field -> {"AddTxt"};
  my $logic      =  1;
  my $blocking   = "";
  my $output     = "";
  # my $valueMem = "";

  #print "Metodo ProcessingCF\n";
  #print "MO:"            . $hash_field -> {"MO"}     . "\n";
  #print "AddTxt:"        . $hash_field -> {"AddTxt"} . "\n";
  #print "PS:"            . $hash_field -> {"PS"}     . "\n";
  #print "Action:"        . $action                   . "\n";
  #print "Cascade:"            . $cascade     . "\n";
  #print "splitFilter1: " . $self -> {splitFilter1}   . "\n";
  #print "splitFilter2: " . $self -> {splitFilter2}   . "\n";
  # print "----------------------------------------------------------------\n";
  if ($action eq "SetGrupos") {
    # print "Action: " . $action . "\n";
    return DirectSetGrupos($hash_field,$hashref_fc);
  }

  if (ifexists $hashref_fc) {
    foreach my $Filter (@{$hashref_fc -> keys}) {
      @splitted_1 = split($self -> {splitFilter1}, $hashref_fc -> get($Filter));
      foreach my $line(@splitted_1){
        @splitted_2 = split($self -> {splitFilter2},$line);
        # print $Filter . " -> Param:" . $splitted_2[0] . ", Oper: " . $splitted_2[1] . ", Val: \"" . $splitted_2[2] . "\"\n";
        if(($splitted_2[0] ne "Action") && ($splitted_2[0] ne "SetIncidentType") && ($splitted_2[0] ne "SetUserText") && ($splitted_2[0] ne "SetGrupos")){
          # print "Diferente de Action\n";
          # print $Filter . " -> Param:" . $splitted_2[0] . ", Oper: " . $splitted_2[1] . ", Val: \"" . $splitted_2[2] . "\"\n";
          $logic = $logic & Operations($splitted_2[0],$splitted_2[1],$splitted_2[2],$hash_field);
        }
        elsif(($splitted_2[0] eq "SetIncidentType") || ($splitted_2[0] eq "SetUserText") || ($splitted_2[0] eq "SetGrupos")){
          if( $splitted_2[1] eq "IsPresent" ){
            # my $l = IsPresent($action,$splitted_2[2],$hash_field);
            # print "Logica del IsPresent CorrectiveFilter: " . $l . "\n";
            $logic = $logic & IsPresent($action,$splitted_2[2],$hash_field);
          }
        }
        else{
          # print $Filter . " -> Param:" . $splitted_2[0] . ", Oper: " . $splitted_2[1] . ", Val: \"" . $splitted_2[2] . "\"\n";
          if   ($splitted_2[1] eq $action   ){
            # print "Esto " . $splitted_2[1] . " es igual a " . $action ."\n";
            # print $Filter . " -> " . $splitted_2[0] . ", Oper: " . $splitted_2[1] . ", Val: \"" . $splitted_2[2] . "\"\n";
            $output = ActionReview($splitted_2[0],$splitted_2[1],$splitted_2[2],$hash_field,$OrigAddTxt,$cascade);
          }
          elsif($splitted_2[1] eq "Blocking"){
            # print "Blocking\n";
            # print $Filter . " -> " . $splitted_2[0] . ", Oper: " . $splitted_2[1] . ", Value: \"" . $splitted_2[2] . "\"\n";
            $output = ActionFalse($action, $hash_field);
            # print "Logica para Blocking: " . $logic . "\n";
            if($logic){$blocking = $splitted_2[2];}
          }
          else{$logic = 0;}
        }
      }

      if($logic){
        # print "Logic           : " . $logic    . " => True\n";
        # print "Blocking Value  : " . $blocking . "\n";
        if($blocking eq "" || $Filter !~ /$blocking\_\d+$/){
          # print "Value Assign    : " . $output   . "\n";
          # print "No Blocking Filter: " . $Filter . "\n";
          ######################################
          ############## Cascade ###############
          ######################################
          if(ifexists $cascade){
        print "INFO:" . $cascade . "\n";
            if($cascade eq "NonCascade"){
              return $output;
            }
          }
          ######################################
          ############# Assignment #############
          ######################################
          if   ($action eq "PrependAdditionalText"){
            $hash_field -> {"AddTxt"} = $output;
          }
          elsif($action eq "SetEventSeverity"){
            $hash_field -> {"PS"} = $output;
          }
          elsif($action eq "SetGrupos"){
            $hash_field -> {"AddTxt"} = $output;
          }
          elsif($action eq "SetIncidentType"){
            $hash_field -> {"AddTxt"} = $output;
          }
          elsif($action eq "SetUserText"){
            $hash_field -> {"AddTxt"} = $output;
          }
          elsif($action eq "SetEventManagedObject"){
            $hash_field -> {"MO"} = $output;
          }
          # else{
            # if(ifexists $action){
              # print "[WARNING]: Invalid action \"" . $action . "\" in the Corrective Filter";

              #
            # }
            # else{
              # print "[WARNING]: Action is "empty" in the Corrective Filter";

            # }
          # }
          # return $output;
        }
        # else{print "Blocking Filter: " . $Filter . "\n";}

      }else{
        # print "Logic         : " . $logic                            . " => False\n";
        # print "Blocking Value: " . $blocking                         . "\n";
        # print "Value Assign  : " . ActionFalse($action, $hash_field) . "\n";
        # print "Filter Skip   : " . $Filter                           . "\n";
        $logic = 1;

      }
      # print "----------------------------------------------------------------\n";
    }
    return ActionFalse($action, $hash_field);
  }
  else{
    return ActionFalse($action, $hash_field);
  }
}

################################################################################
################################## SetGrupos ###################################
################################################################################
sub DirectSetGrupos {
  # my $self = shift;
  my ($hash_field,$hashref_fc) = @_;
  my $var_mo     = "";
  my $var_output = "";
  # print "MO:"            . $hash_field -> {"MO"}     . "\n";
  if($hash_field -> {"MO"} =~ /"(.*)"/){$var_mo=$1;}
  # print "var = $var_mo\n";
  if(ifexists($var_mo))
  {
    $var_output = $hashref_fc->get($var_mo);
    # print "var_output = $var_output\n\n";
    if(ifexists($var_output)){return $hash_field -> {"AddTxt"} . " SetGrupos=" . $var_output . ";\$\$";}
  }
  # print "----------------------------------------------------------------\n\n";

  return $hash_field -> {"AddTxt"};
}

################################################################################
################################### Actions ####################################
################################################################################
sub ActionReview{
  my $param         = shift;
  my $oper          = shift;
  my $value         = shift;
  my $HashTextAlarm = shift;
  my $addtxt        = shift;
  my $cascade       = shift;
  my $Output        = "";
  # print "Funcion ActionReview\n";
  # print "Action: " . $param . "\n";
  # print "Oper  : " . $oper  . "\n";
  if($param eq "Action"){
    if($oper =~ "PrependAdditionalText"){
      # print "Oper  : " . $oper                        . "\n";
      # print "AddTxt: " . $HashTextAlarm -> {"AddTxt"} . "\n";
      if($value =~ /^".*"/){
        $value =~ s/"//g;
      }
      if(ifexists $HashTextAlarm -> {"AddTxt"}){$Output = $value . $HashTextAlarm -> {"AddTxt"};}
      else{$Output = $value;}
      return $Output;
    }
    elsif($oper =~ "SetEventSeverity"){
      # print "Oper: " . $oper                    . "\n";
      # print "PS  : " . $HashTextAlarm -> {"PS"} . "\n";
      $Output = $value;
      return $Output;
    }
    elsif($oper =~ "SetIncidentType"){
      # print "Estoy en SetIncidentType\n";
      # print "Oper: "   . $oper . "Add " . $value . " to AddTxt\n";
      if($value =~ /^".*"/){
        $value =~ s/"//g;
      }

      if(ifexists $HashTextAlarm -> {"AddTxt"}){
        if($HashTextAlarm -> {"AddTxt"} =~ /SetIncidentType=.*;\$\$/){

          if(ifexists $cascade){

            if($cascade eq "NonCascade"){
              $Output = $addtxt;
              $Output =~ s/ SetIncidentType=.*?;\$\$/ SetIncidentType=$value;\$\$/;
            }
            else{
              $Output = $addtxt;
            }

          }else{
            $Output = $addtxt . " SetIncidentType=" . $value . ";\$\$";
          }

        }else{
          $Output = $HashTextAlarm -> {"AddTxt"} . " SetIncidentType=" . $value . ";\$\$";
        }
      }
      else{$Output = " SetIncidentType=" . $value . ";\$\$";}

      return $Output;
    }
    elsif($oper =~ "SetUserText"){
      # print "Oper: "   . $oper . "Add " . $value . " to AddTxt\n";
      if($value =~ /^".*"/){
        $value =~ s/"//g;
      }

      if(ifexists $HashTextAlarm -> {"AddTxt"}){

        if($HashTextAlarm -> {"AddTxt"} =~ /SetUserText=.*;\$\$/){

          if(ifexists $cascade){

            if($cascade eq "NonCascade"){
              $Output = $addtxt;
              $Output =~ s/ SetUserText=.*?;\$\$/ SetUserText=$value;\$\$/;
            }
            else{
              $Output = $addtxt;
            }

          }else{
            $Output = $addtxt . " SetUserText=" . $value . ";\$\$";
          }
        }
        else{
          $Output = $HashTextAlarm -> {"AddTxt"} . " SetUserText=" . $value . ";\$\$";
        }

      }
      else{$Output = " SetUserText=" . $value . ";\$\$";}

      return $Output;
    }
    elsif($oper =~ "SetGrupos"){
      # print "Oper: "   . $oper . "Add " . $value . " to AddTxt\n";
      if($value =~ /^".*"/){
        $value =~ s/"//g;
      }

      if(ifexists $HashTextAlarm -> {"AddTxt"}){

        if($HashTextAlarm -> {"AddTxt"} =~ /SetGrupos=.*;\$\$/){

          if(ifexists $cascade){

            if($cascade eq "NonCascade"){
              $Output = $addtxt;
              $Output =~ s/ SetGrupos=.*?;\$\$/ SetGrupos=$value;\$\$/;
            }
            else{
              $Output = $addtxt;
            }

          }else{
            $Output = $addtxt . " SetGrupos=" . $value . ";\$\$";
          }

        }
        else{
          $Output = $HashTextAlarm -> {"AddTxt"} . " SetGrupos=" . $value . ";\$\$";
        }

      }
      else{$Output = " SetGrupos=" . $value . ";\$\$";}

      return $Output;
    }
    elsif($oper =~ "SetEventManagedObject"){
      # print "Oper: "   . $oper                        . "\n";
      # print "MO: " . $HashTextAlarm -> {"MO"} . "\n";
      if($value =~ /^".*"/){
        $value =~ s/"//g;
      }
      $Output = $value;
      return $Output;
    }
  }
}

sub ActionFalse{
  my $oper          = shift;
  my $HashTextAlarm = shift;
  # print "Funcion ActionFalse\n";
  # print "Oper  : " . $oper  . "\n";
  if($oper =~ "PrependAdditionalText"){
    return $HashTextAlarm -> {"AddTxt"};
  }
  elsif($oper =~ "SetEventSeverity"){
    return $HashTextAlarm -> {"PS"};
  }
  elsif($oper =~ "SetIncidentType"){
    return $HashTextAlarm -> {"AddTxt"};
  }
  elsif($oper =~ "SetUserText"){
    return $HashTextAlarm -> {"AddTxt"};
  }
  elsif($oper =~ "SetGrupos"){
    return $HashTextAlarm -> {"AddTxt"};
  }
  elsif($oper =~ "SetEventManagedObject"){
    return $HashTextAlarm -> {"MO"};
  }
  # else{
    # # print "[ERROR]: The action"" . $oper . "\" is not identified.\n";

  # }
}


################################################################################
################################## Operations ##################################
################################################################################
sub IsPresent{
  my $oper          = shift;
  my $value         = shift;
  my $HashTextAlarm = shift;
  my $Output        = "";
  my $vl            = 1;
  if(ifexists $HashTextAlarm -> {"AddTxt"}){

    if   ($oper eq "SetGrupos"){
      # print "IsPresent: SetGrupos\n";
      $vl = functionMatch($HashTextAlarm -> {"AddTxt"},$value);
    }
    elsif($oper eq "SetIncidentType"){
      # print "IsPresent: SetIncidentType, Value: " . $value . "\n";
      $vl = functionMatch($HashTextAlarm -> {"AddTxt"},$value);
      # print "IsPresent: SetIncidentType, Value: " . $vl . "\n";
    }
    elsif($oper eq "SetUserText"){
      # print "IsPresent: SetUserText\n";
      $vl = functionMatch($HashTextAlarm -> {"AddTxt"},$value);
    }
    else{
      $vl = 0;
    }

  }else{
    $vl = 0;
  }

  return $vl;
}

sub Operations{
  my $param         = shift;
  my $oper          = shift;
  my $value         = shift;
  my $HashTextAlarm = shift;
  my $var           = "";
  my $vl            = 1;
  if($param eq "AddTxt"){
    if(ifexists $HashTextAlarm -> {"AddTxt"}){
      if($oper eq "match"){
        $vl = functionMatch($HashTextAlarm -> {"AddTxt"},$value);
      }elsif($oper eq "equal"){
        $vl = functionEqual($HashTextAlarm -> {"AddTxt"},$value);
      }
    }else{
      $vl = 0;
    }
  }
  elsif($param eq "MO"){
    if(ifexists $HashTextAlarm -> {"MO"}) {
      if($oper eq "match"){
        $vl = functionMatch($HashTextAlarm -> {"MO"},$value);
      }elsif($oper eq "equal"){
        $var = $HashTextAlarm -> {"MO"};
        $var =~ s/^"//;
        $var =~ s/"$//;
        $vl  = functionEqual($var,$value);
      }
    }else{
      $vl = 0;
    }

  }
  elsif($param eq "PS"){
    if(isInteger($HashTextAlarm -> {"PS"})){
      if($oper eq "eq"){
        $vl = functionEq($value,$HashTextAlarm -> {"PS"});
        # print "Logica eq: $vl\n";
      }
      elsif($oper eq "ne"){
        $vl = functionNe($value,$HashTextAlarm -> {"PS"});
        # print "Logica ne: $vl\n";
      }elsif($oper eq "lt"){
        $vl = PSlt($value,$HashTextAlarm -> {"PS"});
        # print "Logica lt: $vl\n";
      }elsif($oper eq "gt"){
        $vl = PSgt($value,$HashTextAlarm -> {"PS"});
        # print "Logica gt: $vl\n";
      }elsif($oper eq "le"){
        $vl = PSle($value,$HashTextAlarm -> {"PS"});
        # print "Logica le: $vl\n";
      }elsif($oper eq "ge"){
        $vl = PSge($value,$HashTextAlarm -> {"PS"});
        # print "Logica ge: $vl\n";
      }
    }else{
      $vl = 0;
    }
  }
  elsif($param eq "PC"){
    if(isInteger($HashTextAlarm -> {"PC"})){
      if($oper eq "eq"){
        $vl = functionEq($value,$HashTextAlarm -> {"PC"});
      }
      elsif($oper eq "ne"){
        $vl = functionNe($value,$HashTextAlarm -> {"PC"});
      }elsif($oper eq "lt"){
        $vl = functionLt($value,$HashTextAlarm -> {"PC"});
      }elsif($oper eq "gt"){
        $vl = functionGt($value,$HashTextAlarm -> {"PC"});
      }elsif($oper eq "le"){
        $vl = functionLe($value,$HashTextAlarm -> {"PC"});
      }elsif($oper eq "ge"){
        $vl = functionGe($value,$HashTextAlarm -> {"PC"});
      }
    }else{
      $vl = 0;
    }
  }
  # print "Operation, Logic: " . $vl . "\n";
  return $vl;
}

################################################################################
################################## File Name ###################################
################################################################################

sub changeFileName{
  my $file = shift;
  if($file =~ /(.*)\.yes/){
    return "$1.no";
  }else{
    return "$file";
  }
}
################################################################################
############################# Comparison of String #############################
################################################################################

sub functionMatch{
  my $text  = shift;
  my $match = shift;
  my $l     = shift;
  eval{
    $l = ($text =~ /$match/);
    return $l;
  }or do{
    return 0;
  };
}

# sub functionMatch{
#   my $text  = shift;
#   my $match = shift;
#   if($text =~ /$match/){
#     return 1;
#   }else{
#     return 0;
#   }
# }

sub functionEqual{
  my $text  = shift;
  my $equal = shift;
  if($text eq $equal){
    return 1;
  }
  else{
    return 0;
  }
}

################################################################################
############################ Comparison of Numbers #############################
################################################################################

sub functionEq{
  my $val1 = shift;
  my $val2 = shift;
  if($val1 == $val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionNe{
  my $val1 = shift;
  my $val2 = shift;
  if($val1 != $val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionLt{
  my $val1 = shift;
  my $val2 = shift;
  if($val1 < $val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionGt{
  my $val1 = shift;
  my $val2 = shift;
  if($val1 > $val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionLe{
  my $val1 = shift;
  my $val2 = shift;
  if($val1 <= $val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionGe{
  my $val1 = shift;
  my $val2 = shift;
  if($val1 >= $val2){
    return 1;
  }else{
    return 0;
  }
}


################################################################################
########################### Comparison of Numbers PS ###########################
################################################################################

sub PSle{
  my $val1 = shift;
  my $val2 = shift;

  # print "val1 -> " . $val1 . " le val2 -> " . $val2 . "\n";

  if($val1 ne "5" and $val2 ne "5"){

    if($val2 eq "0"){
      # print ">> " . $val1 . " <= " . $val2 . " -> 1\n";
      return 1;
    }else{
      if($val1 eq "0"){
        # print ">> " . $val1 . " <= " . $val2 . " -> 0\n";
        return 0;
      }else{
        if($val1 <= $val2){
          # print ">> " . $val1 . " <= " . $val2 . " -> 1\n";
          return 1;
        }else{
          # print ">> " . $val1 . " <= " . $val2 . " -> 0\n";
          return 0;
        }
      }
    }

  }else{
    return 0;
  }

}

sub PSlt{
  my $val1 = shift;
  my $val2 = shift;

  # print "val1 -> " . $val1 . " lt val2 -> " . $val2 . "\n";

  if($val1 ne "5" and $val2 ne "5"){

    if($val2 eq "0"){
      if($val1 eq  "0"){
        return 0;
      }else{
        return 1;
      }
      # print ">> " . $val1 . " <= " . $val2 . " -> 1\n";
    }else{
      if($val1 eq "0"){
        # print ">> " . $val1 . " <= " . $val2 . " -> 0\n";
        return 0;
      }else{
        if($val1 < $val2){
          # print ">> " . $val1 . " <= " . $val2 . " -> 1\n";
          return 1;
        }else{
          # print ">> " . $val1 . " <= " . $val2 . " -> 0\n";
          return 0;
        }
      }
    }

  }else{
    return 0;
  }

}

sub PSge{
  my $val1 = shift;
  my $val2 = shift;

  # print "val1 -> " . $val1 . " ge val2 -> " . $val2 . "\n";

  if($val1 ne "5" and $val2 ne "5"){

    if($val1 eq "0"){
      # print ">> " . $val1 . " >= " . $val2 . " -> 1\n";
      return 1;
    }else{
      if($val2 eq "0"){
        # print ">> " . $val1 . " >= " . $val2 . " -> 1\n";
        return 0;
      }else{
        if($val1 >= $val2){
          # print ">> " . $val1 . " >= " . $val2 . " -> 1\n";
          return 1;
        }else{
          # print ">> " . $val1 . " >= " . $val2 . " -> 0\n";
          return 0;
        }
      }
    }

  }else{
    return 0;
  }

}

sub PSgt{
  my $val1 = shift;
  my $val2 = shift;

  # print "val1 -> " . $val1 . " gt val2 -> " . $val2 . "\n";

  if($val1 ne "5" and $val2 ne "5"){

    if($val1 eq "0"){
      # print ">> " . $val1 . " >= " . $val2 . " -> 1\n";
      return 0;
    }else{
      if($val2 eq "0"){
        # print ">> " . $val1 . " >= " . $val2 . " -> 1\n";
        return 0;
      }else{
        if($val1 > $val2){
          # print ">> " . $val1 . " >= " . $val2 . " -> 1\n";
          return 1;
        }else{
          # print ">> " . $val1 . " >= " . $val2 . " -> 0\n";
          return 0;
        }
      }
    }

  }else{
    return 0;
  }

}

################################################################################
#################################### Integer ###################################
################################################################################

sub isInteger{
  my $input = shift;
  if(ifexists $input){
    if($input !~ /\d+\.\d+/){
      if($input =~ /\d+/){
        # print "IsInteger: \"" . $input . "\"\n";
        return 1;
      }
      else{
        return 0;
      }
    }else{
     return 0;
    }
  }
  return 0;
}

1;

