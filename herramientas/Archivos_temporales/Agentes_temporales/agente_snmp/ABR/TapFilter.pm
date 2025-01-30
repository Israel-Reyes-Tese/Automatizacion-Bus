
package ABR::TapFilter;
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
  my $config_index;
  my $match_text;
  my %hash_filter; # Filter
  my $hash_ref;
  my %hash_check_operation = ("AddTxt"          => ["match","equal"],
                              "MO"              => ["match","equal"],
                              "PS"              => ["eq","ne","lt","gt","le","ge"],
                              "PC"              => ["eq","ne","lt","gt","le","ge"],
                              "Action"          => ["Blocking","Passing"],
                              "SetGrupos"       => ["IsPresent"],
                              "SetUserText"     => ["IsPresent"],
                              "SetIncidentType" => ["IsPresent"]);
  my $hashOrdered          = ABR::HashOrder -> new();
  my $stausFileFilter      = 0;
  my $Error                = 1;
  my $InfoErrors           = "";
  my %filter_read;
  my @array;
  my @splitted_1;
  my @splitted_2;

  $args     = {@_};
  $hash_ref = $args -> {hash_ref};
  @array    = split(',',$args -> {config_index});
  print "\n------------------ Cargando y verificando sintaxis del filtro ------------------\n";
  eval{
  foreach my $FilterName (@array) {
    foreach my $index (keys %{$hash_ref}) {
      if($index eq $FilterName){
        $hashOrdered = ${$hash_ref}{$index};
        my $SF = ABR::HashOrder -> new(); # Subfilter HashOrder
        foreach my $subFilter (@{$hashOrdered -> keys}) {
          if($hashOrdered -> get($subFilter) !~ /.*Action\<\>Blocking|Passing\<\>.*/){
            my $rW = "";
            if($subFilter =~ m/(.*)_\d+$/){
              $rW = $hashOrdered -> get($subFilter) . "<&&>Action<>Blocking<>" . $1;
              $hashOrdered -> set($subFilter => $rW);
            }
          }
          @splitted_1 = split($args -> {split_filter1},$hashOrdered -> get($subFilter));
          foreach my $item(@splitted_1){
            @splitted_2 = split($args -> {split_filter2},$item);
            if($hash_check_operation{$splitted_2[0]}){
              foreach(@{$hash_check_operation{$splitted_2[0]}}){
                if($splitted_2[1] eq $_){
                  if($splitted_2[0] eq "PS"){
                    if(!(isInteger($splitted_2[2]))){
                      $InfoErrors = "Error in the file " . $FilterName . " and Index " . $subFilter . ": No accepted value \"" . $splitted_2[2] . "\" in \"" . $splitted_2[0] . "\" -> " . $hashOrdered -> get($subFilter) . "\n";
                      die;
                    }
                    else{
                      if(($splitted_2[2] eq "5") or ($splitted_2[2] eq "1") or ($splitted_2[2] eq "2") or ($splitted_2[2] eq "3") or ($splitted_2[2] eq "4") or ($splitted_2[2] eq "0")){
                        if($splitted_2[2] eq "5"){
                          print "[WARN]: In the file " . $FilterName . " and Index " . $subFilter . ":\n";
                          print "[WARN]: " . $hashOrdered -> get($subFilter) . ",\n";
                          print "[WARN]: you used severity \"5 -> Clear\" on this filter, check that it's not on a blocking filter or that the operation is different of \"eq\".\n";
                        }
                      }
                      else{
                        $InfoErrors = "Error in the file " . $FilterName . " and Index " . $subFilter . ": No accepted value \"" . $splitted_2[2] . "\" in \"" . $splitted_2[0] . "\" -> " . $hashOrdered -> get($subFilter) . "\n";
                        die;
                      }
                    }
                  }
                  elsif( $splitted_2[0] eq "PC"){
                    if(!(isInteger($splitted_2[2]))){
                      $InfoErrors = "Error in the file " . $FilterName . " and Index " . $subFilter . ": No accepted value \"" . $splitted_2[2] . "\" in \"" . $splitted_2[0] . "\" -> " . $hashOrdered -> get($subFilter) . "\n";
                      die;
                    }
                  }
                  else{
                    if(!(ifexists $splitted_2[2])){
                      $InfoErrors = "Error in the file " . $FilterName . " and Index " . $subFilter . ": value is empty\"" . $splitted_2[2] . "\" in \"" . $splitted_2[0] . "\" -> " . $hashOrdered -> get($subFilter) . "\n";
                      die;
                    }
                  }
                  $Error = 0;
                }
              }
              if($Error){
                $InfoErrors = "Error in the file " . $FilterName . " and Index " . $subFilter . ": No accepted operation \"" . $splitted_2[1] . "\" in \"" . $splitted_2[0] . "\" -> " . $hashOrdered -> get($subFilter) . "\n";
                die;
              }
              $Error = 1;
            }else{
              $InfoErrors = "Error in the file " . $FilterName . " and Index " . $subFilter . ": No accepted parameter \"" . $splitted_2[0] . "\" -> " . $hashOrdered -> get($subFilter) . "\n";
              die;
            }
          }
          $SF -> set($subFilter => [@splitted_1] );
          $hash_filter{$FilterName} = $SF;
        }
        $stausFileFilter = $stausFileFilter | 1;
      }else{
        $stausFileFilter = $stausFileFilter | 0;
      }
    }
  }
  print ">> No hay Errores de sintaxis en el filtro de bloqueo\n";
  print "--------------------------------------------------------------------------------\n\n";
}or do{
  die "[ERR ]: TapFilter.pm, " . $InfoErrors;
};

  $self = { hash_filter => \%hash_filter, status => $stausFileFilter, match_text => $match_text, separator => $args -> {split_filter2} };
  return bless $self,$class;
}



sub ProcessingFilters{
  my $self            = shift;
  my $textAlarm       = shift;
  my $file_Alarm      = shift;
  my $filter_read_ref = $self -> {hash_filter};
  my $stausFileFilter = $self -> {status};
  my $separator       = $self -> {separator};
  my %hash_ref_filter = %$filter_read_ref;
  my $matchText       = "";
  my $SubFbefore      = "";
  my $PFString        = "NULL";
  my $hash_ref;
  my @splitted;
  my $logic           = 1;
  my $BF              = 0;
  my $PF              = 0;
  my $statusPF        = 0;
  if ($stausFileFilter) {
    $hash_ref = ProcessingTextAlarm($textAlarm);
    foreach my $filter (keys %hash_ref_filter) {
      foreach my $subFilter (@{$hash_ref_filter{$filter} -> keys}) {
        if($subFilter !~ /$PFString\_\d+$/ ){
          if(ifexists $SubFbefore){
            if($subFilter !~ /$SubFbefore\_\d+$/){
              if(($PF eq 0) and ($statusPF eq 1)){
                return changeFileName($file_Alarm);
              }
              $PF       = 0;
              $statusPF = 0;
            }
          }
          foreach my $val ( @{$hash_ref_filter{$filter} -> get($subFilter)} ) {
            @splitted = split($separator,$val);
            if( $splitted[0] ne 'Action' && ($splitted[0] ne "SetIncidentType") && ($splitted[0] ne "SetUserText") && ($splitted[0] ne "SetGrupos") ){
              $logic = $logic & Operations($splitted[0],$splitted[1],$splitted[2],$hash_ref);
            }
            elsif(($splitted[0] eq "SetIncidentType") || ($splitted[0] eq "SetUserText") || ($splitted[0] eq "SetGrupos")){
              if( $splitted[1] eq "IsPresent" ){
                $logic = $logic & IsPresent($splitted[0],$splitted[2],$hash_ref);
              }
            }
            elsif( $splitted[1] eq 'Blocking' ){
              $BF         = $logic;
              $SubFbefore = $splitted[2];
            }
            elsif( $splitted[1] eq 'Passing' ){
              $PF       = $logic;
              $PFString = $splitted[2];
              $statusPF = 1;
            }
            if($logic){
              $matchText = $matchText ."[INFO]: Filter: " . $filter . "->" . $subFilter . ":
[INFO]: Parameter: " . $splitted[0] . ", Operation: " . $splitted[1] . ", Value: " . $splitted[2] . "
";
            }else{
              $matchText = "";
            }
          }
          if($BF){
            $self -> {match_text} = $matchText;
            return changeFileName($file_Alarm);
          }else{
            if($PF){
              $self -> {match_text} = "";
              $logic = 1;
              $BF    = 0;
            }
            else{
              $self -> {match_text} = "";
              $PFString             = "NULL";
              $logic = 1;
              $BF    = 0;
            }
          }
        }
      }
    }
    if(($PF eq 0) and ($statusPF eq 1)){
      return changeFileName($file_Alarm);
    }
    $PF       = 0;
    $statusPF = 0;
  }
  return "$file_Alarm";
}

sub IsPresent{
  my $oper          = shift;
  my $value         = shift;
  my $HashTextAlarm = shift;
  my $vl            = 1;
  if(ifexists $HashTextAlarm -> {"AddTxt"}){
    if   ($oper eq "SetGrupos"){
      $vl = functionMatch($HashTextAlarm -> {"AddTxt"},$value);
    }
    elsif($oper eq "SetIncidentType"){
      $vl = functionMatch($HashTextAlarm -> {"AddTxt"},$value);
    }
    elsif($oper eq "SetUserText"){
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
        my $var = "";
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
      }
      elsif($oper eq "ne"){
        $vl = functionNe($value,$HashTextAlarm -> {"PS"});
      }elsif($oper eq "lt"){
        $vl = PSlt($value,$HashTextAlarm -> {"PS"});
      }elsif($oper eq "gt"){
        $vl = PSgt($value,$HashTextAlarm -> {"PS"});
      }elsif($oper eq "le"){
        $vl = PSle($value,$HashTextAlarm -> {"PS"});
      }elsif($oper eq "ge"){
        $vl = PSge($value,$HashTextAlarm -> {"PS"});
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
  return $vl;
}
################################################################################
############################ Processing Text Alarm #############################
################################################################################

sub ProcessingTextAlarm{
  # print "\nProcessingTextAlarm\n";
  my $textAlarm = shift;
  my @s1;
  my %hash_alarm;
  $textAlarm =~ s/###START###//g;
  $textAlarm =~ s/###END###//g;
  $textAlarm =~ s/\n/ /g;
  # print "$textAlarm\n";
  @s1 = split('#\$\%','$textAlarm');
  foreach my $i1(@s1){
    if($i1 =~ /(\w+):(.*)/){
      # print "$1 -> $2\n";
      $hash_alarm{$1} = $2;
    }
  }
  # print "\n\n";
  return \%hash_alarm;
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
#   # print "functionMatch\n";
#   my $text  = shift;
#   my $match = shift;
#   if($text =~ /$match/){
#     # print "matc:$text , $match\n\n";
#     return 1;
#   }else{
#     return 0;
#   }
# }

sub functionEqual{
  # print "functionEqual";
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

################################################################################
############################## Print alarm matches #############################
################################################################################

sub PrintFilterConditionFulfilled{
  my $self  = shift;
  my $match = $self -> {match_text};

  if($match){
    print "[INFO]: filter conditions fulfilled:\n$match\n";
  }
  else{
    print "[INFO]: No filter conditions fulfilled\n\n";
  }
}

1;
