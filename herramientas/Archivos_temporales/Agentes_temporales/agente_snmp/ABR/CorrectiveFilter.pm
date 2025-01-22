package ABR::CorrectiveFilter;
# Version=6.0
use warnings;
use strict;

use ABR::HashOrder;

sub ifexists {
    my $variable = shift;
    if (defined $variable && $variable ne "") {
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
    $self = { splitFilter1 => $args->{split_filter1}, splitFilter2 => $args->{split_filter2} };
    return bless $self, $class;
}

sub ProcessingCF {
    my $self = shift;
    my ($hash_field, $hashref_fc, $action, $cascade) = @_;
    my @splitted_1;
    my @splitted_2;
    my $OrigAddTxt = $hash_field->{"AddTxt"};
    my $logic      =  1;
    my $blocking   = "";
    my $output     = "";

    if ($action eq "SetGrupos") {
        return DirectSetGrupos($hash_field, $hashref_fc);
    }

    if (ifexists $hashref_fc) {
        foreach my $Filter (@{$hashref_fc->keys}) {
            @splitted_1 = split($self->{splitFilter1}, $hashref_fc->get($Filter));
            foreach my $line (@splitted_1) {
                @splitted_2 = split($self->{splitFilter2}, $line);
                if (($splitted_2[0] ne "Action") && ($splitted_2[0] ne "SetIncidentType") && ($splitted_2[0] ne "SetUserText") && ($splitted_2[0] ne "SetGrupos")) {
                    $logic = $logic & Operations($splitted_2[0], $splitted_2[1], $splitted_2[2], $hash_field);
                } elsif (($splitted_2[0] eq "SetIncidentType") || ($splitted_2[0] eq "SetUserText") || ($splitted_2[0] eq "SetGrupos")) {
                    if ($splitted_2[1] eq "IsPresent") {
                        $logic = $logic & IsPresent($action, $splitted_2[2], $hash_field);
                    }
                } else {
                    if ($splitted_2[1] eq $action) {
                        $output = ActionReview($splitted_2[0], $splitted_2[1], $splitted_2[2], $hash_field, $OrigAddTxt, $cascade);
                    } elsif ($splitted_2[1] eq "Blocking") {
                        $output = ActionFalse($action, $hash_field);
                        if ($logic) { $blocking = $splitted_2[2]; }
                    } else { $logic = 0; }
                }
            }

            if ($logic) {
                if ($blocking eq "" || $Filter !~ /$blocking\_\d+$/) {
                    if (ifexists $cascade) {
                        if ($cascade eq "NonCascade") {
                            return $output;
                        }
                    }
                    if ($action eq "PrependAdditionalText") {
                        $hash_field->{"AddTxt"} = $output;
                    } elsif ($action eq "SetEventSeverity") {
                        $hash_field->{"PS"} = $output;
                    } elsif ($action eq "SetGrupos") {
                        $hash_field->{"AddTxt"} = $output;
                    } elsif ($action eq "SetIncidentType") {
                        $hash_field->{"AddTxt"} = $output;
                    } elsif ($action eq "SetUserText") {
                        $hash_field->{"AddTxt"} = $output;
                    } elsif ($action eq "SetEventManagedObject") {
                        $hash_field->{"MO"} = $output;
                    }
                }
            } else {
                $logic = 1;
            }
        }
        return ActionFalse($action, $hash_field);
    } else {
        return ActionFalse($action, $hash_field);
    }
}

sub DirectSetGrupos {
    my ($hash_field, $hashref_fc) = @_;
    my $var_mo     = "";
    my $var_output = "";
    if ($hash_field->{"MO"} =~ /"(.*)"/) { $var_mo = $1; }
    if (ifexists $var_mo) {
        $var_output = $hashref_fc->get($var_mo);
        if (ifexists $var_output) { return $hash_field->{"AddTxt"} . " SetGrupos=" . $var_output . ";$$"; }
    }
    return $hash_field->{"AddTxt"};
}

sub ActionReview {
    my ($param, $oper, $value, $HashTextAlarm, $addtxt, $cascade) = @_;
    my $Output = "";
    if ($param eq "Action") {
        if ($oper =~ "PrependAdditionalText") {
            if ($value =~ /^".*"/) {
                $value =~ s/"//g;
            }
            if (ifexists $HashTextAlarm->{"AddTxt"}) { $Output = $value . $HashTextAlarm->{"AddTxt"}; }
            else { $Output = $value; }
            return $Output;
        } elsif ($oper =~ "SetEventSeverity") {
            $Output = $value;
            return $Output;
        } elsif ($oper =~ "SetIncidentType") {
            if ($value =~ /^".*"/) {
                $value =~ s/"//g;
            }
            if (ifexists $HashTextAlarm->{"AddTxt"}) {
                if ($HashTextAlarm->{"AddTxt"} =~ /SetIncidentType=.*;$$/) {
                    if (ifexists $cascade) {
                        if ($cascade eq "NonCascade") {
                            $Output = $addtxt;
                            $Output =~ s/ SetIncidentType=.*?;$$/ SetIncidentType=$value;$$/;
                        } else {
                            $Output = $addtxt;
                        }
                    } else {
                        $Output = $addtxt . " SetIncidentType=" . $value . ";$$";
                    }
                } else {
                    $Output = $HashTextAlarm->{"AddTxt"} . " SetIncidentType=" . $value . ";$$";
                }
            } else { $Output = " SetIncidentType=" . $value . ";$$"; }
            return $Output;
        } elsif ($oper =~ "SetUserText") {
            if ($value =~ /^".*"/) {
                $value =~ s/"//g;
            }
            if (ifexists $HashTextAlarm->{"AddTxt"}) {
                if ($HashTextAlarm->{"AddTxt"} =~ /SetUserText=.*;$$/) {
                    if (ifexists $cascade) {
                        if ($cascade eq "NonCascade") {
                            $Output = $addtxt;
                            $Output =~ s/ SetUserText=.*?;$$/ SetUserText=$value;$$/;
                        } else {
                            $Output = $addtxt;
                        }
                    } else {
                        $Output = $addtxt . " SetUserText=" . $value . ";$$";
                    }
                } else {
                    $Output = $HashTextAlarm->{"AddTxt"} . " SetUserText=" . $value . ";$$";
                }
            } else { $Output = " SetUserText=" . $value . ";$$"; }
            return $Output;
        } elsif ($oper =~ "SetGrupos") {
            if ($value =~ /^".*"/) {
                $value =~ s/"//g;
            }
            if (ifexists $HashTextAlarm->{"AddTxt"}) {
                if ($HashTextAlarm->{"AddTxt"} =~ /SetGrupos=.*;$$/) {
                    if (ifexists $cascade) {
                        if ($cascade eq "NonCascade") {
                            $Output = $addtxt;
                            $Output =~ s/ SetGrupos=.*?;$$/ SetGrupos=$value;$$/;
                        } else {
                            $Output = $addtxt;
                        }
                    } else {
                        $Output = $addtxt . " SetGrupos=" . $value . ";$$";
                    }
                } else {
                    $Output = $HashTextAlarm->{"AddTxt"} . " SetGrupos=" . $value . ";$$";
                }
            } else { $Output = " SetGrupos=" . $value . ";$$"; }
            return $Output;
        } elsif ($oper =~ "SetEventManagedObject") {
            if ($value =~ /^".*"/) {
                $value =~ s/"//g;
            }
            $Output = $value;
            return $Output;
        }
    }
}

sub ActionFalse {
    my ($oper, $HashTextAlarm) = @_;
    if ($oper =~ "PrependAdditionalText") {
        return $HashTextAlarm->{"AddTxt"};
    } elsif ($oper =~ "SetEventSeverity") {
        return $HashTextAlarm->{"PS"};
    } elsif ($oper =~ "SetIncidentType") {
        return $HashTextAlarm->{"AddTxt"};
    } elsif ($oper =~ "SetUserText") {
        return $HashTextAlarm->{"AddTxt"};
    } elsif ($oper =~ "SetGrupos") {
        return $HashTextAlarm->{"AddTxt"};
    } elsif ($oper =~ "SetEventManagedObject") {
        return $HashTextAlarm->{"MO"};
    }
}

sub IsPresent {
    my ($oper, $value, $HashTextAlarm) = @_;
    my $Output = "";
    my $vl     = 1;
    if (ifexists $HashTextAlarm->{"AddTxt"}) {
        if ($oper eq "SetGrupos") {
            $vl = functionMatch($HashTextAlarm->{"AddTxt"}, $value);
        } elsif ($oper eq "SetIncidentType") {
            $vl = functionMatch($HashTextAlarm->{"AddTxt"}, $value);
        } elsif ($oper eq "SetUserText") {
            $vl = functionMatch($HashTextAlarm->{"AddTxt"}, $value);
        } else {
            $vl = 0;
        }
    } else {
        $vl = 0;
    }
    return $vl;
}

sub Operations {
    my ($param, $oper, $value, $HashTextAlarm) = @_;
    my $var = "";
    my $vl  = 1;
    if ($param eq "AddTxt") {
        if (ifexists $HashTextAlarm->{"AddTxt"}) {
            if ($oper eq "match") {
                $vl = functionMatch($HashTextAlarm->{"AddTxt"}, $value);
            } elsif ($oper eq "equal") {
                $vl = functionEqual($HashTextAlarm->{"AddTxt"}, $value);
            }
        } else {
            $vl = 0;
        }
    } elsif ($param eq "MO") {
        if (ifexists $HashTextAlarm->{"MO"}) {
            if (ifexists $HashTextAlarm->{"MO"}) {
                if ($oper eq "match") {
                    $vl = functionMatch($HashTextAlarm->{"MO"}, $value);
                } elsif ($oper eq "equal") {
                    $vl = functionEqual($HashTextAlarm->{"MO"}, $value);
                }
            } else {
                $vl = 0;
            }
        } elsif ($param eq "PS") {
            if (ifexists $HashTextAlarm->{"PS"}) {
                if ($oper eq "match") {
                    $vl = functionMatch($HashTextAlarm->{"PS"}, $value);
                } elsif ($oper eq "equal") {
                    $vl = functionEqual($HashTextAlarm->{"PS"}, $value);
                }
            } else {
                $vl = 0;
            }
        }
        return $vl;
    }
}

sub functionMatch {
    my ($var, $value) = @_;
    if ($var =~ /\Q$value\E/) {
        return 1;
    } else {
        return 0;
    }
}

sub functionEqual {
    my ($var, $value) = @_;
    if ($var eq $value) {
        return 1;
    } else {
        return 0;
    }
}

sub functionEq {
    my ($val1, $val2) = @_;
    return $val1 == $val2 ? 1 : 0;
}

sub functionNe {
    my ($val1, $val2) = @_;
    return $val1 != $val2 ? 1 : 0;
}

sub functionLt {
    my ($val1, $val2) = @_;
    return $val1 < $val2 ? 1 : 0;
}

sub functionGt {
    my ($val1, $val2) = @_;
    return $val1 > $val2 ? 1 : 0;
}

sub functionLe {
    my ($val1, $val2) = @_;
    return $val1 <= $val2 ? 1 : 0;
}

sub functionGe {
    my ($val1, $val2) = @_;
    return $val1 >= $val2 ? 1 : 0;
}

sub PSle {
    my ($val1, $val2) = @_;
    return 0 if $val1 eq "5" or $val2 eq "5";
    return 1 if $val2 eq "0";
    return 0 if $val1 eq "0";
    return $val1 <= $val2 ? 1 : 0;
}

sub PSlt {
    my ($val1, $val2) = @_;
    return 0 if $val1 eq "5" or $val2 eq "5";
    return $val1 eq "0" ? 0 : $val2 eq "0" ? 1 : $val1 < $val2 ? 1 : 0;
}

sub PSge {
    my ($val1, $val2) = @_;
    return 0 if $val1 eq "5" or $val2 eq "5";
    return $val1 eq "0" ? 1 : $val2 eq "0" ? 0 : $val1 >= $val2 ? 1 : 0;
}

sub PSgt {
    my ($val1, $val2) = @_;
    return 0 if $val1 eq "5" or $val2 eq "5";
    return $val1 eq "0" || $val2 eq "0" ? 0 : $val1 > $val2 ? 1 : 0;
}

sub isInteger {
    my $input = shift;
    return 0 unless ifexists($input);
    return 0 if $input =~ /d+.d+/;
    return $input =~ /d+/ ? 1 : 0;
}

1;
