package ABR::SNMPAgente;
# Version=1.1
use warnings;
use strict;
use Net::SNMPTrapd;
use Sys::Hostname;

sub new {
    my $local_address;
    my $local_port;
    my $self;
    my @args = @_;
    my $class = $args[0];
    if($#args > 1) {
        $local_address = $args[1];
        $local_port = $args[2];
    } else {
        $local_port = 3434;
        my $hostname = "10.152.74.250";
        ( my $nombre, my $alias, my $addr_tipo, my $largo, my @direcciones )= gethostbyname($hostname);
        ( my $a, my $e, my $i, my $o )  = unpack("C4", $direcciones[0]);
        $local_address = $a . "." . $e . "." . $i ."." . $o;
    }

    my $snmptrapd = Net::SNMPTrapd -> new( -LocalAddr=>$local_address, -LocalPort=>$local_port, -timeout=>1);

    if(!defined($snmptrapd)) {
        exit(1);
    } else {
      $self = bless({ snmptrapd => $snmptrapd }, $class);
    }

    return $self;
}

sub get_trap {
    my $self     = shift;
    my $onPrints = shift;
    my $trap;
    my $trap_version;

    $trap = $self -> { snmptrapd } -> get_trap();

    if (!defined($trap)) {
        exit 1;
    } elsif ($trap == 0) {
        undef($trap);
        return $trap;
    }

    if (!defined($trap->process_trap())) {
        undef($trap);
        return $trap;
    } else {
        $trap_version = $trap->version();
        if($trap_version == 1) {
          $self -> processV1($trap,$onPrints);
        } elsif ($trap_version == 2) {
          $self -> processV2($trap,$onPrints);
        }
    }
}

sub processV1 {
    my @trap_array;
    my $self              = shift;
    my $trap              = shift;
    my $onPrints          = shift;
    my $remoteaddr        = $trap -> agentaddr();
    my $arreglo_varbind   = $trap -> varbinds();
    my @varbinds          = @{$arreglo_varbind};
    my $remoteaddr_ref    = { "IPADDR" => $remoteaddr };
    my $e_oid             = $trap -> ent_OID();
    my $gen_trap          = $trap -> generic_trap();
    my $gen_trap_ref      = { "GEN_TRAP" => $gen_trap };
    my $spec_trap         = $trap -> specific_trap();
    my $spec_trap_ref     = { "SPEC_TRAP" => $spec_trap };
    my $trap_oid_complete = $e_oid . ".0."  . $spec_trap;
    my $e_oid_ref         = { "EOID" => $trap_oid_complete };

    unshift(@varbinds, $spec_trap_ref);
    unshift(@varbinds, $gen_trap_ref);
    unshift(@varbinds, $e_oid_ref);
    unshift(@varbinds, $remoteaddr_ref);

    for my $vals (@varbinds) {
        foreach(keys(%$vals)) {
            push(@trap_array, $vals->{$_});
        }
    }

    return @varbinds;
}

sub processV2 {
    my @trap_array;
    my $self            = shift;
    my $trap            = shift;
    my $onPrints        = shift;
    my $remoteaddr      = $trap -> remoteaddr();
    my $remoteaddr_ref  = { IPADDR => $remoteaddr };
    my $arreglo_varbind = $trap -> varbinds();
    my @varbinds        = @{$arreglo_varbind};
    my $gen_trap_ref    = { "GEN_TRAP" => "" };
    my $spec_trap_ref   = { "SPEC_TRAP" => "" };
    my $bandera         = 0;
    my $e_oid;
    my $e_oid_ref;

    externo: for my $vals (@$arreglo_varbind) {
        foreach(keys(%$vals)) {
            if($_ eq "1.3.6.1.6.3.1.1.4.1.0") {
                $e_oid = $vals -> {$_};
                $e_oid_ref = { "EOID" => $e_oid };
                if($bandera == 1) {
                    last externo;
                }
                $bandera = 1;
            }

            if($_ eq "1.3.6.1.6.3.18.1.3.0") {
                $remoteaddr = $vals -> {$_};
                $remoteaddr_ref = { "IPADDR" => $remoteaddr };
                if($bandera == 1) {
                    last externo;
                }
                $bandera = 1;
            }
        }
    }

    unshift(@varbinds, $gen_trap_ref);
    unshift(@varbinds, $spec_trap_ref);
    unshift(@varbinds, $e_oid_ref);
    unshift(@varbinds, $remoteaddr_ref);

    for my $vals (@varbinds) {
        foreach(keys(%$vals)) {
        }
    }

    return @varbinds;
}

1;
