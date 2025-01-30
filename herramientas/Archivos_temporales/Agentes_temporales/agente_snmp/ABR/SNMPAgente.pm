package ABR::SNMPAgente;
# Version=1.1
use warnings;
use strict;
use Net::SNMPTrapd;
use Sys::Hostname;
# use Net::SNMP;

# use parent "Net::SNMPTrapd";

sub new
{
    my $local_address;
    my $local_port;
    my $self;
    my @args = @_;
    my $class = $args[0];
    if($#args > 1)
    {
        $local_address = $args[1];
        $local_port = $args[2];
    }
    else
    {
        #$local_port = 10462;
    $local_port = 3434;
    #$local_port = 2271;
        #my $hostname = hostname() ;
    my $hostname = "10.152.74.249";
    #my $hostname = "100.127.5.81";
        print "EL HOSTNAME ES: $hostname\n";

        ( my $nombre, my $alias, my $addr_tipo, my $largo, my @direcciones )= gethostbyname($hostname);

        ( my $a, my $e, my $i, my $o )  = unpack("C4", $direcciones[0]);
        $local_address = $a . "." . $e . "." . $i ."." . $o;
    }

    print "LA DIRECCION LOCAL ES: $local_address\n";
    print "EL PUERTO LOCAL ES: $local_port\n";

    my $snmptrapd = Net::SNMPTrapd -> new( -LocalAddr=>$local_address, -LocalPort=>$local_port, -timeout=>1);

    if(!defined($snmptrapd))
    {
        print "There has been an error while openning the specified port: $local_port on address: $local_address.\n";
        print Net::SNMPTrapd -> error();
        exit(1);
    }
    else
    {
      $self = bless({ snmptrapd => $snmptrapd }, $class);
    }

    return $self;
}

sub get_trap
{
    my $self     = shift;
    my $onPrints = shift;
    my $trap;
    my $trap_version;

    $trap = $self -> { snmptrapd } -> get_trap();

    if (!defined($trap))
    {
        printf "$0: %s\n", Net::SNMPTrapd->error();
        print  "There is a problem with the trap reception\n";
        exit 1;
    }
    elsif ($trap == 0)
    {
    #    print "Trap value is zero, returning....\n";
        undef($trap);
        return $trap;
    }

    #JEMM_Comentario de impresiones
    #print "ESTOY ANTES DE PROCESAR EL TRAP\n";
    if (!defined($trap->process_trap()))
    {
        printf "$0: %s\n", Net::SNMPTrapd->error();
        print "There is a problem, processin the trap within the library\n";
        undef($trap);
        return $trap;
    }
    else
    {
        $trap_version = $trap->version();
#         printf "%s	%i	%i	%s\n", $trap->remoteaddr(), $trap->remoteport(), $trap_version, $trap->community();
        if($trap_version == 1)
        {
          if($onPrints){print "ESTE TRAP ES VERSION 1\n";}
          $self -> processV1($trap,$onPrints);
        }
        elsif ($trap_version == 2)
        {
          if($onPrints){print "ESTE TRAP ES VERSION 2\n";}
          $self -> processV2($trap,$onPrints);
        }
    }
}

sub processV1
{
    my @trap_array;
    my $self              = shift;
    my $trap              = shift;
    my $onPrints          = shift;
    # my $remoteaddr       = $trap -> remoteaddr();
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

    if($onPrints){
      print "The SNMP V1 Gen Trap is: $e_oid\n";
      print "The SNMP V1 Spec Trap is: $spec_trap\n";
      print "The complete trap OID is: $trap_oid_complete\n";
    }

        for my $vals (@varbinds)
        {
            foreach(keys(%$vals))
            {
                if($onPrints){print "EL OID ES: $_" . " EL VALOR DEL VARBIND ES: $vals->{$_}\n";}
                push(@trap_array, $vals->{$_});
            }
        }

    return @varbinds;
}

sub processV2
{
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

    externo: for my $vals (@$arreglo_varbind)
    {
        foreach(keys(%$vals))
        {
            if($_ eq "1.3.6.1.6.3.1.1.4.1.0")
            {
                $e_oid = $vals -> {$_};
                $e_oid_ref = { "EOID" => $e_oid };
                if($bandera == 1)
                {
                    last externo;
                }
                $bandera = 1;
            }

            if($_ eq "1.3.6.1.6.3.18.1.3.0")
            {
                $remoteaddr = $vals -> {$_};
                $remoteaddr_ref = { "IPADDR" => $remoteaddr };
                if($bandera == 1)
                {
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

        for my $vals (@varbinds)
        {
            foreach(keys(%$vals))
            {
                if($onPrints){print "EL OID V2 ES: $_" . " EL VALOR DEL VARBIND ES: $vals->{$_}\n";}
            }
        }

    return @varbinds;
}

1;
