package LogicEstructuraLegacy;

use strict;
use warnings;

use Tk;
use Tk::FileDialog;
use Tk::TableMatrix;
use Tk::Pane;

use FindBin;  # Añadir FindBin para obtener la ruta del script
use Data::Dumper; # Importar el modulo Data::Dumper

use File::Path qw(make_path rmtree);
use File::Temp qw(tempfile);

use File::Spec;
use File::Basename;

use Cwd 'abs_path';

# Añadir la carpeta donde se encuentran los modulos
use lib $FindBin::Bin . "/herramientas";
use lib $FindBin::Bin . "./Script Generacion de Agentes SNMP/utilidades";

# Ventanas secundarias
use MIB_utils;

use Toolbar;
use Estilos;
use Complementos;
use Rutas;

use SNMP::MIB::Compiler;


use Log::Log4perl qw(get_logger :levels);

# Initialize logger
Log::Log4perl->init(\<<'EOT');
log4perl.logger = DEBUG, Screen, File

log4perl.appender.Screen = Log::Log4perl::Appender::Screen
log4perl.appender.Screen.layout = Log::Log4perl::Layout::PatternLayout
log4perl.appender.Screen.layout.ConversionPattern = %d %p %m %n

log4perl.appender.File = Log::Log4perl::Appender::File
log4perl.appender.File.filename = terminal.log
log4perl.appender.File.layout = Log::Log4perl::Layout::PatternLayout
log4perl.appender.File.layout.ConversionPattern = %d %p %m %n
EOT

my $logger = get_logger();

sub obtener_texto_implementacion {
  my ($implementacion, $ruta_absoluta, $agente) = @_;
  my $texto_implementacion = '';

  if ($implementacion eq 'Desarrollo') {
    $texto_implementacion = "#!/usr/bin/perl -I /opt/UMP/AGENTES/$agente\n";
  } elsif ($implementacion eq 'Local Windows') {
    $texto_implementacion = "#!/usr/bin/perl -I $ruta_absoluta\n";
  } elsif ($implementacion eq 'Local linux') {
    $texto_implementacion = "#!/usr/bin/perl -I $ruta_absoluta\n";
  }

  return $texto_implementacion;
}

# Function to generate parser data
sub generar_datos_parser {
    my ($ventana_principal, $agente, $alarmas_principales) = @_;
    $agente ||= 'agente_snmp';

    my %parser_data;

    foreach my $alarm_name (keys %$alarmas_principales) {
        my $oid = $alarmas_principales->{$alarm_name}->{OID};
        $oid =~ s/\./_/g;  # Replace dots with underscores for subroutine name
        $parser_data{$alarmas_principales->{$alarm_name}->{OID}} = {
            trap_name  => $alarm_name,
            subroutine => "ABR::$agente\::_$oid"
        };
    }

    return \%parser_data;
}


sub create_snmpagente {
    my ($ventana_principal, $agente, $ruta_agente_abr, $data_extra, $implementacion, $impresiones_desarrollo) = @_;
    my $hostname;
    if ($data_extra->{entries}->{'host name'}) {
        $hostname = $data_extra->{entries}->{'host name'};

    } else {
        $hostname = $data_extra->{combo_boxes}->{'Servidor instalacion'};
    }

    my $local_port = $data_extra->{entries}->{'local port'};

    my $archivo_snmpagente = File::Spec->catfile($ruta_agente_abr, "SNMPAgente.pm");

    if (-e $archivo_snmpagente) {
        open my $fh, '>', $archivo_snmpagente or do {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
            return;
        };
        close $fh;
    }

    open my $fh, '>', $archivo_snmpagente or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
    };
        # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_abr);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo SNMP AGENTE: $archivo_snmpagente");
    print $fh <<"END_CODE";
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
    my \$local_address;
    my \$local_port;
    my \$self;
    my \@args = \@_;
    my \$class = \$args[0];
    if(\$\#args > 1)
    {
        \$local_address = \$args[1];
        \$local_port = \$args[2];
    }
    else
    {
        #\$local_port = 10462;
    \$local_port = $local_port;
    #\$local_port = 2271;
        #my \$hostname = hostname() ;
    my \$hostname = "$hostname";
    #my \$hostname = "100.127.5.81";
        print "EL HOSTNAME ES: \$hostname\\n";

        ( my \$nombre, my \$alias, my \$addr_tipo, my \$largo, my \@direcciones )= gethostbyname(\$hostname);

        ( my \$a, my \$e, my \$i, my \$o )  = unpack("C4", \$direcciones[0]);
        \$local_address = \$a . "." . \$e . "." . \$i ."." . \$o;
    }

    print "LA DIRECCION LOCAL ES: \$local_address\\n";
    print "EL PUERTO LOCAL ES: \$local_port\\n";

    my \$snmptrapd = Net::SNMPTrapd -> new( -LocalAddr=>\$local_address, -LocalPort=>\$local_port, -timeout=>1);

    if(!defined(\$snmptrapd))
    {
        print "There has been an error while openning the specified port: \$local_port on address: \$local_address.\\n";
        print Net::SNMPTrapd -> error();
        exit(1);
    }
    else
    {
      \$self = bless({ snmptrapd => \$snmptrapd }, \$class);
    }

    return \$self;
}

sub get_trap
{
    my \$self     = shift;
    my \$onPrints = shift;
    my \$trap;
    my \$trap_version;

    \$trap = \$self -> { snmptrapd } -> get_trap();

    if (!defined(\$trap))
    {
        printf "\$0: \%s\\n", Net::SNMPTrapd->error();
        print  "There is a problem with the trap reception\\n";
        exit 1;
    }
    elsif (\$trap == 0)
    {
    #    print "Trap value is zero, returning....\\n";
        undef(\$trap);
        return \$trap;
    }

    #JEMM_Comentario de impresiones
    #print "ESTOY ANTES DE PROCESAR EL TRAP\\n";
    if (!defined(\$trap->process_trap()))
    {
        printf "\$0: \%s\\n", Net::SNMPTrapd->error();
        print "There is a problem, processin the trap within the library\\n";
        undef(\$trap);
        return \$trap;
    }
    else
    {
        \$trap_version = \$trap->version();
#         printf "\%s\t\%i\t\%i\t\%s\\n", \$trap->remoteaddr(), \$trap->remoteport(), \$trap_version, \$trap->community();
        if(\$trap_version == 1)
        {
          if(\$onPrints){print "ESTE TRAP ES VERSION 1\\n";}
          \$self -> processV1(\$trap,\$onPrints);
        }
        elsif (\$trap_version == 2)
        {
          if(\$onPrints){print "ESTE TRAP ES VERSION 2\\n";}
          \$self -> processV2(\$trap,\$onPrints);
        }
    }
}

sub processV1
{
    my \@trap_array;
    my \$self              = shift;
    my \$trap              = shift;
    my \$onPrints          = shift;
    # my \$remoteaddr       = \$trap -> remoteaddr();
    my \$remoteaddr        = \$trap -> agentaddr();
    my \$arreglo_varbind   = \$trap -> varbinds();
    my \@varbinds          = \@{\$arreglo_varbind};
    my \$remoteaddr_ref    = { "IPADDR" => \$remoteaddr };
    my \$e_oid             = \$trap -> ent_OID();
    my \$gen_trap          = \$trap -> generic_trap();
    my \$gen_trap_ref      = { "GEN_TRAP" => \$gen_trap };
    my \$spec_trap         = \$trap -> specific_trap();
    my \$spec_trap_ref     = { "SPEC_TRAP" => \$spec_trap };
    my \$trap_oid_complete = \$e_oid . ".0."  . \$spec_trap;
    my \$e_oid_ref         = { "EOID" => \$trap_oid_complete };

    unshift(\@varbinds, \$spec_trap_ref);
    unshift(\@varbinds, \$gen_trap_ref);
    unshift(\@varbinds, \$e_oid_ref);
    unshift(\@varbinds, \$remoteaddr_ref);

    if(\$onPrints){
      print "The SNMP V1 Gen Trap is: \$e_oid\\n";
      print "The SNMP V1 Spec Trap is: \$spec_trap\\n";
      print "The complete trap OID is: \$trap_oid_complete\\n";
    }

        for my \$vals (\@varbinds)
        {
            foreach(keys(\%\$vals))
            {
                if(\$onPrints){print "EL OID ES: \$_" . " EL VALOR DEL VARBIND ES: \$vals->{\$_}\\n";}
                push(\@trap_array, \$vals->{\$_});
            }
        }

    return \@varbinds;
}

sub processV2
{
    my \@trap_array;
    my \$self            = shift;
    my \$trap            = shift;
    my \$onPrints        = shift;
    my \$remoteaddr      = \$trap -> remoteaddr();
    my \$remoteaddr_ref  = { IPADDR => \$remoteaddr };
    my \$arreglo_varbind = \$trap -> varbinds();
    my \@varbinds        = \@{\$arreglo_varbind};
    my \$gen_trap_ref    = { "GEN_TRAP" => "" };
    my \$spec_trap_ref   = { "SPEC_TRAP" => "" };
    my \$bandera         = 0;
    my \$e_oid;
    my \$e_oid_ref;

    externo: for my \$vals (\@\$arreglo_varbind)
    {
        foreach(keys(\%\$vals))
        {
            if(\$_ eq "1.3.6.1.6.3.1.1.4.1.0")
            {
                \$e_oid = \$vals -> {\$_};
                \$e_oid_ref = { "EOID" => \$e_oid };
                if(\$bandera == 1)
                {
                    last externo;
                }
                \$bandera = 1;
            }

            if(\$_ eq "1.3.6.1.6.3.18.1.3.0")
            {
                \$remoteaddr = \$vals -> {\$_};
                \$remoteaddr_ref = { "IPADDR" => \$remoteaddr };
                if(\$bandera == 1)
                {
                    last externo;
                }
                \$bandera = 1;
            }
        }
    }

    unshift(\@varbinds, \$gen_trap_ref);
    unshift(\@varbinds, \$spec_trap_ref);
    unshift(\@varbinds, \$e_oid_ref);
    unshift(\@varbinds, \$remoteaddr_ref);

        for my \$vals (\@varbinds)
        {
            foreach(keys(\%\$vals))
            {
                if(\$onPrints){print "EL OID V2 ES: \$_" . " EL VALOR DEL VARBIND ES: \$vals->{\$_}\\n";}
            }
        }

    return \\\@varbinds;
}

1;
END_CODE

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo \$archivo_snmpagente", 'success');
    return 1;
}


sub create_tapfilter {
    my ($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo) = @_;

    my $archivo_tapfilter = File::Spec->catfile($ruta_agente_abr, "TapFilter.pm");

    if (-e $archivo_tapfilter) {
        open my $fh, '>', $archivo_tapfilter or do {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
            return;
        };
        close $fh;
    }

    open my $fh, '>', $archivo_tapfilter or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
    };
        # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_abr);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo Tap Filter: $archivo_tapfilter");

    print $fh <<"END_CODE";

package ABR::TapFilter;
# Version=6.0
use warnings;
use strict;

use ABR::HashOrder;

sub ifexists
{
 my \$variable = shift;
 if (defined \$variable && \$variable ne ""){
   return 1;
 } else {
   return 0;
 }
}

# Constructor

sub new {
  my \$class = shift;
  my \$args;
  my \$self;
  my \$config_index;
  my \$match_text;
  my \%hash_filter; # Filter
  my \$hash_ref;
  my \%hash_check_operation = ("AddTxt"          => ["match","equal"],
                              "MO"              => ["match","equal"],
                              "PS"              => ["eq","ne","lt","gt","le","ge"],
                              "PC"              => ["eq","ne","lt","gt","le","ge"],
                              "Action"          => ["Blocking","Passing"],
                              "SetGrupos"       => ["IsPresent"],
                              "SetUserText"     => ["IsPresent"],
                              "SetIncidentType" => ["IsPresent"]);
  my \$hashOrdered          = ABR::HashOrder -> new();
  my \$stausFileFilter      = 0;
  my \$Error                = 1;
  my \$InfoErrors           = "";
  my \%filter_read;
  my \@array;
  my \@splitted_1;
  my \@splitted_2;

  \$args     = {\@_};
  \$hash_ref = \$args -> {hash_ref};
  \@array    = split(',',\$args -> {config_index});
  print "\\n------------------ Cargando y verificando sintaxis del filtro ------------------\\n";
  eval{
  foreach my \$FilterName (\@array) {
    foreach my \$index (keys \%{\$hash_ref}) {
      if(\$index eq \$FilterName){
        \$hashOrdered = \${\$hash_ref}{\$index};
        my \$SF = ABR::HashOrder -> new(); # Subfilter HashOrder
        foreach my \$subFilter (\@{\$hashOrdered -> keys}) {
          if(\$hashOrdered -> get(\$subFilter) !~ /.*Action\\<\\>Blocking|Passing\\<\\>.*/){
            my \$rW = "";
            if(\$subFilter =~ m/(.*)_\\d+\$/){
              \$rW = \$hashOrdered -> get(\$subFilter) . "<&&>Action<>Blocking<>" . \$1;
              \$hashOrdered -> set(\$subFilter => \$rW);
            }
          }
          \@splitted_1 = split(\$args -> {split_filter1},\$hashOrdered -> get(\$subFilter));
          foreach my \$item(\@splitted_1){
            \@splitted_2 = split(\$args -> {split_filter2},\$item);
            if(\$hash_check_operation{\$splitted_2[0]}){
              foreach(\@{\$hash_check_operation{\$splitted_2[0]}}){
                if(\$splitted_2[1] eq \$_){
                  if(\$splitted_2[0] eq "PS"){
                    if(!(isInteger(\$splitted_2[2]))){
                      \$InfoErrors = "Error in the file " . \$FilterName . " and Index " . \$subFilter . ": No accepted value \\"" . \$splitted_2[2] . "\\" in \\"" . \$splitted_2[0] . "\\" -> " . \$hashOrdered -> get(\$subFilter) . "\\n";
                      die;
                    }
                    else{
                      if((\$splitted_2[2] eq "5") or (\$splitted_2[2] eq "1") or (\$splitted_2[2] eq "2") or (\$splitted_2[2] eq "3") or (\$splitted_2[2] eq "4") or (\$splitted_2[2] eq "0")){
                        if(\$splitted_2[2] eq "5"){
                          print "[WARN]: In the file " . \$FilterName . " and Index " . \$subFilter . ":\\n";
                          print "[WARN]: " . \$hashOrdered -> get(\$subFilter) . ",\\n";
                          print "[WARN]: you used severity \\"5 -> Clear\\" on this filter, check that it's not on a blocking filter or that the operation is different of \\"eq\\".\\n";
                        }
                      }
                      else{
                        \$InfoErrors = "Error in the file " . \$FilterName . " and Index " . \$subFilter . ": No accepted value \\"" . \$splitted_2[2] . "\\" in \\"" . \$splitted_2[0] . "\\" -> " . \$hashOrdered -> get(\$subFilter) . "\\n";
                        die;
                      }
                    }
                  }
                  elsif( \$splitted_2[0] eq "PC"){
                    if(!(isInteger(\$splitted_2[2]))){
                      \$InfoErrors = "Error in the file " . \$FilterName . " and Index " . \$subFilter . ": No accepted value \\"" . \$splitted_2[2] . "\\" in \\"" . \$splitted_2[0] . "\\" -> " . \$hashOrdered -> get(\$subFilter) . "\\n";
                      die;
                    }
                  }
                  else{
                    if(!(ifexists \$splitted_2[2])){
                      \$InfoErrors = "Error in the file " . \$FilterName . " and Index " . \$subFilter . ": value is empty\\"" . \$splitted_2[2] . "\\" in \\"" . \$splitted_2[0] . "\\" -> " . \$hashOrdered -> get(\$subFilter) . "\\n";
                      die;
                    }
                  }
                  \$Error = 0;
                }
              }
              if(\$Error){
                \$InfoErrors = "Error in the file " . \$FilterName . " and Index " . \$subFilter . ": No accepted operation \\"" . \$splitted_2[1] . "\\" in \\"" . \$splitted_2[0] . "\\" -> " . \$hashOrdered -> get(\$subFilter) . "\\n";
                die;
              }
              \$Error = 1;
            }else{
              \$InfoErrors = "Error in the file " . \$FilterName . " and Index " . \$subFilter . ": No accepted parameter \\"" . \$splitted_2[0] . "\\" -> " . \$hashOrdered -> get(\$subFilter) . "\\n";
              die;
            }
          }
          \$SF -> set(\$subFilter => [\@splitted_1] );
          \$hash_filter{\$FilterName} = \$SF;
        }
        \$stausFileFilter = \$stausFileFilter | 1;
      }else{
        \$stausFileFilter = \$stausFileFilter | 0;
      }
    }
  }
  print ">> No hay Errores de sintaxis en el filtro de bloqueo\\n";
  print "--------------------------------------------------------------------------------\\n\\n";
}or do{
  die "[ERR ]: TapFilter.pm, " . \$InfoErrors;
};

  \$self = { hash_filter => \\\%hash_filter, status => \$stausFileFilter, match_text => \$match_text, separator => \$args -> {split_filter2} };
  return bless \$self,\$class;
}



sub ProcessingFilters{
  my \$self            = shift;
  my \$textAlarm       = shift;
  my \$file_Alarm      = shift;
  my \$filter_read_ref = \$self -> {hash_filter};
  my \$stausFileFilter = \$self -> {status};
  my \$separator       = \$self -> {separator};
  my \%hash_ref_filter = \%\$filter_read_ref;
  my \$matchText       = "";
  my \$SubFbefore      = "";
  my \$PFString        = "NULL";
  my \$hash_ref;
  my \@splitted;
  my \$logic           = 1;
  my \$BF              = 0;
  my \$PF              = 0;
  my \$statusPF        = 0;
  if (\$stausFileFilter) {
    \$hash_ref = ProcessingTextAlarm(\$textAlarm);
    foreach my \$filter (keys \%hash_ref_filter) {
      foreach my \$subFilter (\@{\$hash_ref_filter{\$filter} -> keys}) {
        if(\$subFilter !~ /\$PFString\\_\\d+\$/ ){
          if(ifexists \$SubFbefore){
            if(\$subFilter !~ /\$SubFbefore\\_\\d+\$/){
              if((\$PF eq 0) and (\$statusPF eq 1)){
                return changeFileName(\$file_Alarm);
              }
              \$PF       = 0;
              \$statusPF = 0;
            }
          }
          foreach my \$val ( \@{\$hash_ref_filter{\$filter} -> get(\$subFilter)} ) {
            \@splitted = split(\$separator,\$val);
            if( \$splitted[0] ne 'Action' && (\$splitted[0] ne "SetIncidentType") && (\$splitted[0] ne "SetUserText") && (\$splitted[0] ne "SetGrupos") ){
              \$logic = \$logic & Operations(\$splitted[0],\$splitted[1],\$splitted[2],\$hash_ref);
            }
            elsif((\$splitted[0] eq "SetIncidentType") || (\$splitted[0] eq "SetUserText") || (\$splitted[0] eq "SetGrupos")){
              if( \$splitted[1] eq "IsPresent" ){
                \$logic = \$logic & IsPresent(\$splitted[0],\$splitted[2],\$hash_ref);
              }
            }
            elsif( \$splitted[1] eq 'Blocking' ){
              \$BF         = \$logic;
              \$SubFbefore = \$splitted[2];
            }
            elsif( \$splitted[1] eq 'Passing' ){
              \$PF       = \$logic;
              \$PFString = \$splitted[2];
              \$statusPF = 1;
            }
            if(\$logic){
              \$matchText = \$matchText ."[INFO]: Filter: " . \$filter . "->" . \$subFilter . ":\n[INFO]: Parameter: " . \$splitted[0] . ", Operation: " . \$splitted[1] . ", Value: " . \$splitted[2] . "\n";
            }else{
              \$matchText = "";
            }
          }
          if(\$BF){
            \$self -> {match_text} = \$matchText;
            return changeFileName(\$file_Alarm);
          }else{
            if(\$PF){
              \$self -> {match_text} = "";
              \$logic = 1;
              \$BF    = 0;
            }
            else{
              \$self -> {match_text} = "";
              \$PFString             = "NULL";
              \$logic = 1;
              \$BF    = 0;
            }
          }
        }
      }
    }
    if((\$PF eq 0) and (\$statusPF eq 1)){
      return changeFileName(\$file_Alarm);
    }
    \$PF       = 0;
    \$statusPF = 0;
  }
  return "\$file_Alarm";
}

sub IsPresent{
  my \$oper          = shift;
  my \$value         = shift;
  my \$HashTextAlarm = shift;
  my \$vl            = 1;
  if(ifexists \$HashTextAlarm -> {"AddTxt"}){
    if   (\$oper eq "SetGrupos"){
      \$vl = functionMatch(\$HashTextAlarm -> {"AddTxt"},\$value);
    }
    elsif(\$oper eq "SetIncidentType"){
      \$vl = functionMatch(\$HashTextAlarm -> {"AddTxt"},\$value);
    }
    elsif(\$oper eq "SetUserText"){
      \$vl = functionMatch(\$HashTextAlarm -> {"AddTxt"},\$value);
    }
    else{
      \$vl = 0;
    }
  }else{
    \$vl = 0;
  }
  return \$vl;
}

sub Operations{
  my \$param         = shift;
  my \$oper          = shift;
  my \$value         = shift;
  my \$HashTextAlarm = shift;
  my \$vl            = 1;
  if(\$param eq "AddTxt"){
    if(ifexists \$HashTextAlarm -> {"AddTxt"}){
      if(\$oper eq "match"){
        \$vl = functionMatch(\$HashTextAlarm -> {"AddTxt"},\$value);
      }elsif(\$oper eq "equal"){
        \$vl = functionEqual(\$HashTextAlarm -> {"AddTxt"},\$value);
      }
    }else{
      \$vl = 0;
    }
  }
  elsif(\$param eq "MO"){
    if(ifexists \$HashTextAlarm -> {"MO"}) {
      if(\$oper eq "match"){
        \$vl = functionMatch(\$HashTextAlarm -> {"MO"},\$value);
      }elsif(\$oper eq "equal"){
        my \$var = "";
        \$var = \$HashTextAlarm -> {"MO"};
        \$var =~ s/^"//;
        \$var =~ s/"\$//;
        \$vl  = functionEqual(\$var,\$value);
      }
    }else{
      \$vl = 0;
    }
  }
  elsif(\$param eq "PS"){
    if(isInteger(\$HashTextAlarm -> {"PS"})){
      if(\$oper eq "eq"){
        \$vl = functionEq(\$value,\$HashTextAlarm -> {"PS"});
      }
      elsif(\$oper eq "ne"){
        \$vl = functionNe(\$value,\$HashTextAlarm -> {"PS"});
      }elsif(\$oper eq "lt"){
        \$vl = PSlt(\$value,\$HashTextAlarm -> {"PS"});
      }elsif(\$oper eq "gt"){
        \$vl = PSgt(\$value,\$HashTextAlarm -> {"PS"});
      }elsif(\$oper eq "le"){
        \$vl = PSle(\$value,\$HashTextAlarm -> {"PS"});
      }elsif(\$oper eq "ge"){
        \$vl = PSge(\$value,\$HashTextAlarm -> {"PS"});
      }
    }else{
      \$vl = 0;
    }
  }
  elsif(\$param eq "PC"){
    if(isInteger(\$HashTextAlarm -> {"PC"})){
      if(\$oper eq "eq"){
        \$vl = functionEq(\$value,\$HashTextAlarm -> {"PC"});
      }
      elsif(\$oper eq "ne"){
        \$vl = functionNe(\$value,\$HashTextAlarm -> {"PC"});
      }elsif(\$oper eq "lt"){
        \$vl = functionLt(\$value,\$HashTextAlarm -> {"PC"});
      }elsif(\$oper eq "gt"){
        \$vl = functionGt(\$value,\$HashTextAlarm -> {"PC"});
      }elsif(\$oper eq "le"){
        \$vl = functionLe(\$value,\$HashTextAlarm -> {"PC"});
      }elsif(\$oper eq "ge"){
        \$vl = functionGe(\$value,\$HashTextAlarm -> {"PC"});
      }
    }else{
      \$vl = 0;
    }
  }
  return \$vl;
}
################################################################################
############################ Processing Text Alarm #############################
################################################################################

sub ProcessingTextAlarm{
  # print "\\nProcessingTextAlarm\\n";
  my \$textAlarm = shift;
  my \@s1;
  my \%hash_alarm;
  \$textAlarm =~ s/###START###//g;
  \$textAlarm =~ s/###END###//g;
  \$textAlarm =~ s/\\n/ /g;
  # print "\$textAlarm\\n";
  \@s1 = split('#\\\$\\%','\$textAlarm');
  foreach my \$i1(\@s1){
    if(\$i1 =~ /(\\w+):(.*)/){
      # print "\$1 -> \$2\\n";
      \$hash_alarm{\$1} = \$2;
    }
  }
  # print "\\n\\n";
  return \\\%hash_alarm;
}

################################################################################
################################## File Name ###################################
################################################################################

sub changeFileName{
  my \$file = shift;
  if(\$file =~ /(.*)\\.yes/){
    return "\$1.no";
  }else{
    return "\$file";
  }
}

################################################################################
############################# Comparison of String #############################
################################################################################

sub functionMatch{
  my \$text  = shift;
  my \$match = shift;
  my \$l     = shift;
  eval{
    \$l = (\$text =~ /\$match/);
    return \$l;
  }or do{
    return 0;
  };
}

# sub functionMatch{
#   # print "functionMatch\\n";
#   my \$text  = shift;
#   my \$match = shift;
#   if(\$text =~ /\$match/){
#     # print "matc:\$text , \$match\\n\\n";
#     return 1;
#   }else{
#     return 0;
#   }
# }

sub functionEqual{
  # print "functionEqual";
  my \$text  = shift;
  my \$equal = shift;
  if(\$text eq \$equal){
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
  my \$val1 = shift;
  my \$val2 = shift;
  if(\$val1 == \$val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionNe{
  my \$val1 = shift;
  my \$val2 = shift;
  if(\$val1 != \$val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionLt{
  my \$val1 = shift;
  my \$val2 = shift;
  if(\$val1 < \$val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionGt{
  my \$val1 = shift;
  my \$val2 = shift;
  if(\$val1 > \$val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionLe{
  my \$val1 = shift;
  my \$val2 = shift;
  if(\$val1 <= \$val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionGe{
  my \$val1 = shift;
  my \$val2 = shift;
  if(\$val1 >= \$val2){
    return 1;
  }else{
    return 0;
  }
}

################################################################################
########################### Comparison of Numbers PS ###########################
################################################################################

sub PSle{
  my \$val1 = shift;
  my \$val2 = shift;

  # print "val1 -> " . \$val1 . " le val2 -> " . \$val2 . "\\n";

  if(\$val1 ne "5" and \$val2 ne "5"){

    if(\$val2 eq "0"){
      # print ">> " . \$val1 . " <= " . \$val2 . " -> 1\\n";
      return 1;
    }else{
      if(\$val1 eq "0"){
        # print ">> " . \$val1 . " <= " . \$val2 . " -> 0\\n";
        return 0;
      }else{
        if(\$val1 <= \$val2){
          # print ">> " . \$val1 . " <= " . \$val2 . " -> 1\\n";
          return 1;
        }else{
          # print ">> " . \$val1 . " <= " . \$val2 . " -> 0\\n";
          return 0;
        }
      }
    }

  }else{
    return 0;
  }

}

sub PSlt{
  my \$val1 = shift;
  my \$val2 = shift;

  # print "val1 -> " . \$val1 . " lt val2 -> " . \$val2 . "\\n";

  if(\$val1 ne "5" and \$val2 ne "5"){

    if(\$val2 eq "0"){
      if(\$val1 eq  "0"){
        return 0;
      }else{
        return 1;
      }
      # print ">> " . \$val1 . " <= " . \$val2 . " -> 1\\n";
    }else{
      if(\$val1 eq "0"){
        # print ">> " . \$val1 . " <= " . \$val2 . " -> 0\\n";
        return 0;
      }else{
        if(\$val1 < \$val2){
          # print ">> " . \$val1 . " <= " . \$val2 . " -> 1\\n";
          return 1;
        }else{
          # print ">> " . \$val1 . " <= " . \$val2 . " -> 0\\n";
          return 0;
        }
      }
    }

  }else{
    return 0;
  }

}

sub PSge{
  my \$val1 = shift;
  my \$val2 = shift;

  # print "val1 -> " . \$val1 . " ge val2 -> " . \$val2 . "\\n";

  if(\$val1 ne "5" and \$val2 ne "5"){

    if(\$val1 eq "0"){
      # print ">> " . \$val1 . " >= " . \$val2 . " -> 1\\n";
      return 1;
    }else{
      if(\$val2 eq "0"){
        # print ">> " . \$val1 . " >= " . \$val2 . " -> 1\\n";
        return 0;
      }else{
        if(\$val1 >= \$val2){
          # print ">> " . \$val1 . " >= " . \$val2 . " -> 1\\n";
          return 1;
        }else{
          # print ">> " . \$val1 . " >= " . \$val2 . " -> 0\\n";
          return 0;
        }
      }
    }

  }else{
    return 0;
  }

}

sub PSgt{
  my \$val1 = shift;
  my \$val2 = shift;

  # print "val1 -> " . \$val1 . " gt val2 -> " . \$val2 . "\\n";

  if(\$val1 ne "5" and \$val2 ne "5"){

    if(\$val1 eq "0"){
      # print ">> " . \$val1 . " >= " . \$val2 . " -> 1\\n";
      return 0;
    }else{
      if(\$val2 eq "0"){
        # print ">> " . \$val1 . " >= " . \$val2 . " -> 1\\n";
        return 0;
      }else{
        if(\$val1 > \$val2){
          # print ">> " . \$val1 . " >= " . \$val2 . " -> 1\\n";
          return 1;
        }else{
          # print ">> " . \$val1 . " >= " . \$val2 . " -> 0\\n";
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
  my \$input = shift;
  if(ifexists \$input){
    if(\$input !~ /\\d+\\.\\d+/){
      if(\$input =~ /\\d+/){
        # print "IsInteger: \\"" . \$input . "\\"\\n";
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
  my \$self  = shift;
  my \$match = \$self -> {match_text};

  if(\$match){
    print "[INFO]: filter conditions fulfilled:\\n\$match\\n";
  }
  else{
    print "[INFO]: No filter conditions fulfilled\\n\\n";
  }
}

1;
END_CODE
    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_tapfilter", 'success');
    return 1;
}



sub create_microtime {
    my ($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo) = @_;

    my $archivo_microtime = File::Spec->catfile($ruta_agente_abr, "MICROTIME.pm");

    if (-e $archivo_microtime) {
        open my $fh, '>', $archivo_microtime or do {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
            return;
        };
        close $fh;
    }

    open my $fh, '>', $archivo_microtime or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
    };
        # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_abr);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo Microtime: $archivo_microtime");

    print $fh <<"END_CODE";
package ABR::MICROTIME;
# Version=1.0
use Time::HiRes qw(gettimeofday);
use bignum;

sub getmicro {
    my \$micros;
    (my \$ts, my \$tm) = gettimeofday();
    \$micros = (\$ts + \$tm / 1000000) * 1000000;
    return \$micros;
}

1;
END_CODE

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_microtime", 'success');
    return 1;
}

sub create_llenaComun {
    my ($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo) = @_;

    my $archivo_llena_comun = File::Spec->catfile($ruta_agente_abr, "llenaComun.pm");

    if (-e $archivo_llena_comun) {
        open my $fh, '>', $archivo_llena_comun or do {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
            return;
        };
        close $fh;
    }

    open my $fh, '>', $archivo_llena_comun or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
    };
        # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_abr);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo llena Comun: $archivo_llena_comun");

    print $fh <<"END_CODE";
package ABR::llenaComun;
# Version=1.0
use POSIX qw(strftime);
use warnings;
use strict;

sub new {

        my \$class=shift;
        my \$self;
        my \$mensaje_x733;

        \$self = bless( {  mensaje_x733 => \\\$mensaje_x733 }, \$class );
}

sub vacia_mensaje_x733 {

        my \$self = shift;
        my \$mensaje_x733 = \$self -> { mensaje_x733 };
        \$\$mensaje_x733 = "";
}

sub llenaEN {
        my \$self    = shift;
        my \$en_list = shift;
        #     my \%mo_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$en_list\\n";
        \$en_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$en_list;
}

sub llenaMO {
        my \$self    = shift;
        my \$mo_list = shift;
        #     my \%mo_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$mo_list\\n";
        \$mo_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$mo_list;
}

sub llenaPC {
        my \$self    = shift;
        my \$pc_list = shift;
        #     my \%pc_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$pc_list\\n";
        \$pc_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$pc_list;
}

sub llenaSP {
        my \$self    = shift;
        my \$ps_list = shift;
        #     my \%ps_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$ps_list\\n";
        \$ps_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$ps_list;
}

sub llenaPS {
        my \$self    = shift;
        my \$ps_list = shift;
        #     my \%ps_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$ps_list\\n";
        \$ps_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$ps_list;
}

sub llenaBUS {
        my \$self     = shift;
        my \$bus_list = shift;
        #     my \%bus_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$bus_list\\n";
        \$bus_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$bus_list;
}

sub llenaBAO {
        my \$self     = shift;
        my \$bao_list = shift;
        #     my \%bao_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$bao_list\\n";
        \$bao_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$bao_list;
}

sub llenaTrendI {
        my \$self        = shift;
        my \$trendi_list = shift;
        #     my \%trendi_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$trendi_list\\n";
        \$trendi_list   .= "#\\\$%";
        \$\$mensaje_x733 .= \$trendi_list;
}

sub llenaThresholdI {
        my \$self            = shift;
        my \$thresholdi_list = shift;
        #   smy \%thresholdi_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$thresholdi_list\\n";
        \$thresholdi_list .= "#\\\$%";
        \$\$mensaje_x733   .= \$thresholdi_list;
}

sub llenaNI {
        my \$self    = shift;
        my \$ni_list = shift;
        #     my \%ni_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$ni_list\\n";
        \$ni_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$ni_list;
}

sub llenaCN {
        my \$self    = shift;
        my \$cn_list = shift;
        #     my \%cn_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$cn_list\\n";
        \$cn_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$cn_list;
}

sub llenaSCD {
        my \$self     = shift;
        my \$scd_list = shift;
        #     my \%scd_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$scd_list\\n";
        \$scd_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$scd_list;
}

sub llenaMA {
        my \$self    = shift;
        my \$ma_list = shift;
        #     my \%ma_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$ma_list\\n";
        \$ma_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$ma_list;
}

sub llenaPRA {
        my \$self     = shift;
        my \$pra_list = shift;
        #     my \%pra_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$pra_list\\n";
        \$pra_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$pra_list;
}

sub llenaAT {
        my \$self    = shift;
        my \$at_list = shift;
        #     my \%at_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$at_list\\n";
        \$at_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$at_list;
}

sub llenaAI {
        my \$self    = shift;
        my \$ai_list = shift;
        #     my \%ai_hash;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: \$ai_list\\n";
        \$ai_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$ai_list;
}

sub EventTime {
        my \$self         = shift;
        my \$et_list      = shift;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        \$et_list .= "#\\\$%";
        \$\$mensaje_x733 .= \$et_list;
}

sub EventType {
        my \$self         = shift;
        my \$ety_list     = shift;
        my \$mensaje_x733 = \$self->{mensaje_x733};
        \$\$mensaje_x733 .= \$ety_list;
}

sub fecha {
  my \$self         = shift;
  my \$datestring = strftime "%b %e %H:%M:%S %Z %Y", localtime;
  return \$datestring;
}

1;
END_CODE

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_llena_comun", 'success');
    return 1;
}



sub create_hashorder {
    my ($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo) = @_;
    my $self;
    my $archivo_hashorder = File::Spec->catfile($ruta_agente_abr, "HashOrder.pm");

    if (-e $archivo_hashorder) {
        open my $fh, '>', $archivo_hashorder or do {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
            return;
        };
        close $fh;
    }

    open my $fh, '>', $archivo_hashorder or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
    };
        # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_abr);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo Hash Order: $archivo_hashorder");

    print $fh <<"END_CODE";
package ABR::HashOrder;
# Version=1.0
use warnings;
use strict;

sub ifexists
{
 my \$variable = shift;
 if (defined \$variable && \$variable ne ""){
   return 1;
 } else {
   return 0;
 }
}

# Constructor
sub new {
  my \$class = shift;
  my \$args  = {\@_};
  my \$self;
  my \%hash;
  my \@array;

  my \$type = "\$args";
  if(ifexists(\$type)){
    if(\$type =~ /HASH/i){
      foreach my \$x(keys \%{\$args}){
        # print "args: " . \$x . " -> " . \$args -> {\$x} . "\\n";
        # agregando al final del arreglo un elemento
        push(\@array,\$x);
        \$hash{\$x} = \$args -> {\$x};
      }
    }
  }

  \$self = {hash_ref => \\\%hash, array_ref => \\\@array};
  return bless \$self,\$class;
}

sub exists{
  my \$self = shift;
  my \$key  = shift;

  if(ifexists(\$key)){
    if(ifexists(\$self -> {hash_ref}{\$key})){
      # print "funcion existe: " . \$self -> {hash_ref} -> {\$key} . "\\n";
      return 1;
    }else{
      return 0;
    }
  }else{
    return 0;
  }
}

sub delete{
  my \$self     = shift;
  my \$key      = shift;
  my \$size_arr = 0;

  if(ifexists(\$key)){
    if(ifexists(\$self -> {hash_ref}{\$key})){
      # Eliminando la llave del hash_ref
      delete \$self -> {hash_ref}{\$key};

      # Eliminando la llave del array_ref
      \$size_arr = \@{\$self -> {array_ref}};
      if(\$size_arr != 0){
        for (my \$var = 0; \$var < \$size_arr; \$var++) {
          # print "index: " . \$var . " -> " . \$self -> {array_ref}[\$var] . "\\n";
          if(\$self -> {array_ref}[\$var] eq \$key ){
            splice(\@{\$self -> {array_ref}},\$var,1);
            last;
          }
        }
      }
    }
  }
}

sub get{
  my \$self     = shift;
  my \$key      = shift;

  if(ifexists(\$key)){
    if(ifexists(\$self -> {hash_ref}{\$key})){
      return \$self -> {hash_ref}{\$key};
    }else{
      return "";
    }
  }else{
    return "";
  }
}

sub set{
  my \$self     = shift;
  my \$input1   = shift;
  my \$input2   = shift;
  my \$size_arr = 0;

  if(ifexists(\$input1)){
    if(ifexists(\$input2)){
      push(\@{\$self -> {array_ref}},\$input1);
      \$self -> {hash_ref}{\$input1} = \$input2;
    }
  }
}

sub keys{
  my \$self   = shift;
  my \$size   = 0;

  \$size = \@{\$self -> {array_ref}};
  if(\$size != 0){
    return \$self -> {array_ref};
  }

  return "";
}

sub getSize{
  my \$self   = shift;
  my \$size   = 0;
  \$size = \@{\$self -> {array_ref}};
  return \$size;
}

1;
END_CODE

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_hashorder", 'success');
    return 1;
}



sub crear_file_handler {
    my ($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo) = @_;

    my $archivo_file_handler = File::Spec->catfile($ruta_agente_abr, "FILE_HANDLER.pm");

    if (-e $archivo_file_handler) {
        open my $fh, '>', $archivo_file_handler or do {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
            return;
        };
        close $fh;
    }

    open my $fh, '>', $archivo_file_handler or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
    };
        # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_abr);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo File handler: $archivo_file_handler");

    print $fh <<"END_CODE";
package ABR::FILE_HANDLER;
# Version=1.0
use warnings;
use strict;

sub new {

    my \$class = shift;
    my \$args = { \@_};
    my \%args_hash = \%{\$args};
    my \$gluster_dir;
    my \$auxiliary_dir;

    for(keys(\%args_hash)) {

        if(\$_ eq "gluster_dir")
        {
            \$gluster_dir = \$args_hash{\$_};
        }
        if(\$_ eq "auxiliary_dir")
        {
            \$auxiliary_dir = \$args_hash{\$_};
        }
    }

    return bless( { gluster_dir => \$gluster_dir, auxiliary_dir => \$auxiliary_dir, not_send => [ ] }, \$class );
}

sub write_file {

    my \$self = shift;
    my \$file_name = shift;
    my \$file_content = shift;
    my \$gluster_dir = \$self -> {gluster_dir};
    my \$auxiliary_dir = \$self -> {auxiliary_dir};
    my \$ref_files_not_send = \$self -> {not_send};
    my \@files_not_send = \@{\$ref_files_not_send};
    my \$file_path;
    my \$emergency_path;
    my \$regreso;
    my \$size;

    \$file_path = \$gluster_dir . "/" . \$file_name;
    \$emergency_path = \$auxiliary_dir . "/" . \$file_name;

    \$regreso = open ARCH, ">", \$file_path;

    if(!defined(\$regreso)) {

        print "I could not write to gluster directory\\n";
        \$regreso = open EMERGENCY, ">", \$emergency_path;
        if(!defined(\$regreso)) {

            die "The emergency directory does not exist or is not accesible";
        }

        print EMERGENCY \$file_content;
        close EMERGENCY;
        \$size = scalar(\@files_not_send);
        print "EL TAMAN\\xD1O ES: \$size\\n";

        for(my \$i = 0; \$i < \$size; \$i++) {

            print "LOS ARCHIVOS DENTRO DEL ARREGLO ANTES SON: " . \$files_not_send[\$i] . "\\n";
        }

        print "EL ARCHIVO QUE SE VA A EMPUJAR ES: " . \$file_name . "\\n";
        \$ref_files_not_send -> [\$size] =  \$file_name;
        \$size = scalar(\@{\$ref_files_not_send});
        print "EL TAMAN\\xD1O ES: \$size\\n";

        for(my \$i = 0; \$i < \$size; \$i++) {

            print "LOS ARCHIVOS DENTRO DEL ARREGLO DESPUES SON: " . \$ref_files_not_send -> [\$i] . "\\n";
        }

        return "EMERGENCY";
    }

    if(scalar(\@files_not_send) > 0)
    {
        \$self -> file_resynch();
    }

    print ARCH \$file_content;
    close ARCH;
    return "WRITTEN";
}

sub file_resynch {

    my \$self = shift;
    my \$gluster_dir = \$self -> {gluster_dir};
    my \$auxiliary_dir = \$self -> {auxiliary_dir};
    my \$ref_files_not_send = \$self -> {not_send};
    my \@files_not_send = \@{\$ref_files_not_send};
    my \$file_path;
    my \$emergency_path;
    my \$regreso;
    my \$size;

    if((\$size = scalar(\@files_not_send)) > 0) {

        print "VOY A HACER RESYNCH\\n";
        print "Size of the array is: " . \$size . "\\n";

        while (\@{\$ref_files_not_send}) {

            my \$emergency_file = shift(\@{\$ref_files_not_send});
            print "The emergency file is " . \$emergency_file . "\\n";

            \$file_path = \$gluster_dir . "/" . \$emergency_file;
            print "The file path is: \$file_path\\n";

            \$emergency_path = \$auxiliary_dir . "/" . \$emergency_file;
            print "The emergency file path is: \$emergency_path\\n";

            \$regreso = `mv -f \$emergency_path \$file_path`;
            print "EL VALOR DE REGRESO ES: " . \$? . "\\n";

            if(\$? == -1) {

                unshift(\@{\$ref_files_not_send}, \$emergency_file);
                last;
            }
        }
    }
}

sub dummy_write {

    my \$self = shift;
    my \$gluster_dir = \$self -> {gluster_dir};
    my \$ref_files_not_send = \$self -> {not_send};
    my \@files_not_send = \@{\$ref_files_not_send};

    if(scalar(\@files_not_send) > 0){

        if(opendir(DIR, \$gluster_dir)) {

            print "DUMMY: IT OPENEND THE DIR\\n";
            close DIR;
            \$self -> file_resynch();
        }
    }
}

sub startup_write {

    my \$self = shift;
    my \$gluster_dir = \$self -> {gluster_dir};
    my \$auxiliary_dir = \$self -> {auxiliary_dir};
    my \$ref_files_not_send = \$self -> {not_send};
    my \$regreso;
    my \@files;
    my \$count = 0;

    if(opendir(DIR, \$gluster_dir)) {

        close DIR;
        \$regreso = `ls -rt \$auxiliary_dir`;

        if(\$? == -1) {

            die "There is a problem reading files from the emergency file path";
        }

        \@files = split("\\n", \$regreso);

        foreach(\@files) {

            \$ref_files_not_send -> [\$count] = \$_;
            \$count++;
        }

        \$self -> file_resynch();
    }
}

1;
END_CODE

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_file_handler", 'success');
    return 1;
}


sub crear_corrective_filter {
    my ($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo) = @_;

    my $archivo_corrective_filter = File::Spec->catfile($ruta_agente_abr, "CorrectiveFilter.pm");

    if (-e $archivo_corrective_filter) {
        open my $fh, '>', $archivo_corrective_filter or do {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
            return;
        };
        close $fh;
    }

    open my $fh, '>', $archivo_corrective_filter or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
    };
        # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_abr);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo Filter: $archivo_corrective_filter");

    print $fh <<"END_CODE";
package ABR::CorrectiveFilter;
# Version=6.0
use warnings;
use strict;

use ABR::HashOrder;

sub ifexists
{
 my \$variable = shift;
 if (defined \$variable && \$variable ne ""){
   return 1;
 } else {
   return 0;
 }
}

# Constructor

sub new {
  my \$class = shift;
  my \$args;
  my \$self;

  \$args  = {\@_};
  \$self = { splitFilter1 => \$args -> {split_filter1}, splitFilter2 => \$args -> {split_filter2} };
  return bless \$self,\$class;
}

sub ProcessingCF{
  my \$self = shift;
  my (\$hash_field,\$hashref_fc,\$action,\$cascade) = \@_;
  my \@splitted_1;
  my \@splitted_2;
  my \$OrigAddTxt = \$hash_field -> {"AddTxt"};
  my \$logic      =  1;
  my \$blocking   = "";
  my \$output     = "";
  # my \$valueMem = "";

  #print "Metodo ProcessingCF\\n";
  #print "MO:"            . \$hash_field -> {"MO"}     . "\\n";
  #print "AddTxt:"        . \$hash_field -> {"AddTxt"} . "\\n";
  #print "PS:"            . \$hash_field -> {"PS"}     . "\\n";
  #print "Action:"        . \$action                   . "\\n";
  #print "Cascade:"            . \$cascade     . "\\n";
  #print "splitFilter1: " . \$self -> {splitFilter1}   . "\\n";
  #print "splitFilter2: " . \$self -> {splitFilter2}   . "\\n";
  # print "----------------------------------------------------------------\\n";
  if (\$action eq "SetGrupos") {
    # print "Action: " . \$action . "\\n";
    return DirectSetGrupos(\$hash_field,\$hashref_fc);
  }

  if (ifexists \$hashref_fc) {
    foreach my \$Filter (\@{\$hashref_fc -> keys}) {
      \@splitted_1 = split(\$self -> {splitFilter1}, \$hashref_fc -> get(\$Filter));
      foreach my \$line(\@splitted_1){
        \@splitted_2 = split(\$self -> {splitFilter2},\$line);
        # print \$Filter . " -> Param:" . \$splitted_2[0] . ", Oper: " . \$splitted_2[1] . ", Val: \\"" . \$splitted_2[2] . "\\"\\n";
        if((\$splitted_2[0] ne "Action") && (\$splitted_2[0] ne "SetIncidentType") && (\$splitted_2[0] ne "SetUserText") && (\$splitted_2[0] ne "SetGrupos")){
          # print "Diferente de Action\\n";
          # print \$Filter . " -> Param:" . \$splitted_2[0] . ", Oper: " . \$splitted_2[1] . ", Val: \\"" . \$splitted_2[2] . "\\"\\n";
          \$logic = \$logic & Operations(\$splitted_2[0],\$splitted_2[1],\$splitted_2[2],\$hash_field);
        }
        elsif((\$splitted_2[0] eq "SetIncidentType") || (\$splitted_2[0] eq "SetUserText") || (\$splitted_2[0] eq "SetGrupos")){
          if( \$splitted_2[1] eq "IsPresent" ){
            # my \$l = IsPresent(\$action,\$splitted_2[2],\$hash_field);
            # print "Logica del IsPresent CorrectiveFilter: " . \$l . "\\n";
            \$logic = \$logic & IsPresent(\$action,\$splitted_2[2],\$hash_field);
          }
        }
        else{
          # print \$Filter . " -> Param:" . \$splitted_2[0] . ", Oper: " . \$splitted_2[1] . ", Val: \\"" . \$splitted_2[2] . "\\"\\n";
          if   (\$splitted_2[1] eq \$action   ){
            # print "Esto " . \$splitted_2[1] . " es igual a " . \$action ."\\n";
            # print \$Filter . " -> " . \$splitted_2[0] . ", Oper: " . \$splitted_2[1] . ", Val: \\"" . \$splitted_2[2] . "\\"\\n";
            \$output = ActionReview(\$splitted_2[0],\$splitted_2[1],\$splitted_2[2],\$hash_field,\$OrigAddTxt,\$cascade);
          }
          elsif(\$splitted_2[1] eq "Blocking"){
            # print "Blocking\\n";
            # print \$Filter . " -> " . \$splitted_2[0] . ", Oper: " . \$splitted_2[1] . ", Value: \\"" . \$splitted_2[2] . "\\"\\n";
            \$output = ActionFalse(\$action, \$hash_field);
            # print "Logica para Blocking: " . \$logic . "\\n";
            if(\$logic){\$blocking = \$splitted_2[2];}
          }
          else{\$logic = 0;}
        }
      }

      if(\$logic){
        # print "Logic           : " . \$logic    . " => True\\n";
        # print "Blocking Value  : " . \$blocking . "\\n";
        if(\$blocking eq "" || \$Filter !~ /\$blocking\\\_\\d+\$/){
          # print "Value Assign    : " . \$output   . "\\n";
          # print "No Blocking Filter: " . \$Filter . "\\n";
          ######################################
          ############## Cascade ###############
          ######################################
          if(ifexists \$cascade){
        print "INFO:" . \$cascade . "\\n";
            if(\$cascade eq "NonCascade"){
              return \$output;
            }
          }
          ######################################
          ############# Assignment #############
          ######################################
          if   (\$action eq "PrependAdditionalText"){
            \$hash_field -> {"AddTxt"} = \$output;
          }
          elsif(\$action eq "SetEventSeverity"){
            \$hash_field -> {"PS"} = \$output;
          }
          elsif(\$action eq "SetGrupos"){
            \$hash_field -> {"AddTxt"} = \$output;
          }
          elsif(\$action eq "SetIncidentType"){
            \$hash_field -> {"AddTxt"} = \$output;
          }
          elsif(\$action eq "SetUserText"){
            \$hash_field -> {"AddTxt"} = \$output;
          }
          elsif(\$action eq "SetEventManagedObject"){
            \$hash_field -> {"MO"} = \$output;
          }
          # else{
            # if(ifexists \$action){
              # print "[WARNING]: Invalid action \\"" . \$action . "\\" in the Corrective Filter";

              #
            # }
            # else{
              # print "[WARNING]: Action is \"empty\" in the Corrective Filter";

            # }
          # }
          # return \$output;
        }
        # else{print "Blocking Filter: " . \$Filter . "\\n";}

      }else{
        # print "Logic         : " . \$logic                            . " => False\\n";
        # print "Blocking Value: " . \$blocking                         . "\\n";
        # print "Value Assign  : " . ActionFalse(\$action, \$hash_field) . "\\n";
        # print "Filter Skip   : " . \$Filter                           . "\\n";
        \$logic = 1;

      }
      # print "----------------------------------------------------------------\\n";
    }
    return ActionFalse(\$action, \$hash_field);
  }
  else{
    return ActionFalse(\$action, \$hash_field);
  }
}

################################################################################
################################## SetGrupos ###################################
################################################################################
sub DirectSetGrupos {
  # my \$self = shift;
  my (\$hash_field,\$hashref_fc) = \@_;
  my \$var_mo     = "";
  my \$var_output = "";
  # print "MO:"            . \$hash_field -> {"MO"}     . "\\n";
  if(\$hash_field -> {"MO"} =~ /"(.*)"/){\$var_mo=\$1;}
  # print "var = \$var_mo\\n";
  if(ifexists(\$var_mo))
  {
    \$var_output = \$hashref_fc->get(\$var_mo);
    # print "var_output = \$var_output\\n\\n";
    if(ifexists(\$var_output)){return \$hash_field -> {"AddTxt"} . " SetGrupos=" . \$var_output . ";\\\$\\\$";}
  }
  # print "----------------------------------------------------------------\\n\\n";

  return \$hash_field -> {"AddTxt"};
}

################################################################################
################################### Actions ####################################
################################################################################
sub ActionReview{
  my \$param         = shift;
  my \$oper          = shift;
  my \$value         = shift;
  my \$HashTextAlarm = shift;
  my \$addtxt        = shift;
  my \$cascade       = shift;
  my \$Output        = "";
  # print "Funcion ActionReview\\n";
  # print "Action: " . \$param . "\\n";
  # print "Oper  : " . \$oper  . "\\n";
  if(\$param eq "Action"){
    if(\$oper =~ "PrependAdditionalText"){
      # print "Oper  : " . \$oper                        . "\\n";
      # print "AddTxt: " . \$HashTextAlarm -> {"AddTxt"} . "\\n";
      if(\$value =~ /^".*"/){
        \$value =~ s/"//g;
      }
      if(ifexists \$HashTextAlarm -> {"AddTxt"}){\$Output = \$value . \$HashTextAlarm -> {"AddTxt"};}
      else{\$Output = \$value;}
      return \$Output;
    }
    elsif(\$oper =~ "SetEventSeverity"){
      # print "Oper: " . \$oper                    . "\\n";
      # print "PS  : " . \$HashTextAlarm -> {"PS"} . "\\n";
      \$Output = \$value;
      return \$Output;
    }
    elsif(\$oper =~ "SetIncidentType"){
      # print "Estoy en SetIncidentType\\n";
      # print "Oper: "   . \$oper . "Add " . \$value . " to AddTxt\\n";
      if(\$value =~ /^".*"/){
        \$value =~ s/"//g;
      }

      if(ifexists \$HashTextAlarm -> {"AddTxt"}){
        if(\$HashTextAlarm -> {"AddTxt"} =~ /SetIncidentType=.*;\\\$\\\$/){

          if(ifexists \$cascade){

            if(\$cascade eq "NonCascade"){
              \$Output = \$addtxt;
              \$Output =~ s/ SetIncidentType=.*?;\\\$\\\$/ SetIncidentType=\$value;\\\$\\\$/;
            }
            else{
              \$Output = \$addtxt;
            }

          }else{
            \$Output = \$addtxt . " SetIncidentType=" . \$value . ";\\\$\\\$";
          }

        }else{
          \$Output = \$HashTextAlarm -> {"AddTxt"} . " SetIncidentType=" . \$value . ";\\\$\\\$";
        }
      }
      else{\$Output = " SetIncidentType=" . \$value . ";\\\$\\\$";}

      return \$Output;
    }
    elsif(\$oper =~ "SetUserText"){
      # print "Oper: "   . \$oper . "Add " . \$value . " to AddTxt\\n";
      if(\$value =~ /^".*"/){
        \$value =~ s/"//g;
      }

      if(ifexists \$HashTextAlarm -> {"AddTxt"}){

        if(\$HashTextAlarm -> {"AddTxt"} =~ /SetUserText=.*;\\\$\\\$/){

          if(ifexists \$cascade){

            if(\$cascade eq "NonCascade"){
              \$Output = \$addtxt;
              \$Output =~ s/ SetUserText=.*?;\\\$\\\$/ SetUserText=\$value;\\\$\\\$/;
            }
            else{
              \$Output = \$addtxt;
            }

          }else{
            \$Output = \$addtxt . " SetUserText=" . \$value . ";\\\$\\\$";
          }
        }
        else{
          \$Output = \$HashTextAlarm -> {"AddTxt"} . " SetUserText=" . \$value . ";\\\$\\\$";
        }

      }
      else{\$Output = " SetUserText=" . \$value . ";\\\$\\\$";}

      return \$Output;
    }
    elsif(\$oper =~ "SetGrupos"){
      # print "Oper: "   . \$oper . "Add " . \$value . " to AddTxt\\n";
      if(\$value =~ /^".*"/){
        \$value =~ s/"//g;
      }

      if(ifexists \$HashTextAlarm -> {"AddTxt"}){

        if(\$HashTextAlarm -> {"AddTxt"} =~ /SetGrupos=.*;\\\$\\\$/){

          if(ifexists \$cascade){

            if(\$cascade eq "NonCascade"){
              \$Output = \$addtxt;
              \$Output =~ s/ SetGrupos=.*?;\\\$\\\$/ SetGrupos=\$value;\\\$\\\$/;
            }
            else{
              \$Output = \$addtxt;
            }

          }else{
            \$Output = \$addtxt . " SetGrupos=" . \$value . ";\\\$\\\$";
          }

        }
        else{
          \$Output = \$HashTextAlarm -> {"AddTxt"} . " SetGrupos=" . \$value . ";\\\$\\\$";
        }

      }
      else{\$Output = " SetGrupos=" . \$value . ";\\\$\\\$";}

      return \$Output;
    }
    elsif(\$oper =~ "SetEventManagedObject"){
      # print "Oper: "   . \$oper                        . "\\n";
      # print "MO: " . \$HashTextAlarm -> {"MO"} . "\\n";
      if(\$value =~ /^".*"/){
        \$value =~ s/"//g;
      }
      \$Output = \$value;
      return \$Output;
    }
  }
}

sub ActionFalse{
  my \$oper          = shift;
  my \$HashTextAlarm = shift;
  # print "Funcion ActionFalse\\n";
  # print "Oper  : " . \$oper  . "\\n";
  if(\$oper =~ "PrependAdditionalText"){
    return \$HashTextAlarm -> {"AddTxt"};
  }
  elsif(\$oper =~ "SetEventSeverity"){
    return \$HashTextAlarm -> {"PS"};
  }
  elsif(\$oper =~ "SetIncidentType"){
    return \$HashTextAlarm -> {"AddTxt"};
  }
  elsif(\$oper =~ "SetUserText"){
    return \$HashTextAlarm -> {"AddTxt"};
  }
  elsif(\$oper =~ "SetGrupos"){
    return \$HashTextAlarm -> {"AddTxt"};
  }
  elsif(\$oper =~ "SetEventManagedObject"){
    return \$HashTextAlarm -> {"MO"};
  }
  # else{
    # # print "[ERROR]: The action\"" . \$oper . "\\" is not identified.\\n";

  # }
}


################################################################################
################################## Operations ##################################
################################################################################
sub IsPresent{
  my \$oper          = shift;
  my \$value         = shift;
  my \$HashTextAlarm = shift;
  my \$Output        = "";
  my \$vl            = 1;
  if(ifexists \$HashTextAlarm -> {"AddTxt"}){

    if   (\$oper eq "SetGrupos"){
      # print "IsPresent: SetGrupos\\n";
      \$vl = functionMatch(\$HashTextAlarm -> {"AddTxt"},\$value);
    }
    elsif(\$oper eq "SetIncidentType"){
      # print "IsPresent: SetIncidentType, Value: " . \$value . "\\n";
      \$vl = functionMatch(\$HashTextAlarm -> {"AddTxt"},\$value);
      # print "IsPresent: SetIncidentType, Value: " . \$vl . "\\n";
    }
    elsif(\$oper eq "SetUserText"){
      # print "IsPresent: SetUserText\\n";
      \$vl = functionMatch(\$HashTextAlarm -> {"AddTxt"},\$value);
    }
    else{
      \$vl = 0;
    }

  }else{
    \$vl = 0;
  }

  return \$vl;
}

sub Operations{
  my \$param         = shift;
  my \$oper          = shift;
  my \$value         = shift;
  my \$HashTextAlarm = shift;
  my \$var           = "";
  my \$vl            = 1;
  if(\$param eq "AddTxt"){
    if(ifexists \$HashTextAlarm -> {"AddTxt"}){
      if(\$oper eq "match"){
        \$vl = functionMatch(\$HashTextAlarm -> {"AddTxt"},\$value);
      }elsif(\$oper eq "equal"){
        \$vl = functionEqual(\$HashTextAlarm -> {"AddTxt"},\$value);
      }
    }else{
      \$vl = 0;
    }
  }
  elsif(\$param eq "MO"){
    if(ifexists \$HashTextAlarm -> {"MO"}) {
      if(\$oper eq "match"){
        \$vl = functionMatch(\$HashTextAlarm -> {"MO"},\$value);
      }elsif(\$oper eq "equal"){
        \$var = \$HashTextAlarm -> {"MO"};
        \$var =~ s/^"//;
        \$var =~ s/"\$//;
        \$vl  = functionEqual(\$var,\$value);
      }
    }else{
      \$vl = 0;
    }

  }
  elsif(\$param eq "PS"){
    if(isInteger(\$HashTextAlarm -> {"PS"})){
      if(\$oper eq "eq"){
        \$vl = functionEq(\$value,\$HashTextAlarm -> {"PS"});
        # print "Logica eq: \$vl\\n";
      }
      elsif(\$oper eq "ne"){
        \$vl = functionNe(\$value,\$HashTextAlarm -> {"PS"});
        # print "Logica ne: \$vl\\n";
      }elsif(\$oper eq "lt"){
        \$vl = PSlt(\$value,\$HashTextAlarm -> {"PS"});
        # print "Logica lt: \$vl\\n";
      }elsif(\$oper eq "gt"){
        \$vl = PSgt(\$value,\$HashTextAlarm -> {"PS"});
        # print "Logica gt: \$vl\\n";
      }elsif(\$oper eq "le"){
        \$vl = PSle(\$value,\$HashTextAlarm -> {"PS"});
        # print "Logica le: \$vl\\n";
      }elsif(\$oper eq "ge"){
        \$vl = PSge(\$value,\$HashTextAlarm -> {"PS"});
        # print "Logica ge: \$vl\\n";
      }
    }else{
      \$vl = 0;
    }
  }
  elsif(\$param eq "PC"){
    if(isInteger(\$HashTextAlarm -> {"PC"})){
      if(\$oper eq "eq"){
        \$vl = functionEq(\$value,\$HashTextAlarm -> {"PC"});
      }
      elsif(\$oper eq "ne"){
        \$vl = functionNe(\$value,\$HashTextAlarm -> {"PC"});
      }elsif(\$oper eq "lt"){
        \$vl = functionLt(\$value,\$HashTextAlarm -> {"PC"});
      }elsif(\$oper eq "gt"){
        \$vl = functionGt(\$value,\$HashTextAlarm -> {"PC"});
      }elsif(\$oper eq "le"){
        \$vl = functionLe(\$value,\$HashTextAlarm -> {"PC"});
      }elsif(\$oper eq "ge"){
        \$vl = functionGe(\$value,\$HashTextAlarm -> {"PC"});
      }
    }else{
      \$vl = 0;
    }
  }
  # print "Operation, Logic: " . \$vl . "\\n";
  return \$vl;
}

################################################################################
################################## File Name ###################################
################################################################################

sub changeFileName{
  my \$file = shift;
  if(\$file =~ /(.*)\\.yes/){
    return "\$1.no";
  }else{
    return "\$file";
  }
}
################################################################################
############################# Comparison of String #############################
################################################################################

sub functionMatch{
  my \$text  = shift;
  my \$match = shift;
  my \$l     = shift;
  eval{
    \$l = (\$text =~ /\$match/);
    return \$l;
  }or do{
    return 0;
  };
}

# sub functionMatch{
#   my \$text  = shift;
#   my \$match = shift;
#   if(\$text =~ /\$match/){
#     return 1;
#   }else{
#     return 0;
#   }
# }

sub functionEqual{
  my \$text  = shift;
  my \$equal = shift;
  if(\$text eq \$equal){
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
  my \$val1 = shift;
  my \$val2 = shift;
  if(\$val1 == \$val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionNe{
  my \$val1 = shift;
  my \$val2 = shift;
  if(\$val1 != \$val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionLt{
  my \$val1 = shift;
  my \$val2 = shift;
  if(\$val1 < \$val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionGt{
  my \$val1 = shift;
  my \$val2 = shift;
  if(\$val1 > \$val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionLe{
  my \$val1 = shift;
  my \$val2 = shift;
  if(\$val1 <= \$val2){
    return 1;
  }else{
    return 0;
  }
}

sub functionGe{
  my \$val1 = shift;
  my \$val2 = shift;
  if(\$val1 >= \$val2){
    return 1;
  }else{
    return 0;
  }
}


################################################################################
########################### Comparison of Numbers PS ###########################
################################################################################

sub PSle{
  my \$val1 = shift;
  my \$val2 = shift;

  # print "val1 -> " . \$val1 . " le val2 -> " . \$val2 . "\\n";

  if(\$val1 ne "5" and \$val2 ne "5"){

    if(\$val2 eq "0"){
      # print ">> " . \$val1 . " <= " . \$val2 . " -> 1\\n";
      return 1;
    }else{
      if(\$val1 eq "0"){
        # print ">> " . \$val1 . " <= " . \$val2 . " -> 0\\n";
        return 0;
      }else{
        if(\$val1 <= \$val2){
          # print ">> " . \$val1 . " <= " . \$val2 . " -> 1\\n";
          return 1;
        }else{
          # print ">> " . \$val1 . " <= " . \$val2 . " -> 0\\n";
          return 0;
        }
      }
    }

  }else{
    return 0;
  }

}

sub PSlt{
  my \$val1 = shift;
  my \$val2 = shift;

  # print "val1 -> " . \$val1 . " lt val2 -> " . \$val2 . "\\n";

  if(\$val1 ne "5" and \$val2 ne "5"){

    if(\$val2 eq "0"){
      if(\$val1 eq  "0"){
        return 0;
      }else{
        return 1;
      }
      # print ">> " . \$val1 . " <= " . \$val2 . " -> 1\\n";
    }else{
      if(\$val1 eq "0"){
        # print ">> " . \$val1 . " <= " . \$val2 . " -> 0\\n";
        return 0;
      }else{
        if(\$val1 < \$val2){
          # print ">> " . \$val1 . " <= " . \$val2 . " -> 1\\n";
          return 1;
        }else{
          # print ">> " . \$val1 . " <= " . \$val2 . " -> 0\\n";
          return 0;
        }
      }
    }

  }else{
    return 0;
  }

}

sub PSge{
  my \$val1 = shift;
  my \$val2 = shift;

  # print "val1 -> " . \$val1 . " ge val2 -> " . \$val2 . "\\n";

  if(\$val1 ne "5" and \$val2 ne "5"){

    if(\$val1 eq "0"){
      # print ">> " . \$val1 . " >= " . \$val2 . " -> 1\\n";
      return 1;
    }else{
      if(\$val2 eq "0"){
        # print ">> " . \$val1 . " >= " . \$val2 . " -> 1\\n";
        return 0;
      }else{
        if(\$val1 >= \$val2){
          # print ">> " . \$val1 . " >= " . \$val2 . " -> 1\\n";
          return 1;
        }else{
          # print ">> " . \$val1 . " >= " . \$val2 . " -> 0\\n";
          return 0;
        }
      }
    }

  }else{
    return 0;
  }

}

sub PSgt{
  my \$val1 = shift;
  my \$val2 = shift;

  # print "val1 -> " . \$val1 . " gt val2 -> " . \$val2 . "\\n";

  if(\$val1 ne "5" and \$val2 ne "5"){

    if(\$val1 eq "0"){
      # print ">> " . \$val1 . " >= " . \$val2 . " -> 1\\n";
      return 0;
    }else{
      if(\$val2 eq "0"){
        # print ">> " . \$val1 . " >= " . \$val2 . " -> 1\\n";
        return 0;
      }else{
        if(\$val1 > \$val2){
          # print ">> " . \$val1 . " >= " . \$val2 . " -> 1\\n";
          return 1;
        }else{
          # print ">> " . \$val1 . " >= " . \$val2 . " -> 0\\n";
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
  my \$input = shift;
  if(ifexists \$input){
    if(\$input !~ /\\d+\\.\\d+/){
      if(\$input =~ /\\d+/){
        # print "IsInteger: \\"" . \$input . "\\"\\n";
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

END_CODE

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_corrective_filter", 'success');
    return 1;
}



sub crear_configurator {
    my ($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo) = @_;

    my $archivo_configurator = File::Spec->catfile($ruta_agente_abr, "CONFIGURATOR.pm");

    if (-e $archivo_configurator) {
        open my $fh, '>', $archivo_configurator or do {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
            return;
        };
        close $fh;
    }

    open my $fh, '>', $archivo_configurator or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
    };
        # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_abr);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo Configurator: $archivo_configurator");



    print $fh <<"END_CODE";
package ABR::CONFIGURATOR;
# Version=6.0
use ABR::HashOrder;
use warnings;
use strict;
use Carp;
use Data::Dumper;


# Constructor
sub new {
    my (\$class, \%args) = \@_;
    my \$config_file = \$args{config_file} or die "> [ERROR]: CONFIGURATOR.pm, Configurator: No configuration file provided\\n";
    my \%hash_read;
    return bless { config_file => \$config_file, hash_read => \\\%hash_read }, \$class;
}

# Main function to read the configuration file
sub read_config {
    my \$self = shift;
    my \$config_file = \$self->{config_file};
    my \$config_ref  = \$self->{hash_read};
    my \$hashOrdered = ABR::HashOrder->new();

    eval {
        open(my \$fh, '<', \$config_file) or croak "Error: Could not open the configuration file: \$config_file";
        while (my \$line = <\$fh>) {
            chomp(\$line);
            next if \$line =~ /^\s*\$/ or \$line =~ /^#/;  # Skip empty lines and comments
            my (\$index, \$value) = parse_line(\$line);

            # Eliminar espacios en blanco al principio y al final
            \$index =~ s/^s+|s+\$//g;  # Trim leading and trailing whitespace
            \$value =~ s/^s+|s+\$//g;  # Trim leading and trailing whitespace
            # Eliminar saltos de línea
            \$index =~ s/[\\r\\n]//g;
            \$value =~ s/[\\r\\n]//g;

            \$hashOrdered->set(\$index => \$value);
        }
        close(\$fh);
        \$config_ref->{"GLOBAL"} = \$hashOrdered;
    };
    if (\$\@) {
        print STDERR "Error in read_config: \$\@\\n";
        croak "Error in read_config: \$\@";
    }

    return \$config_ref;
}

# Helper function to parse a line from the configuration file
sub parse_line {
    my (\$line) = \@_;
    my \@splitted = split(":=", \$line);
    \$splitted[0] =~ s/^\s+|\s+\$//g;  # Trim leading and trailing whitespace
    \$splitted[1] =~ s/^\s+|\s+\$//g;  # Trim leading and trailing whitespace
    return (\$splitted[0], \$splitted[1]);
}

# Function to read a map from the configuration file
sub read_map {
    my (\$self, \$tag, \$sep, \$config_file) = \@_;
    my \$hash_ref    = \$self->{hash_read};
    my \$hashOrdered = ABR::HashOrder->new();

    unless (\$config_file) {
        print STDERR "> [ERROR]: CONFIGURATOR.pm, Verify configuration file: AGENT.properties\\n";
        die "> [ERROR]: CONFIGURATOR.pm, Could not open the configuration file\\n";
    }

    open(my \$fh, '<', \$config_file) or die "> [ERROR]: CONFIGURATOR.pm, Could not open the configuration file: \$config_file\\n";
    while (my \$line = <\$fh>) {
        chomp(\$line);
        next if \$line =~ /^\s*\$/ or \$line =~ /^#/;
        my \@splitted = split(\$sep, \$line);
        my \$index = ifexists(\$splitted[0]) ? \$splitted[0] =~ s/^\s+|\s+\$//gr : '';
        my \$value = ifexists(\$splitted[1]) ? \$splitted[1] =~ s/^\s+|\s+\$//gr : '';
        \$hashOrdered->set(\$index => \$value) if \$index && \$value;
    }
    close(\$fh);

    \$hash_ref->{\$tag} = \$hashOrdered;
    return \$hash_ref;
}

# Function to check if a variable exists and is not empty
sub ifexists {
    my \$variable = shift;
    return defined \$variable && \$variable ne "";
}

1;
END_CODE

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_configurator", 'success');
    return 1;
}


# Crear MAP_Severtity
sub crear_map_severity {
    my ($ventana_principal, $agente, $ruta_agente_conf, $implementacion, $impresiones_desarrollo, $data_extra) = @_;

    my $archivo_map_severity = File::Spec->catfile($ruta_agente_conf, 'MAP_Severity');

    if (-e $archivo_map_severity) {
        open my $fh, '>', $archivo_map_severity or do {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
            return;
        };
        close $fh;
    }

    open my $fh, '>', $archivo_map_severity or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
    };


    # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_conf);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo Mapeo de la severidad: $archivo_map_severity");
    my $map_severity = $data_extra->{text_entries}->{'Informacion MAP Severity'};
    # Eliminar espacios en blanco al principio y al final de cada línea
    my @lineas = split /\n/, $map_severity;
    @lineas = map { s/^\s+|\s+$//gr } @lineas;
    $map_severity = join "\n", @lineas;
    print $fh <<"END_CODE";
    # Mapa de severidad
    $map_severity
END_CODE
    close $fh or warn "Advertencia: No se pudo cerrar el archivo editado:";

    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_map_severity", 'success');
    return 1;
  }
  # Crear MAP_Hostname
  sub crear_map_hostname {
    my ($ventana_principal, $agente, $ruta_agente_conf, $implementacion, $impresiones_desarrollo, $data_extra) = @_;

    my $archivo_map_hostname = File::Spec->catfile($ruta_agente_conf, 'MAP_Hostname');

    if (-e $archivo_map_hostname) {
      open my $fh, '>', $archivo_map_hostname or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
      };
      close $fh;
    }

    open my $fh, '>', $archivo_map_hostname or do {
      herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
      return;
    };

    # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_conf);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo Mapeo de hostname: $archivo_map_hostname");
    my $map_hostname = $data_extra->{text_entries}->{'Informacion MAP HostName'};
    # Eliminar espacios en blanco al principio y al final de cada línea
    my @lineas = split /\n/, $map_hostname;
    @lineas = map { s/^\s+|\s+$//gr } @lineas;
    $map_hostname = join "\n", @lineas;
    print $fh <<"END_CODE";
    # Mapa de hostname
    $map_hostname
END_CODE
    close $fh or warn "Advertencia: No se pudo cerrar el archivo editado:";

    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_map_hostname", 'success');
    return 1;
    }

sub crear_map_example_external {
    my ($ventana_principal, $agente, $ruta_agente_conf, $implementacion, $impresiones_desarrollo, $data_extra) = @_;

    my $archivo_map_example_external = File::Spec->catfile($ruta_agente_conf, 'MAP_ExampleExternal');

    if (-e $archivo_map_example_external) {
      open my $fh, '>', $archivo_map_example_external or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
      };
      close $fh;
    }

    open my $fh, '>', $archivo_map_example_external or do {
      herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
      return;
    };

    # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_conf);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo Mapeo de ejemplo externo: $archivo_map_example_external");
    my $map_example_external = $data_extra->{text_entries}->{'Informacion Map Example External'};
    # Eliminar espacios en blanco al principio y al final de cada línea
    my @lineas = split /\n/, $map_example_external;
    @lineas = map { s/^\s+|\s+$//gr } @lineas;
    $map_example_external = join "\n", @lineas;
    print $fh <<"END_CODE";
    # Mapa de ejemplo externo
    $map_example_external
END_CODE
    close $fh or warn "Advertencia: No se pudo cerrar el archivo editado:";

    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_map_example_external", 'success');
    return 1;
    }






sub crear_archivos_mapeo {
    my ($ventana_principal, $agente ,$ruta_agente, $implementacion, $impresiones_desarrollo) = @_;

    my $ruta_agente_completa = File::Spec->catfile($ruta_agente, $agente);
    # Validar si el nombre del agente se repite en la ruta completa
    if ($ruta_agente_completa =~ /$agente.*$agente/) {
        $ruta_agente_completa =~ s/\\$agente//;
    }
    my $ruta_agente_conf = File::Spec->catfile($ruta_agente_completa, 'CONF');

    unless (-d $ruta_agente_completa) {
        my $entry_ruta_agente = herramientas::Complementos::register_directory($ventana_principal, 'Selecciona la ruta donde se creara el agente', "Buscar");
        $ruta_agente_completa = File::Spec->catfile($entry_ruta_agente, $agente);
        unless (-d $ruta_agente_completa) {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', 'La ruta del agente no existe', 'error');
            return;
        }
    }

      # Data extra
      my %lista_opciones_text = (
        opciones => {
            'Informacion MAP Severity'  => "
            Clared -> 5
            Clear -> 5
            clear -> 5
            Critical -> 1
            Cri -> 1
            Major -> 2
            Mayor -> 2
            Minor -> 3
            Menor -> 3
            Warning -> 4",
            'Informacion MAP HostName'  => "
            127.* -> TEST_LOCAL
            100.127.5 -> BU(S)
            100.127.5.80 -> BUS (1)
            100.127.5.81 -> BUS (2)
            100.127.5.81 -> BUS (3)",
          'Informacion Map Example External' => "
            Clared -> 5
            Clear -> 5
            clear -> 5
            Critical -> 1
            Cri -> 1
            Major -> 2
            Mayor -> 2
            Minor -> 3
            Menor -> 3
            Warning -> 4
            0 -> 0
            1 -> 1
            2 -> 2
            3 -> 3
            4 -> 4
            5 -> 5
          ",

        }
    );

    my $data_extra = herramientas::Complementos::create_scrollable_panel_with_checkboxes_and_entries($ventana_principal, "Mapeo externo",  0, 0, 0, \%lista_opciones_text);

    crear_map_severity($ventana_principal, $agente, $ruta_agente_conf, $implementacion, $impresiones_desarrollo, $data_extra );
    crear_map_hostname($ventana_principal, $agente, $ruta_agente_conf, $implementacion, $impresiones_desarrollo, $data_extra );
    crear_map_example_external($ventana_principal, $agente, $ruta_agente_conf, $implementacion, $impresiones_desarrollo, $data_extra );

  }


sub crear_archivos_genericos {
    my ($ventana_principal, $agente ,$ruta_agente, $implementacion, $impresiones_desarrollo) = @_;

    my $ruta_agente_completa = File::Spec->catfile($ruta_agente, $agente);
    # Validar si el nombre del agente se repite en la ruta completa
    if ($ruta_agente_completa =~ /$agente.*$agente/) {
        $ruta_agente_completa =~ s/\\$agente//;
    }
    my $ruta_agente_abr = File::Spec->catfile($ruta_agente_completa, 'ABR');

    unless (-d $ruta_agente_completa) {
        my $entry_ruta_agente = herramientas::Complementos::register_directory($ventana_principal, 'Selecciona la ruta donde se creara el agente', "Buscar");
        $ruta_agente_completa = File::Spec->catfile($entry_ruta_agente, $agente);
        unless (-d $ruta_agente_completa) {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', 'La ruta del agente no existe', 'error');
            return;
        }
    }

   
    my $direcciones_ip = Rutas::ip_generales_path();
    $direcciones_ip = herramientas::Complementos::parse_file($direcciones_ip);

    
    my %lista_opciones_combo_box = (
        opciones => {
            'Servidor instalacion' => [
                map { @$_ } values %$direcciones_ip
            ],
        }
    );

    my %lista_opciones_entry = (
        opciones => {
            'local port' => 3434,
            'host name' => '',
        }
    );


    my $data_extra = herramientas::Complementos::create_scrollable_panel_with_checkboxes_and_entries($ventana_principal, "Selecciona un servidor",  0, \%lista_opciones_entry, \%lista_opciones_combo_box);

    crear_configurator($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo);
    crear_corrective_filter($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo);
    crear_file_handler($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo);
    create_hashorder($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo);
    create_llenaComun($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo);
    create_microtime($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo);
    create_tapfilter($ventana_principal, $agente, $ruta_agente_abr, $implementacion, $impresiones_desarrollo);
    create_snmpagente($ventana_principal, $agente, $ruta_agente_abr, $data_extra, $implementacion, $impresiones_desarrollo);

}


sub crear_archivo_subrutinas {
    my ($ventana_principal, $agente, $ruta_agente, $alarmas_principales, $alarmas_secundarias, $implementacion, $impresiones_desarrollo) = @_;
    $agente ||= 'agente_snmp';

    my $ruta_agente_completa = File::Spec->catfile($ruta_agente, $agente);
    # Validar si el nombre del agente se repite en la ruta completa
    if ($ruta_agente_completa =~ /$agente.*$agente/) {
        $ruta_agente_completa =~ s/\\$agente//;
    }

    unless (-d $ruta_agente_completa) {
        my $entry_ruta_agente = herramientas::Complementos::register_directory($ventana_principal, 'Selecciona la ruta donde se creara el agente', "Buscar");
        $ruta_agente_completa = File::Spec->catfile($entry_ruta_agente, $agente);
        unless (-d $ruta_agente_completa) {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', 'La ruta del agente no existe', 'error');
            return;
        }
    }
    
    my %lista_opciones_checkbox = (
        opciones => {
            'Agregar (description) Adiccional Text' => 0, 
            'Agregar (TrapName)  Adiccional Text'   => 0,   
            'Asignar Severidad (description)'       => 0,
        }
    );

    my %lista_opciones_entry = (
        opciones => {
            'Esteblecer Severidad'                => 2,
            'Establecer Probable Cause'           => 0,
            'Establecer Event Type'               => 10,
            'Establecer Specific Problem'         => 0,
            'Establecer Notification ID (sucesivo)' => 1300,
        }
    );

    my %lista_opciones_combo_box = (
        opciones => {
            'Establecer Additional Text'  => ['Vacio', 'Descripcion', 'Descripcion + TrapName'],
            'Establecer Managed Object'   => ['Vacio', 'Host + Agent address + MO', 'Entrada generica'],
        }
    );

    my $data_extra = herramientas::Complementos::create_scrollable_panel_with_checkboxes_and_entries($ventana_principal, "Opciones de estructura",  \%lista_opciones_checkbox, \%lista_opciones_entry, \%lista_opciones_combo_box);

    my $archivo_agente = File::Spec->catfile($ruta_agente_completa, 'ABR', "$agente.pm");
    
    if (-e $archivo_agente) {
        open my $fh, '>', $archivo_agente or do {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
            return;
        };
        close $fh;
    }
    
    open my $fh, '>>', $archivo_agente or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
    };
        # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_completa);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo Subrutinas: $archivo_agente");

   
    print $fh <<"END_CODE";
package ABR::$agente;

use warnings;
use strict;
use Digest::MurmurHash qw(murmur_hash);
use ABR::llenaComun;
my \$llena = ABR::llenaComun->new();
use ABR::CorrectiveFilter;
my \$cf = ABR::CorrectiveFilter->new(split_filter1 => '\\<&&\\>', split_filter2 => '\\<\\>');

my \$dat_MO;

sub ifexists {
    my \$variable = shift;
    return defined \$variable && \$variable ne "";
}

sub ifExistsAndNumber {
    my \$variable = shift;
    return defined \$variable && \$variable ne "" && \$variable =~ /^[-+]?[0-9]*\\.?[0-9]+\$/;
}

sub HostRegex {
    my (\$configHost_ref, \$ip_address) = \@_;
    my \$salida = "";
    if (ifexists(\$configHost_ref)) {
        foreach my \$k (\$configHost_ref->keys) {
            if (\$ip_address =~ /\\\$k/) {
                \$salida = \$configHost_ref->get(\$k);
            }
        }
    }
    return \$salida;
}

sub get_managed_object {
    my (\$hostname, \$agent_address, \$dat_managed_object) = \@_;
    my \$dat_MO = "";
    if (ifexists(\$hostname)) {
        if (ifexists(\$dat_managed_object)) {
            \$dat_MO = \$hostname . " " . \$dat_managed_object;
        } else {
            \$dat_MO = \$hostname;
        }
    } elsif (ifexists(\$dat_managed_object)) {
        \$dat_MO = "HostND " . \$agent_address . " " . \$dat_managed_object;
    } else {
        \$dat_MO = "HostND " . \$agent_address;
    }
    if (ifexists(\$dat_MO)) {
        \$dat_MO =~ s/"//g;
        \$dat_MO = "\\"" . \$dat_MO . "\\"";
    }
    return \$dat_MO;
}

sub FuncAdditionalInfo {
    my (\$entrada, \$tp_name) = \@_;
    my \$add_info = " | AddInfo: trap name=" . \$tp_name . ", ";
    foreach my \$k (keys %\$entrada) {
        unless (\$k =~ /^(IPADDR|EOID|SPEC_TRAP|GEN_TRAP|1.3.6.1.2.1.1.3|1.3.6.1.6.3.1.1.4.1)\$/) {
            if (ifexists(\$entrada->{\$k})) {
                \$add_info .= " " . \$k . ": " . \$entrada->{\$k} . ";";
            }
        }
    }
    return \$add_info;
}

sub CorrectiveFilter {
    my (\$hashAlarm_ref, \$config_ref, \$action, \$var, \$c) = \@_;
    my \$output = \$cf->ProcessingCF(\$hashAlarm_ref, \$config_ref, \$action, \$c);
    if (ifexists(\$output)) {
        return \$output;
    } elsif (\$var =~ "MO") {
        return \$hashAlarm_ref->{"MO"};
    } elsif (\$var =~ "AddTxt") {
        return \$hashAlarm_ref->{"AddTxt"};
    } elsif (\$var =~ "PS") {
        return \$hashAlarm_ref->{"PS"};
    }
}

sub trapSeverity {
    my \$vSeverity = shift;
    my \$severity = "";
    if (\$vSeverity eq "5") { \$severity = "Clear"; }
    if (\$vSeverity eq "4") { \$severity = "Critical"; }
    if (\$vSeverity eq "3") { \$severity = "Major"; }
    if (\$vSeverity eq "1") { \$severity = "Warning"; }
    if (\$vSeverity eq "0") { \$severity = "Clear"; }
    if (\$vSeverity eq "2") { \$severity = "Minor"; }
    if (\$vSeverity eq "6") { \$severity = "0"; }
    return \$severity;
}

END_CODE

    my $notification_id = $data_extra->{entries}->{'Establecer Notification ID (sucesivo)'} || 1300;

    foreach my $alarm_name (keys %$alarmas_principales) {
        my $oid = $alarmas_principales->{$alarm_name}->{OID};
        my $description = $alarmas_principales->{$alarm_name}->{DESCRIPTION};
        $oid =~ s/\./_/g;  # Replace dots with underscores for subroutine name
        
        my $var_ps = $data_extra->{entries}->{'Esteblecer Severidad'};
        my $var_sp = $data_extra->{entries}->{'Establecer Specific Problem'};
        my $var_pc = $data_extra->{entries}->{'Establecer Probable Cause'};
        my $var_EventType = $data_extra->{entries}->{'Establecer Event Type'};
        
        my $addTxt = '';
        if ($data_extra->{combo_boxes}->{'Establecer Additional Text'} eq 'Descripcion') {
            $addTxt = $description . ",\n";
        } elsif ($data_extra->{combo_boxes}->{'Establecer Additional Text'} eq 'Descripcion + TrapName') {
            $addTxt = $description . "\\nTrapName = " . $alarm_name . ",\\n";
        }
        
        my $mo = '';
        if ($data_extra->{combo_boxes}->{'Establecer Managed Object'} eq 'Host + Agent address + MO') {
            $mo = 'get_managed_object($hostname, $agent_address, $entrada -> {"1.3.6.1.6.3.18.1.3"})';
        } elsif ($data_extra->{combo_boxes}->{'Establecer Managed Object'} eq 'Entrada generica') {
            $mo = '\$entrada->{"1.3.6.1.6.3.18.1.3"}';
        }

        print $fh <<"END_SUB";
# $alarm_name
sub _$oid
{
    my \$entrada = shift;
    my \$trap_name = shift;
    my \$config_ref = shift;
    my \%config = %\$config_ref;

    my \$alarm_txt;

    my \$agent_address = \$entrada->{"IPADDR"};
    my \$dat_event_time = \$llena->fecha();
    

    my \$dat_severity = $var_ps;
    my \$dat_specific_problem = $var_sp;
    my \$dat_probable_cause = $var_pc;
    my \$dat_event_type = $var_EventType;
    my \$dat_additional_text = "$addTxt";
    
    my \$dat_notification_id = $notification_id;
    my \$dat_correlated_notification_id = "";

    my \$hostname = HostRegex(\$config{"HOST"}, \$agent_address);
    my \$dat_managed_object = $mo;

    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
END_SUB
        if (exists $alarmas_secundarias->{$alarm_name}) {
            foreach my $sec_alarm (keys %{$alarmas_secundarias->{$alarm_name}}) {
                my $oid_sec = $alarmas_secundarias->{$alarm_name}->{$sec_alarm};
                print $fh <<"END_SEC_ALARM";
    if (ifexists(\$entrada->{"$oid_sec"})) {
        \$dat_additional_text .= "\\n$sec_alarm = " . \$entrada->{"$oid_sec"} . ",\\n";
    }
END_SEC_ALARM
            }
        }

        print $fh <<"END_SUB";
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    \$llena->llenaMO("MO:" . \$dat_managed_object) if (ifexists(\$dat_managed_object));
    \$llena->llenaPC("PC:" . \$dat_probable_cause) if (ifexists(\$dat_probable_cause));
    \$llena->llenaSP("SP:" . \$dat_specific_problem) if (ifexists(\$dat_specific_problem));
    \$llena->llenaPS("PS:" . \$dat_severity) if (ifexists(\$dat_severity));
    \$llena->llenaNI("NID:" . \$dat_notification_id) if (ifexists(\$dat_notification_id));
    \$llena->llenaAT("AddTxt:" . \$dat_additional_text) if (ifexists(\$dat_additional_text));
    \$llena->EventTime("ETime:" . \$dat_event_time) if (ifexists(\$dat_event_time));
    \$llena->EventType("EType:" . \$dat_event_type) if (ifexists(\$dat_event_type));

    \$alarm_txt = \${ \$llena->{mensaje_x733} };
    \$llena->vacia_mensaje_x733();
    \$alarm_txt = "###START###" . \$alarm_txt . "###END###";

    return \$alarm_txt;
}

END_SUB
        $notification_id++;
    }
print $fh <<"END_SUB";
1;
END_SUB

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO',
    "Se creo correctamente el archivo $archivo_agente", 'success'
    );
    # Retorna true si se creo correctamente el archivo
    return 1;
}




# Placeholder functions for card commands
sub crear_codigo_principal {
    my ($ventana_principal, $agente, $ruta_agente, $alarmas_principales, $alarmas_secundarias, $implementacion, $impresiones_desarrollo) = @_;
    my $ruta_agente_completa = File::Spec->catfile($ruta_agente, $agente);
    # Validar si el nombre del agente se repite en la ruta completa
    if ($ruta_agente_completa =~ /$agente.*$agente/) {
        $ruta_agente_completa =~ s/\\$agente//;
    }
    
    unless (-d $ruta_agente_completa) {
        my $entry_ruta_agente = herramientas::Complementos::register_directory($ventana_principal, 'Selecciona la ruta donde se creara el agente', "Buscar");
        $ruta_agente_completa = File::Spec->catfile($entry_ruta_agente, $agente);
        unless (-d $ruta_agente_completa) {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', 'La ruta del agente no existe', 'error');
            return;
        }
        # Boton para guardar la ruta
    }
   my $archivo_principal = File::Spec->catfile($ruta_agente_completa, "agente_$agente.pl");
    
    if (-e $archivo_principal) {
        open my $fh, '>', $archivo_principal or do {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
            return;
        };
        close $fh;
    }
    open my $fh, '>', $archivo_principal or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
    };
    # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_completa);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo principal: $archivo_principal");

print $fh <<"END_CODE";
#!/usr/bin/perl -I .

use strict;
use warnings;

use ABR::HashOrder;
use FindBin;
use lib \$FindBin::Bin;

use ABR::SNMPAgente;
use ABR::FILE_HANDLER;
use ABR::MICROTIME;
use ABR::Parser_aux;
use ABR::CONFIGURATOR;
use ABR::TapFilter;

my \$conf_file    = \$FindBin::Bin . "/AGENT.properties";
my \$configurator = ABR::CONFIGURATOR -> new(config_file => \$conf_file);
my \$hashOrdered  = ABR::HashOrder -> new();
my \$hash_ref     = \$configurator -> read_config();
my \$maps         = "";
my \$bFilters     = "";
my \$cFilters     = "";
my \$ndate        = "";
my \$file_name    = "";
my \$warning      = "";
my \$timeUpdate   = "";
my \$minutos      = 0;
my \$abstract_global_hash;
my \$message;
my \$trap_ref;
my \$rtrn;

FuncInfo(\\\@ARGV,\$FindBin::Bin);

print "\\n\\nLEYENDO ARCHIVO DE CONFIGURACION GLOBAL: " . \$conf_file . "\\n";
print "INICIANDO AGENTE CON EL SIGUIENTE HASH GLOBAL:\\n";

for (keys(\%{\$hash_ref})){
  \$hashOrdered = \$\$hash_ref{\$_};
  for my \$key (\@{\$hashOrdered -> keys}){
    my \$value = \$hashOrdered -> get(\$key);
    if (\$value =~ /CONF\\/MAP.+/) {
      if(FileExists(\$FindBin::Bin . "/" . \$value) && FileIsEmpty(\$FindBin::Bin . "/" . \$value)){
        \$hash_ref = \$configurator -> read_map("\$key",'\s*->\s*',\$FindBin::Bin . "/" . \$hashOrdered -> get("\$key"));
        
        print "\\n\\n>>>>>>>        MAPA       <<<<<<<<<< - >>>>>>>>>>>    \\"\$key\\"    <<<<<<<<<<\\n >> CONTENIDO:";
        if(ifexists(\${\$hash_ref}{\$key})){
          \$maps .= "\$key,";
          \$abstract_global_hash .= "\\n > MAPA EXTERNO \\t'\$key'";
          for (\@{\${\$hash_ref}{\$key} -> keys}){
            print "\\n   > KEY: '\$_'    VALUE:    '" . \${\$hash_ref}{\$key} -> get(\$_) . "'";
          }
        }
        else{
          print "\\n   > ¡ESTE MAPA ESTA VACIO!";
          \$warning .= "\\nThe file '\$FindBin::Bin/\$value' with key '\$key' is empty and generate an empty hash. The key '\$key' will be removed from the hash";
          delete \${\$hash_ref}{\$key};
        }
      }
    }
    elsif (\$value =~ /CONF\\/FB.+/) {
      if(FileExists(\$FindBin::Bin . "/" . \$value) && FileIsEmpty(\$FindBin::Bin . "/" . \$value)){
        \$hash_ref = \$configurator -> read_map("\$key",'\s*->\s*',\$FindBin::Bin . "/" . \$hashOrdered -> get("\$key"));
        print "\\n\\n>>>>>   FILTRO DE BLOQUEO   <<<<<<<<<< - >>>>>>>>>>>   \\"\$key\\"    <<<<<<<<<<\\n >> CONTENIDO:";
        if(ifexists(\${\$hash_ref}{\$key})){
          \$bFilters .= "\$key,";
          \$abstract_global_hash .= "\\n > FILTRO DE BLOQUEO \\t'\$key'";
          for (\@{\${\$hash_ref}{\$key} -> keys}){
            print "\\n   > KEY: '\$_'    VALUE:    '" . \${\$hash_ref}{\$key} -> get(\$_) . "'";
          }
        }
        else{
          print "\\n   > ¡ESTE FILTRO ESTA VACIO!";
          \$warning .= "\\nThe file '\$FindBin::Bin/\$value' with key '\$key' is empty and generate an empty hash. The key '\$key' will be removed from the hash";
          delete \${\$hash_ref}{\$key};
        }
      }
    }
    elsif (\$value =~ /CONF\\/FC.+/) {
      if(FileExists(\$FindBin::Bin . "/" . \$value) && FileIsEmpty(\$FindBin::Bin . "/" . \$value)){
        \$hash_ref = \$configurator -> read_map("\$key",'\s*->\s*',\$FindBin::Bin . "/" . \$hashOrdered -> get("\$key"));
        print "\\n\\n>>>>>   FILTRO CORRECTIVO   <<<<<<<<<< - >>>>>>>>>>>    \\"\$key\\"   <<<<<<<<<<\\n >> CONTENIDO:";
        if(ifexists(\${\$hash_ref}{\$key})){
          \$cFilters .= "\$key,";
          \$abstract_global_hash .= "\\n > FILTRO CORRECTIVO \\t'\$key'";
          for (\@{\${\$hash_ref}{\$key} -> keys}){
            print "\\n   > KEY: '\$_'    VALUE:    '" . \${\$hash_ref}{\$key} -> get(\$_) . "'";
          }
        }
        else{
          print "\\n   > ¡ESTE FILTRO ESTA VACIO!";
          \$warning .= "\\nThe file '\$FindBin::Bin/\$value' with key '\$key' is empty and generate an empty hash. The key '\$key' will be removed from the hash";
          delete \${\$hash_ref}{\$key};
        }
      }
    }
    else {
      print "\\n>>>> INDICE: \\"\$key\\"    CON VALOR ->   \\"" . \$value . "\\"";
      \$abstract_global_hash .= "\\n > VALOR DE \$key:  '\$value'";
    }
  }
  chop(\$bFilters);
  chop(\$cFilters);
  chop(\$maps);
}

print "\\n\\n\\n ########################## RESUMEN DE DATOS DEL AGENTE ##########################";
print "\\n\\nNOMBRE DEL AGENTE: ". \$hashOrdered -> get('agt') ."\\n";

my \$host = \$hashOrdered -> get('host');
my \$port = \$hashOrdered -> get('port');
my \$glustDir = "/mnt/umplogic/" . \$hashOrdered -> get('agt');
my \$auxDir = "/mnt/umpemergency/" . \$hashOrdered -> get('agt');

my \$trapd = ABR::SNMPAgente->new(
  \$host, \$port
);
my \$fhandler = ABR::FILE_HANDLER->new(
  gluster_dir =>   \$glustDir,
  auxiliary_dir => \$auxDir
);
print "EL DIRECTORIO GLUSTER ESTA EN: \$glustDir\\n";
print "EL DIRECTORIO AUXILIARY ESTA EN: \$auxDir\\n";
if(ifexists(\$maps))    { print "LOS EXTERNAL MAPS SON: \$maps\\n";}
if(ifexists(\$bFilters)){ print "LOS BLOCKING FILTERS SON: \$bFilters\\n";}
if(ifexists(\$cFilters)){ print "LOS CORRECTIVE FILTERS SON: \$cFilters\\n";}
print "El GLOBAL HASH es: \$abstract_global_hash\\n";
if(ifexists(\$warning)){
  my \@s = split('\\n',\$warning);
  foreach(\@s){
    if(ifexists(\$_)){
      print "> \\[WARNING\\]: " . \$_ . "\\n";
    }
  }
  print "\\n";
}
print "\\n";
print "#"x80;
print "\\n";

my \$filter = ABR::TapFilter -> new(
  hash_ref      => \\\%{\$hash_ref},
  config_index  => "\$bFilters",
  split_filter1 => '\\<&&\\>' ,
  split_filter2 => '\\<\\>'
);
my \$parser = ABR::Parser_aux->new();

print " =================================== ALARMS ===================================\\n";
\$fhandler->startup_write();

while (1) {
  \$trap_ref = \$trapd->get_trap(\$hashOrdered -> get('ALARM_PRINTS'));
  if (\$trap_ref) {
    \$message = \$parser -> formatter(\$trap_ref,\$hash_ref,\$hashOrdered -> get('ALARM_PRINTS'));
    if ( defined(\$message) ) {
      \$ndate = ABR::MICROTIME::getmicro();
      \$file_name = \$hashOrdered -> get('agt') . "." . \$ndate . "." . "yes";
      \$file_name = \$filter -> ProcessingFilters(\$message, \$file_name);
      \$filter -> PrintFilterConditionFulfilled();
      \$rtrn = \$fhandler->write_file( \$file_name, \$message );
    }else {
      if(\$hashOrdered -> get('ALARM_PRINTS')){print "\\nFile not created\\n\\n  ";}
    }
  }else {
    \$fhandler->dummy_write();
  }
}

sub FileExists{
  my \$file = shift;
  if(-e \$file){
    return 1;
  }else{
    \$warning .= "\\nThe file '\$file' not found.";
    return 0;
  }
}

sub FileIsEmpty{
  my \$file = shift;
  if(-s \$file == 0){
    \$warning .= "\\nThe file '\$file' is empty.";
    return 0;
  }else{
    return 1;
  }
}

sub ifexists{
  my \$variable = shift;
  if (defined \$variable && \$variable ne ""){
    return 1;
  }else{
    return 0;
  }
}

sub FuncInfo{
  my \$input   = shift;
  my \$path    = shift;
  my \@files   = ("TapFilter.pm","CorrectiveFilter.pm","HashOrder.pm","SNMPAgente.pm","Parser_aux.pm","MICROTIME.pm","LogsFile.pm","llenaComun.pm","FILE_HANDLER.pm");
  my \$command = "";
  foreach(\@{\$input}){
    if(ifexists(\$_)){
      if(\$_ =~ /--version/){
        print "#"x80;
        print "\\nthe version of " . \$0 . " is 6.0\\n";
        print "this file " . \$0 . " uses packages with versions:\\n";

        foreach my \$f(\@files){
          if(FileExists("\$path/ABR/\$f")){
            \$command = `cat \$path/ABR/\$f | grep 'Version='`;
            chop(\$command);
            if(ifexists(\$command)){if(\$command =~ /#\\s*(Version=.*)/i){print "   -\$f -> " . \$1 . "\\n";}}
            else{print "   -\$f -> \\"is not define version\\"\\n";}
          }
        }
        die "#"x80 . "\\n";
      }elsif(\$_ =~ /--help/){
        print "#"x80;
        print "\\nValid options:\\n";
        print " --help   " . "." . \$path . "/" . \$0 . " [--help]\\n";
        print " --version   " . "." . \$path . "/" . \$0 . " [--version]\\n";
        print "\\n\\n";
        print "Run the file: " . \$0 . "\\n";
        print "execute:\\n";
        print "." . \$path . "/" . \$0 . " or" . " perl " . \$path . "/" . \$0 . "\\n";
        die "#"x80 . "\\n";
      }else{
        print "#"x80;
        print "\\nInvalid option: " . \$_ . "\\n";
        print "\\nValid options:\\n";
        print " --help   " . "." . \$path . "/" . \$0 . " [--help]\\n";
        print " --version   " . "." . \$path . "/" . \$0 . " [--version]\\n";
        die "#"x80 . "\\n";
      }
    }
  }
}
END_CODE

    close $fh or warn "Advertencia: No se pudo cerrar el archivo editado: $!";
    #close $fh_logs or warn "Advertencia: No se pudo cerrar el archivo log: $!";

    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo \$archivo_principal", 'success');
    return 1;
}




sub crear_codigo_parseador {
    my ($ventana_principal, $agente, $ruta_agente, $alarmas_principales, $alarmas_secundarias, $implementacion, $impresiones_desarrollo) = @_;
    $agente ||= 'agente_snmp';

    
    my $ruta_agente_completa = File::Spec->catfile($ruta_agente, $agente);
    
    # Validar si el nombre del agente se repite en la ruta completa
    if ($ruta_agente_completa =~ /$agente.*$agente/) {
        $ruta_agente_completa =~ s/\\$agente//;
    }

    unless (-d $ruta_agente_completa) {
        my $entry_ruta_agente = herramientas::Complementos::register_directory($ventana_principal, 'Selecciona la ruta donde se creara el agente', "Buscar");
        $ruta_agente_completa = File::Spec->catfile($entry_ruta_agente, $agente);
        unless (-d $ruta_agente_completa) {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', 'La ruta del agente no existe', 'error');
            return;
        }
    }

    my $archivo_parseador = File::Spec->catfile($ruta_agente_completa, 'ABR', "Parser_aux.pm");

    if (-e $archivo_parseador) {
        open my $fh, '>', $archivo_parseador or do {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
            return;
        };
        close $fh;
    }

    my $parser_data = generar_datos_parser($ventana_principal, $agente, $alarmas_principales);

    open my $fh, '>', $archivo_parseador or do {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el archivo: $!", 'error');
        return;
    };
    # Crear el texto de implementacion 
    my $ruta_absoluta = abs_path($ruta_agente_completa);
    my $texto_implementacion = obtener_texto_implementacion($implementacion, $ruta_absoluta, $agente);

    $logger->add_appender(Log::Log4perl::Appender->new(
      "Log::Dispatch::File",
      filename => $ruta_absoluta  . "/output.log",
      mode     => "append",
      layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("Creando archivo parseador: $archivo_parseador");


    print $fh <<"END_CODE";
package ABR::Parser_aux;
# Version=1.1
use POSIX qw(strftime);
use warnings;
use strict;

use ABR::$agente;

sub new {
    my \$class = shift;
    my \$self;
    my \$mensaje_x733;
    my \%find_hash;

    \%find_hash = (
END_CODE

    foreach my $oid (keys %$parser_data) {
        my $trap_name = $parser_data->{$oid}->{trap_name};
        my $subroutine = $parser_data->{$oid}->{subroutine};
        print $fh "        \"$oid\" => { trap_name => \"$trap_name\", subroutine => \"$subroutine\" },\n";
    }

    print $fh <<"END_CODE";
    );

    \$self = bless( { find_hash => \\\%find_hash, mensaje_x733 => \\\$mensaje_x733 }, \$class );
}

sub formatter {
    my \$self           = shift;
    my \$trap_array_ref = shift;
    my \$config         = shift;
    my \$onPrints       = shift;
    my \@trap_array     = \@{\$trap_array_ref};
    my \$find_hash      = \$self->{find_hash};
    my \%entrada_val;
    my \$entrada        = \\\%entrada_val;
    my \$trap;
    my \$trap_name;
    my \$trap_sub;
    my \$func_ref;
    my \$trap_oid;
    my \$trap_info;
    my \$alarm_txt;
    my \$contador = 0;

    if (\$onPrints) { print "\\n"; }

    foreach (\@trap_array) {
        my \$key_var = (keys %\$_)[0];
        if (ifexists(\$key_var)) {
            \$entrada_val{\$key_var} = \$_->{\$key_var};
            
            print "THE KEY IS: \$key_var" . " AND THE VALUE IS: \$entrada_val{ \$key_var }" . "\\n";

            my \$trap_oid = \$entrada->{"EOID"};
            if (!ifexists(\$trap_oid)) {
                \$trap_oid = "EMPTY";
            }

            if (\$key_var =~ /(.+)\\.0\$/) {
                my \$key_var_tmp = \$1;
                my \$val_tmp = \$entrada->{\$key_var};
                delete(\$entrada->{\$key_var});
                \$entrada->{\$key_var_tmp} = \$val_tmp;
                if (\$onPrints) { print "THE KEY IS: \$key_var_tmp AND THE VALUE IS: \$val_tmp\\n"; }
            } else {
                if (\$onPrints) { print "THE KEY IS: \$key_var AND THE VALUE IS: \$entrada_val{\$key_var}\\n"; }
            }
        }
    }

    \$trap_oid = \$entrada->{"EOID"};
    if (!ifexists(\$trap_oid)) {
        \$trap_oid = "EMPTY";
    }
    
    print "The Trap is: \$trap_oid\\n";
    
    \$trap_info = \$find_hash->{\$trap_oid};

    if (\$onPrints) {
        if (ifexists(\$trap_info->{trap_name})) { print "The TRAP name is: " . \$trap_info->{trap_name} . "\\n"; }
        else { print "The TRAP name is: not defined\\n"; }
        if (ifexists(\$trap_info->{subroutine})) {
            print "The TRAP subroutine is: " . \$trap_info->{subroutine} . "\\n";
            print "\\n\\n";
        } else { print "The TRAP subroutine is: not defined\\n"; }
    }

    \$trap_name = \$trap_info->{trap_name};
    \$trap_sub  = \$trap_info->{subroutine};


    print "\$trap_oid -> \$trap_sub";
    print "The Trap is \$trap_name\\n";


    if (ifexists(\$trap_name)) {
        \$func_ref = \\&\$trap_sub;
        \$alarm_txt = \$func_ref->(\\\%entrada_val, \$trap_name, \$config);
        \$contador += 1;
        print "\$trap_oid -> \$trap_sub\\n";
        print "\\n\\n======================== *** =================================\\n\\n";
        if (\$onPrints) { print "ESTA ES LA ALARMA: \$alarm_txt\\n"; }
        print "\\n\\n======================== *** =================================\\n\\n";

    } else {
        if (\$onPrints) { print "Alarm message is empty\\n"; }
    }
    return \$alarm_txt;
}

sub ifexists {
    my \$variable = shift;
    if (defined \$variable && \$variable ne "") {
        return 1;
    } else {
        return 0;
    }
}

1;
END_CODE

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_parseador", 'success');
    return 1;
}


1;
