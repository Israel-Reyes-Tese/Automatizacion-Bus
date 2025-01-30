package LogicEstructura;

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



# Placeholder functions for card commands
sub crear_codigo_principal {
    my ($ventana_principal, $agente, $ruta_agente, $alarmas_principales, $alarmas_secundarias) = @_;
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

open my \$fh, '>', \$FindBin::Bin . "/output.log" or die "Could not open file: \$!";
\$fh->autoflush(1);

FuncInfo(\\\@ARGV,\$FindBin::Bin);

for (keys(\%{\$hash_ref})){
  \$hashOrdered = \$\$hash_ref{\$_};
  for my \$key (\@{\$hashOrdered -> keys}){
    my \$value = \$hashOrdered -> get(\$key);
    if (\$value =~ /CONF\\/MAP.+/) {
      if(FileExists(\$FindBin::Bin . "/" . \$value) && FileIsEmpty(\$FindBin::Bin . "/" . \$value)){
        \$hash_ref = \$configurator -> read_map("\$key",'\\s*->\\s*',\$FindBin::Bin . "/" . \$hashOrdered -> get("\$key"));
        if(ifexists(\$hash_ref -> {\$key})){
          \$maps .= "\$key,";
          \$abstract_global_hash .= "\\n > MAPA EXTERNO \\t'\$key'";
          for (\@{\$\$hash_ref{\$key} -> keys}){
            print \$fh "\\n   > KEY: '\$_'    VALUE:    '" . \$\$hash_ref{\$key} -> get(\$_) . "'";
          }
        } else {
          \$warning .= "\\nThe file '\$FindBin::Bin/\$value' with key '\$key' is empty and generate an empty hash. The key '\$key' will be removed from the hash";
          delete \$hash_ref -> {\$key};
        }
      }
    } elsif (\$value =~ /CONF\\/FB.+/) {
      if(FileExists(\$FindBin::Bin . "/" . \$value) && FileIsEmpty(\$FindBin::Bin . "/" . \$value)){
        \$hash_ref = \$configurator -> read_map("\$key",'\\s*->\\s*',\$FindBin::Bin . "/" . \$hashOrdered -> get("\$key"));
        if(ifexists(\$hash_ref -> {\$key})){
          \$bFilters .= "\$key,";
          \$abstract_global_hash .= "\\n > FILT RO DE BLOQUEO \\t'\$key'";
          for (\@{\$\$hash_ref{\$key} -> keys}){
            print \$fh "\\n   > KEY: '\$_'    VALUE:    '" . \$\$hash_ref{\$key} -> get(\$_) . "'";
          }
        } else {
          \$warning .= "\\nThe file '\$FindBin::Bin/\$value' with key '\$key' is empty and generate an empty hash. The key '\$key' will be removed from the hash";
          delete \$hash_ref -> {\$key};
        }
      }
    } elsif (\$value =~ /CONF\\/FC.+/) {
      if(FileExists(\$FindBin::Bin . "/" . \$value) && FileIsEmpty(\$FindBin::Bin . "/" . \$value)){
        \$hash_ref = \$configurator -> read_map("\$key",'\\s*->\\s*',\$FindBin::Bin . "/" . \$hashOrdered -> get("\$key"));
        if(ifexists(\$hash_ref -> {\$key})){
          \$cFilters .= "\$key,";
          \$abstract_global_hash .= "\\n > FILTRO CORRECTIVO \\t'\$key'";
          for (\@{\$\$hash_ref{\$key} -> keys}){
            print \$fh "\\n   > KEY: '\$_'    VALUE:    '" . \$\$hash_ref{\$key} -> get(\$_) . "'";
          }
        } else {
          \$warning .= "\\nThe file '\$FindBin::Bin/\$value' with key '\$key' is empty and generate an empty hash. The key '\$key' will be removed from the hash";
          delete \$hash_ref -> {\$key};
        }
      }
    } else {
      \$abstract_global_hash .= "\\n > VALOR DE \$key:  '\$value'";
    }
  }
  chop(\$bFilters);
  chop(\$cFilters);
  chop(\$maps);
}

#print \$fh "########################## RESUMEN DE DATOS DEL AGENTE ########################## \\n";
#print \$fh "\\n\\nNOMBRE DEL AGENTE: ". \$hashOrdered -> get('agt') ."\\n";

my \$host = \$hashOrdered -> get('host');
my \$port = \$hashOrdered -> get('port');
my \$glustDir = "/mnt/umplogic/" . \$hashOrdered -> get('agt');
my \$auxDir =  "/mnt/umpemergency/" . \$hashOrdered -> get('agt');

my \$trapd = ABR::SNMPAgente->new(
  \$host, \$port
);
my \$fhandler = ABR::FILE_HANDLER->new(
  gluster_dir =>   \$glustDir,
  auxiliary_dir => \$auxDir
);

print \$fh "EL DIRECTORIO GLUSTER ESTA EN: \$glustDir\\n";
print \$fh "EL DIRECTORIO AUXILIARY ESTA EN: \$auxDir\\n";

if(ifexists(\$maps))    { print \$fh "LOS EXTERNAL MAPS SON: \$maps\\n";}
if(ifexists(\$bFilters)){ print \$fh "LOS BLOCKING FILTERS SON: \$bFilters\\n";}
if(ifexists(\$cFilters)){ print \$fh "LOS CORRECTIVE FILTERS SON: \$cFilters\\n";}
print \$fh "El GLOBAL HASH es: \$abstract_global_hash\\n";
if(ifexists(\$warning)){
  my \@s = split('\\n',\$warning);
  foreach(\@s){
    if(ifexists(\$_)){
      print \$fh "> \\[WARNING\\]: " . \$_ . "\\n";
    }
  }
}
##################################### Tap Filters #####################################

print \$fh "LOS FILTROS DE BLOQUEO SON: \$bFilters\\n";
print \$fh "LOS FILTROS CORRECTIVOS SON: \$cFilters\\n";
my \$filter = ABR::TapFilter -> new(
  hash_ref      => \\\%\$hash_ref,
  config_index  => "\$bFilters",
  split_filter1 => '\\<&&\\>' ,
  split_filter2 => '\\<\\>'
);
my \$parser = ABR::Parser_aux->new();

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
    } else {
      if(\$hashOrdered -> get('ALARM_PRINTS')){print \$fh "\\nFile not created\\n\\n  ";}
    }
  } else {
    \$fhandler->dummy_write();
  }
}


  close \$fh or warn "Advertencia: No se pudo cerrar el archivo log: \$!";


sub FileExists{
  my \$file = shift;
  if(-e \$file){
    return 1;
  } else {
    \$warning .= "\\nThe file '\$file' not found.";
    return 0;
  }
}

sub FileIsEmpty{
  my \$file = shift;
  if(-s \$file == 0){
    \$warning .= "\\nThe file '\$file' is empty.";
    return 0;
  } else {
    return 1;
  }
}

sub ifexists{
  my \$variable = shift;
  if (defined \$variable && \$variable ne ""){
    return 1;
  } else {
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
        foreach my \$f(\@files){
          if(FileExists("\$path/ABR/\$f")){
            \$command = `cat \$path/ABR/\$f | grep 'Version='`;
            chop(\$command);
            if(ifexists(\$command)){if(\$command =~ /#\\s*(Version=.*)/i){print \$fh "   -\$f -> " . \$1 . "\\n";}}
            else{print \$fh "   -\$f -> \\"is not define version\\"\\n";}
          }
        }
        die;
      } elsif(\$_ =~ /--help/){
        print \$fh "\\nValid options:\\n";
        print \$fh " --help   " . "." . \$path . "/" . \$0 . " [--help]\\n";
        print \$fh " --version   " . "." . \$path . "/" . \$0 . " [--version]\\n";
        die;
      } else {
        print \$fh "\\nInvalid option: " . \$_ . "\\n";
        print \$fh "\\nValid options:\\n";
        print \$fh " --help   " . "." . \$path . "/" . \$0 . " [--help]\\n";
        print \$fh " --version   " . "." . \$path . "/" . \$0 . " [--version]\\n";
        die;
      }
    }
  }
}
END_CODE

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo \$archivo_principal", 'success');
    return 1;
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

sub crear_codigo_parseador {
    my ($ventana_principal, $agente, $ruta_agente, $alarmas_principales, $alarmas_secundarias) = @_;
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
    # Archivo de parseador

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
    my %find_hash;

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
    my \$entrada        = \%entrada_val;
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

    if (ifexists(\$trap_name)) {
        \$func_ref = \\&\$trap_sub;
        \$alarm_txt = \$func_ref->(\%entrada_val, \$trap_name, \$config);
        \$contador += 1;

        if (\$onPrints) { print "ESTA ES LA ALARMA: \$alarm_txt\\n"; }
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

sub crear_archivo_subrutinas {
    my ($ventana_principal, $agente, $ruta_agente, $alarmas_principales, $alarmas_secundarias) = @_;
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
            $mo = 'get_managed_object(\$hostname, \$agent_address, \$entrada -> {"1.3.6.1.6.3.18.1.3"})';
        } elsif ($data_extra->{combo_boxes}->{'Establecer Managed Object'} eq 'Entrada generica') {
            $mo = '\$entrada->{"1.3.6.1.6.3.18.1.3"}';
        }

        print $fh <<"END_SUB";
# $alarm_name
sub _$oid {
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

1;
END_SUB
        $notification_id++;
    }
    close $fh;

    herramientas::Complementos::show_alert($ventana_principal, 'EXITO',
    "Se creo correctamente el archivo $archivo_agente", 'success'
    );
    # Retorna true si se creo correctamente el archivo
    return 1;
}

sub crear_archivos_genericos {
    my ($ventana_principal, $agente ,$ruta_agente) = @_;

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


    crear_configurator($ventana_principal, $agente, $ruta_agente_abr);
    crear_corrective_filter($ventana_principal, $agente, $ruta_agente_abr);
    crear_file_handler($ventana_principal, $agente, $ruta_agente_abr);
    create_hashorder($ventana_principal, $agente, $ruta_agente_abr);
    create_llenaComun($ventana_principal, $agente, $ruta_agente_abr);
    create_microtime($ventana_principal, $agente, $ruta_agente_abr);
    create_tapfilter($ventana_principal, $agente, $ruta_agente_abr);
    create_snmpagente($ventana_principal, $agente, $ruta_agente_abr, $data_extra);

}

sub crear_configurator {
    my ($ventana_principal, $agente, $ruta_agente_abr) = @_;

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

    print $fh <<"END_CODE";
package ABR::CONFIGURATOR;
# Version=6.0
use ABR::HashOrder;

use warnings;
use strict;

sub new {
    my \$class = shift;
    my \$args;
    my \$config_file;
    my \%hash_read;

    \$args = {\@_};

    for (keys(%{\$args})) {
        if (\$_ eq "config_file") {
            \$config_file = \$args->{\$_};
        } else {
            die "> [ERROR]: CONFIGURATOR.pm, Configurator: No configuration file provided\\n";
        }
    }

    return bless { config_file => \$config_file, hash_read => \\\%hash_read };
}

sub read_config {
    my \$self        = shift;
    my \$config_file = \$self->{config_file};
    my \$config_ref  = \$self->{hash_read};
    my \$hashOrdered = ABR::HashOrder->new();
    my \@splitted;

    open(FILEH, "<", \$config_file) or die "> [ERROR]: CONFIGURATOR.pm, Could not open the configuration file: " . \$config_file . "\\n";

    while (my \$line = <FILEH>) {
        chomp(\$line);

        if (\$line !~ /^\\s*\$/ and \$line !~ /^#/) {
            \@splitted = split(":=", \$line);
            \$splitted[0] =~ /[ \\t]*(.+)[ \\t]*/;
            my \$index = \$1;
            \$splitted[1] =~ /[ \\t]*(.+)[ \\t]*/;
            my \$value = \$1;
            \$hashOrdered->set(\$index => \$value);
            \$config_ref->{"GLOBAL"} = \$hashOrdered;
        }
    }

    return \$config_ref;
}

sub read_map {
    my \$self        = shift;
    my \$tag         = shift;
    my \$sep         = shift;
    my \$config_file = shift;
    my \$hash_ref    = \$self->{hash_read};
    my \$hashOrdered = ABR::HashOrder->new();
    my \@splitted;

    if (!(\$config_file)) {
        print "> [ERROR]: CONFIGURATOR.pm, Verify configuration file: AGENT.properties\\n";
        print "> [ERROR]: CONFIGURATOR.pm, Maybe some of the indexes used are not well written in your *.pl or AGENT.properties file\\n";

        for my \$k (\$hash_ref->{"GLOBAL"}->keys) {
            print "> [ERROR]: CONFIGURATOR.pm, index -> \$k\\n";
        }

        die "> [ERROR]: CONFIGURATOR.pm, Could not open the configuration file\\n";
    }

    open(FILEH, "<", \$config_file) or die "> [ERROR]: CONFIGURATOR.pm, Could not open the configuration file: " . \$config_file . "\\n";

    while (my \$line = <FILEH>) {
        chomp(\$line);

        if (\$line !~ /^\\s*\$/ and \$line !~ /^#/) {
            \@splitted = split(\$sep, \$line);
            my \$index = "";
            my \$value = "";
            if (ifexists(\$splitted[0])) {
                \$splitted[0] =~ /[ \\t]*(.+)[ \\t]*/;
                \$index = \$1;
            }
            if (ifexists(\$splitted[1])) {
                \$splitted[1] =~ /[ \\t]*(.+)[ \\t]*/;
                \$value = \$1;
                \$hashOrdered->set(\$index => \$value);
                \$hash_ref->{\$tag} = \$hashOrdered;
            }
        }
    }
    return \$hash_ref;
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
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_configurator", 'success');
    return 1;
}

sub crear_corrective_filter {
    my ($ventana_principal, $agente, $ruta_agente_abr) = @_;

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

    print $fh <<"END_CODE";
package ABR::CorrectiveFilter;
# Version=6.0
use warnings;
use strict;

use ABR::HashOrder;

sub ifexists {
    my \$variable = shift;
    if (defined \$variable && \$variable ne "") {
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
    \$self = { splitFilter1 => \$args->{split_filter1}, splitFilter2 => \$args->{split_filter2} };
    return bless \$self, \$class;
}

sub ProcessingCF {
    my \$self = shift;
    my (\$hash_field, \$hashref_fc, \$action, \$cascade) = \@_;
    my \@splitted_1;
    my \@splitted_2;
    my \$OrigAddTxt = \$hash_field->{"AddTxt"};
    my \$logic      =  1;
    my \$blocking   = "";
    my \$output     = "";

    if (\$action eq "SetGrupos") {
        return DirectSetGrupos(\$hash_field, \$hashref_fc);
    }

    if (ifexists \$hashref_fc) {
        foreach my \$Filter (\@{\$hashref_fc->keys}) {
            \@splitted_1 = split(\$self->{splitFilter1}, \$hashref_fc->get(\$Filter));
            foreach my \$line (\@splitted_1) {
                \@splitted_2 = split(\$self->{splitFilter2}, \$line);
                if ((\$splitted_2[0] ne "Action") && (\$splitted_2[0] ne "SetIncidentType") && (\$splitted_2[0] ne "SetUserText") && (\$splitted_2[0] ne "SetGrupos")) {
                    \$logic = \$logic & Operations(\$splitted_2[0], \$splitted_2[1], \$splitted_2[2], \$hash_field);
                } elsif ((\$splitted_2[0] eq "SetIncidentType") || (\$splitted_2[0] eq "SetUserText") || (\$splitted_2[0] eq "SetGrupos")) {
                    if (\$splitted_2[1] eq "IsPresent") {
                        \$logic = \$logic & IsPresent(\$action, \$splitted_2[2], \$hash_field);
                    }
                } else {
                    if (\$splitted_2[1] eq \$action) {
                        \$output = ActionReview(\$splitted_2[0], \$splitted_2[1], \$splitted_2[2], \$hash_field, \$OrigAddTxt, \$cascade);
                    } elsif (\$splitted_2[1] eq "Blocking") {
                        \$output = ActionFalse(\$action, \$hash_field);
                        if (\$logic) { \$blocking = \$splitted_2[2]; }
                    } else { \$logic = 0; }
                }
            }

            if (\$logic) {
                if (\$blocking eq "" || \$Filter !~ /\$blocking\\_\\d+\$/) {
                    if (ifexists \$cascade) {
                        if (\$cascade eq "NonCascade") {
                            return \$output;
                        }
                    }
                    if (\$action eq "PrependAdditionalText") {
                        \$hash_field->{"AddTxt"} = \$output;
                    } elsif (\$action eq "SetEventSeverity") {
                        \$hash_field->{"PS"} = \$output;
                    } elsif (\$action eq "SetGrupos") {
                        \$hash_field->{"AddTxt"} = \$output;
                    } elsif (\$action eq "SetIncidentType") {
                        \$hash_field->{"AddTxt"} = \$output;
                    } elsif (\$action eq "SetUserText") {
                        \$hash_field->{"AddTxt"} = \$output;
                    } elsif (\$action eq "SetEventManagedObject") {
                        \$hash_field->{"MO"} = \$output;
                    }
                }
            } else {
                \$logic = 1;
            }
        }
        return ActionFalse(\$action, \$hash_field);
    } else {
        return ActionFalse(\$action, \$hash_field);
    }
}

sub DirectSetGrupos {
    my (\$hash_field, \$hashref_fc) = \@_;
    my \$var_mo     = "";
    my \$var_output = "";
    if (\$hash_field->{"MO"} =~ /"(.*)"/) { \$var_mo = \$1; }
    if (ifexists \$var_mo) {
        \$var_output = \$hashref_fc->get(\$var_mo);
        if (ifexists \$var_output) { return \$hash_field->{"AddTxt"} . " SetGrupos=" . \$var_output . ";\$\$"; }
    }
    return \$hash_field->{"AddTxt"};
}

sub ActionReview {
    my (\$param, \$oper, \$value, \$HashTextAlarm, \$addtxt, \$cascade) = \@_;
    my \$Output = "";
    if (\$param eq "Action") {
        if (\$oper =~ "PrependAdditionalText") {
            if (\$value =~ /^".*"/) {
                \$value =~ s/"//g;
            }
            if (ifexists \$HashTextAlarm->{"AddTxt"}) { \$Output = \$value . \$HashTextAlarm->{"AddTxt"}; }
            else { \$Output = \$value; }
            return \$Output;
        } elsif (\$oper =~ "SetEventSeverity") {
            \$Output = \$value;
            return \$Output;
        } elsif (\$oper =~ "SetIncidentType") {
            if (\$value =~ /^".*"/) {
                \$value =~ s/"//g;
            }
            if (ifexists \$HashTextAlarm->{"AddTxt"}) {
                if (\$HashTextAlarm->{"AddTxt"} =~ /SetIncidentType=.*;\$\$/) {
                    if (ifexists \$cascade) {
                        if (\$cascade eq "NonCascade") {
                            \$Output = \$addtxt;
                            \$Output =~ s/ SetIncidentType=.*?;\$\$/ SetIncidentType=\$value;\$\$/;
                        } else {
                            \$Output = \$addtxt;
                        }
                    } else {
                        \$Output = \$addtxt . " SetIncidentType=" . \$value . ";\$\$";
                    }
                } else {
                    \$Output = \$HashTextAlarm->{"AddTxt"} . " SetIncidentType=" . \$value . ";\$\$";
                }
            } else { \$Output = " SetIncidentType=" . \$value . ";\$\$"; }
            return \$Output;
        } elsif (\$oper =~ "SetUserText") {
            if (\$value =~ /^".*"/) {
                \$value =~ s/"//g;
            }
            if (ifexists \$HashTextAlarm->{"AddTxt"}) {
                if (\$HashTextAlarm->{"AddTxt"} =~ /SetUserText=.*;\$\$/) {
                    if (ifexists \$cascade) {
                        if (\$cascade eq "NonCascade") {
                            \$Output = \$addtxt;
                            \$Output =~ s/ SetUserText=.*?;\$\$/ SetUserText=\$value;\$\$/;
                        } else {
                            \$Output = \$addtxt;
                        }
                    } else {
                        \$Output = \$addtxt . " SetUserText=" . \$value . ";\$\$";
                    }
                } else {
                    \$Output = \$HashTextAlarm->{"AddTxt"} . " SetUserText=" . \$value . ";\$\$";
                }
            } else { \$Output = " SetUserText=" . \$value . ";\$\$"; }
            return \$Output;
        } elsif (\$oper =~ "SetGrupos") {
            if (\$value =~ /^".*"/) {
                \$value =~ s/"//g;
            }
            if (ifexists \$HashTextAlarm->{"AddTxt"}) {
                if (\$HashTextAlarm->{"AddTxt"} =~ /SetGrupos=.*;\$\$/) {
                    if (ifexists \$cascade) {
                        if (\$cascade eq "NonCascade") {
                            \$Output = \$addtxt;
                            \$Output =~ s/ SetGrupos=.*?;\$\$/ SetGrupos=\$value;\$\$/;
                        } else {
                            \$Output = \$addtxt;
                        }
                    } else {
                        \$Output = \$addtxt . " SetGrupos=" . \$value . ";\$\$";
                    }
                } else {
                    \$Output = \$HashTextAlarm->{"AddTxt"} . " SetGrupos=" . \$value . ";\$\$";
                }
            } else { \$Output = " SetGrupos=" . \$value . ";\$\$"; }
            return \$Output;
        } elsif (\$oper =~ "SetEventManagedObject") {
            if (\$value =~ /^".*"/) {
                \$value =~ s/"//g;
            }
            \$Output = \$value;
            return \$Output;
        }
    }
}

sub ActionFalse {
    my (\$oper, \$HashTextAlarm) = \@_;
    if (\$oper =~ "PrependAdditionalText") {
        return \$HashTextAlarm->{"AddTxt"};
    } elsif (\$oper =~ "SetEventSeverity") {
        return \$HashTextAlarm->{"PS"};
    } elsif (\$oper =~ "SetIncidentType") {
        return \$HashTextAlarm->{"AddTxt"};
    } elsif (\$oper =~ "SetUserText") {
        return \$HashTextAlarm->{"AddTxt"};
    } elsif (\$oper =~ "SetGrupos") {
        return \$HashTextAlarm->{"AddTxt"};
    } elsif (\$oper =~ "SetEventManagedObject") {
        return \$HashTextAlarm->{"MO"};
    }
}

sub IsPresent {
    my (\$oper, \$value, \$HashTextAlarm) = \@_;
    my \$Output = "";
    my \$vl     = 1;
    if (ifexists \$HashTextAlarm->{"AddTxt"}) {
        if (\$oper eq "SetGrupos") {
            \$vl = functionMatch(\$HashTextAlarm->{"AddTxt"}, \$value);
        } elsif (\$oper eq "SetIncidentType") {
            \$vl = functionMatch(\$HashTextAlarm->{"AddTxt"}, \$value);
        } elsif (\$oper eq "SetUserText") {
            \$vl = functionMatch(\$HashTextAlarm->{"AddTxt"}, \$value);
        } else {
            \$vl = 0;
        }
    } else {
        \$vl = 0;
    }
    return \$vl;
}

sub Operations {
    my (\$param, \$oper, \$value, \$HashTextAlarm) = \@_;
    my \$var = "";
    my \$vl  = 1;
    if (\$param eq "AddTxt") {
        if (ifexists \$HashTextAlarm->{"AddTxt"}) {
            if (\$oper eq "match") {
                \$vl = functionMatch(\$HashTextAlarm->{"AddTxt"}, \$value);
            } elsif (\$oper eq "equal") {
                \$vl = functionEqual(\$HashTextAlarm->{"AddTxt"}, \$value);
            }
        } else {
            \$vl = 0;
        }
    } elsif (\$param eq "MO") {
        if (ifexists \$HashTextAlarm->{"MO"}) {
            if (ifexists \$HashTextAlarm->{"MO"}) {
                if (\$oper eq "match") {
                    \$vl = functionMatch(\$HashTextAlarm->{"MO"}, \$value);
                } elsif (\$oper eq "equal") {
                    \$vl = functionEqual(\$HashTextAlarm->{"MO"}, \$value);
                }
            } else {
                \$vl = 0;
            }
        } elsif (\$param eq "PS") {
            if (ifexists \$HashTextAlarm->{"PS"}) {
                if (\$oper eq "match") {
                    \$vl = functionMatch(\$HashTextAlarm->{"PS"}, \$value);
                } elsif (\$oper eq "equal") {
                    \$vl = functionEqual(\$HashTextAlarm->{"PS"}, \$value);
                }
            } else {
                \$vl = 0;
            }
        }
        return \$vl;
    }
}

sub functionMatch {
    my (\$var, \$value) = \@_;
    if (\$var =~ /\\Q\$value\\E/) {
        return 1;
    } else {
        return 0;
    }
}

sub functionEqual {
    my (\$var, \$value) = \@_;
    if (\$var eq \$value) {
        return 1;
    } else {
        return 0;
    }
}

sub functionEq {
    my (\$val1, \$val2) = \@_;
    return \$val1 == \$val2 ? 1 : 0;
}

sub functionNe {
    my (\$val1, \$val2) = \@_;
    return \$val1 != \$val2 ? 1 : 0;
}

sub functionLt {
    my (\$val1, \$val2) = \@_;
    return \$val1 < \$val2 ? 1 : 0;
}

sub functionGt {
    my (\$val1, \$val2) = \@_;
    return \$val1 > \$val2 ? 1 : 0;
}

sub functionLe {
    my (\$val1, \$val2) = \@_;
    return \$val1 <= \$val2 ? 1 : 0;
}

sub functionGe {
    my (\$val1, \$val2) = \@_;
    return \$val1 >= \$val2 ? 1 : 0;
}

sub PSle {
    my (\$val1, \$val2) = \@_;
    return 0 if \$val1 eq "5" or \$val2 eq "5";
    return 1 if \$val2 eq "0";
    return 0 if \$val1 eq "0";
    return \$val1 <= \$val2 ? 1 : 0;
}

sub PSlt {
    my (\$val1, \$val2) = \@_;
    return 0 if \$val1 eq "5" or \$val2 eq "5";
    return \$val1 eq "0" ? 0 : \$val2 eq "0" ? 1 : \$val1 < \$val2 ? 1 : 0;
}

sub PSge {
    my (\$val1, \$val2) = \@_;
    return 0 if \$val1 eq "5" or \$val2 eq "5";
    return \$val1 eq "0" ? 1 : \$val2 eq "0" ? 0 : \$val1 >= \$val2 ? 1 : 0;
}

sub PSgt {
    my (\$val1, \$val2) = \@_;
    return 0 if \$val1 eq "5" or \$val2 eq "5";
    return \$val1 eq "0" || \$val2 eq "0" ? 0 : \$val1 > \$val2 ? 1 : 0;
}

sub isInteger {
    my \$input = shift;
    return 0 unless ifexists(\$input);
    return 0 if \$input =~ /\d+\.\d+/;
    return \$input =~ /\d+/ ? 1 : 0;
}

1;
END_CODE

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_corrective_filter", 'success');
    return 1;
}

sub crear_file_handler {
    my ($ventana_principal, $agente, $ruta_agente_abr) = @_;

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

    print $fh <<"END_CODE";
package ABR::FILE_HANDLER;
use warnings;
use strict;

sub new {
    my \$class = shift;
    my \$args = { \@_ };
    my \$gluster_dir = \$args->{gluster_dir};
    my \$auxiliary_dir = \$args->{auxiliary_dir};

    return bless { gluster_dir => \$gluster_dir, auxiliary_dir => \$auxiliary_dir, not_send => [] }, \$class;
}

sub write_file {
    my (\$self, \$file_name, \$file_content) = \@_;
    my \$file_path = "\$self->{gluster_dir}/\$file_name";
    my \$emergency_path = "\$self->{auxiliary_dir}/\$file_name";
    my \$em_fh;
    my \$fh;
    unless (open my \$fh, '>', \$file_path) {
        unless (open my \$em_fh, '>', \$emergency_path) {
            die "The emergency directory does not exist or is not accessible";
        }
        print \$em_fh \$file_content;
        close \$em_fh;
        push \@{\$self->{not_send}}, \$file_name;
        return "EMERGENCY";
    }

    \$self->file_resynch if \@{\$self->{not_send}};
    print \$fh \$file_content;
    close \$fh;
    return "WRITTEN";
}

sub file_resynch {
    my \$self = shift;
    while (my \$emergency_file = shift \@{\$self->{not_send}}) {
        my \$file_path = "\$self->{gluster_dir}/\$emergency_file";
        my \$emergency_path = "\$self->{auxiliary_dir}/\$emergency_file";
        unless (system("mv -f \$emergency_path \$file_path") == 0) {
            unshift \@{\$self->{not_send}}, \$emergency_file;
            last;
        }
    }
}

sub dummy_write {
    my \$self = shift;
    \$self->file_resynch if \@{\$self->{not_send}} && opendir my \$dir, \$self->{gluster_dir};
}

sub startup_write {
    my \$self = shift;
    if (opendir my \$dir, \$self->{gluster_dir}) {
        my \$regreso = `ls -rt \$self->{auxiliary_dir}`;
        die "There is a problem reading files from the emergency file path" if \$? == -1;
        \@{\$self->{not_send}} = split "\\n", \$regreso;
        \$self->file_resynch;
    }
}

1;
END_CODE

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_file_handler", 'success');
    return 1;
}



sub create_hashorder {
    my ($ventana_principal, $agente, $ruta_agente_abr) = @_;
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
      foreach my \$x(keys %{\$args}){
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




sub create_llenaComun {
    my ($ventana_principal, $agente, $ruta_agente_abr) = @_;

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

    print $fh <<"END_CODE";
package ABR::llenaComun;
# Version=1.0
use POSIX qw(strftime);
use warnings;
use strict;

sub new {
    my \$class = shift;
    my \$mensaje_x733;
    return bless { mensaje_x733 => \\\$mensaje_x733 }, \$class;
}

sub vacia_mensaje_x733 {
    my \$self = shift;
    \${\$self->{mensaje_x733}} = "";
}

sub llenaEN {
    my (\$self, \$en_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$en_list#\$%";
}

sub llenaMO {
    my (\$self, \$mo_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$mo_list#\$%";
}

sub llenaPC {
    my (\$self, \$pc_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$pc_list#\$%";
}

sub llenaSP {
    my (\$self, \$ps_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$ps_list#\$%";
}

sub llenaPS {
    my (\$self, \$ps_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$ps_list#\$%";
}

sub llenaBUS {
    my (\$self, \$bus_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$bus_list#\$%";
}

sub llenaBAO {
    my (\$self, \$bao_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$bao_list#\$%";
}

sub llenaTrendI {
    my (\$self, \$trendi_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$trendi_list#\$%";
}

sub llenaThresholdI {
    my (\$self, \$thresholdi_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$thresholdi_list#\$%";
}

sub llenaNI {
    my (\$self, \$ni_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$ni_list#\$%";
}

sub llenaCN {
    my (\$self, \$cn_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$cn_list#\$%";
}

sub llenaSCD {
    my (\$self, \$scd_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$scd_list#\$%";
}

sub llenaMA {
    my (\$self, \$ma_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$ma_list#\$%";
}

sub llenaPRA {
    my (\$self, \$pra_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$pra_list#\$%";
}

sub llenaAT {
    my (\$self, \$at_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$at_list#\$%";
}

sub llenaAI {
    my (\$self, \$ai_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$ai_list#\$%";
}

sub EventTime {
    my (\$self, \$et_list) = \@_;
    \${\$self->{mensaje_x733}} .= "\$et_list#\$%";
}

sub EventType {
    my (\$self, \$ety_list) =\ \@_;
    \${\$self->{mensaje_x733}} .= \$ety_list;
}

sub fecha {
    return strftime "\%b \%e \%H:\%M:\%S \%Z \%Y", localtime;
}

1;
END_CODE

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo $archivo_llena_comun", 'success');
    return 1;
}


sub create_microtime {
    my ($ventana_principal, $agente, $ruta_agente_abr) = @_;

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
sub create_tapfilter {
    my ($ventana_principal, $agente, $ruta_agente_abr) = @_;

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
    print $fh <<"END_CODE";
package ABR::TapFilter;
# Version=6.0
use warnings;
use strict;

use ABR::HashOrder;

sub ifexists {
    my \$variable = shift;
    if (defined \$variable && \$variable ne "") {
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
    my \%hash_check_operation = ("AddTxt" => ["match","equal"],
                                "MO" => ["match","equal"],
                                "PS" => ["eq","ne","lt","gt","le","ge"],
                                "PC" => ["eq","ne","lt","gt","le","ge"],
                                "Action" => ["Blocking","Passing"],
                                "SetGrupos" => ["IsPresent"],
                                "SetUserText" => ["IsPresent"],
                                "SetIncidentType" => ["IsPresent"]);
    my \$hashOrdered = ABR::HashOrder->new();
    my \$stausFileFilter = 0;
    my \$Error = 1;
    my \$InfoErrors = "";
    my \%filter_read;
    my \@array;
    my \@splitted_1;
    my \@splitted_2;

    \$args = {\@_};
    \$hash_ref = \$args->{hash_ref};
    \@array = split(',', \$args->{config_index});

    print "\\n------------------ Cargando y verificando sintaxis del filtro ------------------\\n";

    eval {
        foreach my \$FilterName (\@array) {
            foreach my \$index (%{\$hash_ref}) {
                if (\$index eq \$FilterName) {
                    \$hashOrdered = \$\$hash_ref{\$index};
                    my \$SF = ABR::HashOrder->new(); # Subfilter HashOrder
                    foreach my \$subFilter (\@{\$hashOrdered->keys}) {
                        if (\$hashOrdered->get(\$subFilter) !~ /.*Action\\<\\>Blocking|Passing\\<\\>.*/) {
                            my \$rW = "";
                            if (\$subFilter =~ m/(.*)_\\d+\$/) {
                                \$rW = \$hashOrdered->get(\$subFilter) . "<&&>Action<>Blocking<>" . \$1;
                                \$hashOrdered->set(\$subFilter => \$rW);
                            }
                        }
                        \@splitted_1 = split(\$args->{split_filter1}, \$hashOrdered->get(\$subFilter));
                        foreach my \$item (\@splitted_1) {
                            \@splitted_2 = split(\$args->{split_filter2}, \$item);
                            if (\$hash_check_operation{\$splitted_2[0]}) {
                                foreach (\@{\$hash_check_operation{\$splitted_2[0]}}) {
                                    if (\$splitted_2[1] eq \$_) {
                                        if (\$splitted_2[0] eq "PS") {
                                            if (!(isInteger(\$splitted_2[2]))) {
                                                \$InfoErrors = "Error in the file " . \$FilterName . " and Index " . \$subFilter . ": No accepted value \\"" . \$splitted_2[2] . "\\" in \\"" . \$splitted_2[0] . "\\" -> " . \$hashOrdered->get(\$subFilter) . "\\n";
                                                
                                                die;
                                            } else {
                                                if ((\$splitted_2[2] eq "5") or (\$splitted_2[2] eq "1") or (\$splitted_2[2] eq "2") or (\$splitted_2[2] eq "3") or (\$splitted_2[2] eq "4") or (\$splitted_2[2] eq "0")) {
                                                    if (\$splitted_2[2] eq "5") {
                                                        print "[WARN]: In the file " . \$FilterName . " and Index " . \$subFilter . ":\\n";
                                                        print "[WARN]: " . \$hashOrdered->get(\$subFilter) . ",\\n";
                                                        print "[WARN]: you used severity \\"5 -> Clear\\" on this filter, check that it's not on a blocking filter or that the operation is different of \\"eq\\".\\n";
                                                    }
                                                } else {
                                                    \$InfoErrors = "Error in the file " . \$FilterName . " and Index " . \$subFilter . ": No accepted value \\"" . \$splitted_2[2] . "\\" in \\"" . \$splitted_2[0] . "\\" -> " . \$hashOrdered->get(\$subFilter) . "\\n";
                                                    die;
                                                }
                                            }
                                        } elsif (\$splitted_2[0] eq "PC") {
                                            if (!(isInteger(\$splitted_2[2]))) {
                                                \$InfoErrors = "Error in the file " . \$FilterName . " and Index " . \$subFilter . ": No accepted value \\"" . \$splitted_2[2] . "\\" in \\"" . \$splitted_2[0] . "\\" -> " . \$hashOrdered->get(\$subFilter) . "\\n";
                                                die;
                                            }
                                        } else {
                                            if (!(ifexists \$splitted_2[2])) {
                                                \$InfoErrors = "Error in the file " . \$FilterName . " and Index " . \$subFilter . ": value is empty\\"" . \$splitted_2[2] . "\\" in \\"" . \$splitted_2[0] . "\\" -> " . \$hashOrdered->get(\$subFilter) . "\\n";
                                                die;
                                            }
                                        }
                                        \$Error = 0;
                                    }
                                }
                                if (\$Error) {
                                    \$InfoErrors = "Error in the file " . \$FilterName . " and Index " . \$subFilter . ": No accepted operation \\"" . \$splitted_2[1] . "\\" in \\"" . \$splitted_2[0] . "\\" -> " . \$hashOrdered->get(\$subFilter) . "\\n";
                                    die;
                                }
                                \$Error = 1;
                            } else {
                                \$InfoErrors = "Error in the file " . \$FilterName . " and Index " . \$subFilter . ": No accepted parameter \\"" . \$splitted_2[0] . "\\" -> " . \$hashOrdered->get(\$subFilter) . "\\n";
                                die;
                            }
                        }
                        \$SF->set(\$subFilter => [\@splitted_1]);
                        \$hash_filter{\$FilterName} = \$SF;
                    }
                    \$stausFileFilter = \$stausFileFilter | 1;
                } else {
                    \$stausFileFilter = \$stausFileFilter | 0;
                }
            }
        }
        print ">> No hay Errores de sintaxis en el filtro de bloqueo(s)\\n";
        print "--------------------------------------------------------------------------------\\n";

    } or do {
        die "[ERR ]: TapFilter.pm, " . \$InfoErrors;
    };

    \$self = { hash_filter => \\\%hash_filter, status => \$stausFileFilter, match_text => \$match_text, separator => \$args->{split_filter2} };
    return bless \$self, \$class;
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
              \$matchText = \$matchText ."[INFO]: Filter: " . \$filter . "->" . \$subFilter . ":\\n[INFO]: Parameter: " . \$splitted[0] . ", Operation: " . \$splitted[1] . ", Value: " . \$splitted[2] . "\\n";
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

sub ProcessingTextAlarm{
  my \$textAlarm = shift;
  my \@s1;
  my \%hash_alarm;
  \$textAlarm =~ s/###START###//g;
  \$textAlarm =~ s/###END###//g;
  \$textAlarm =~ s/\\n/ /g;
  \@s1 = split('#\\\$\\%',\$textAlarm);
  foreach my \$i1(\@s1){
    if(\$i1 =~ /(\w+):(.*)/){
      \$hash_alarm{\$1} = \$2;
    }
  }
  return \\\%hash_alarm;
}

sub changeFileName{
  my \$file = shift;
  if(\$file =~ /(.*)\\.yes/){
    return "\$1.no";
  }else{
    return "\$file";
  }
}

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

sub PSle{
  my \$val1 = shift;
  my \$val2 = shift;

  if(\$val1 ne "5" and \$val2 ne "5"){

    if(\$val2 eq "0"){
      return 1;
    }else{
      if(\$val1 eq "0"){
        return 0;
      }else{
        if(\$val1 <= \$val2){
          return 1;
        }else{
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

  if(\$val1 ne "5" and \$val2 ne "5"){

    if(\$val2 eq "0"){
      if(\$val1 eq  "0"){
        return 0;
      }else{
        return 1;
      }
    }else{
      if(\$val1 eq "0"){
        return 0;
      }else{
        if(\$val1 < \$val2){
          return 1;
        }else{
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

  if(\$val1 ne "5" and \$val2 ne "5"){

    if(\$val1 eq "0"){
      return 1;
    }else{
      if(\$val2 eq "0"){
        return 0;
      }else{
        if(\$val1 >= \$val2){
          return 1;
        }else{
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

  if(\$val1 ne "5" and \$val2 ne "5"){

    if(\$val1 eq "0"){
      return 0;
    }else{
      if(\$val2 eq "0"){
        return 0;
      }else{
        if(\$val1 > \$val2){
          return 1;
        }else{
          return 0;
        }
      }
    }

  }else{
    return 0;
  }

}

sub isInteger{
  my \$input = shift;
  if(ifexists \$input){
    if(\$input !~ /\\d+\\.\\d+/){
      if(\$input =~ /\\d+/){
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



sub create_snmpagente {
    my ($ventana_principal, $agente, $ruta_agente_abr, $data_extra) = @_;
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

    print $fh <<"END_CODE";
package ABR::SNMPAgente;
# Version=1.1
use warnings;
use strict;
use Net::SNMPTrapd;
use Sys::Hostname;



sub new {
    open my \$fh, '>', \$FindBin::Bin . "/output.log" or die "Could not open file: \$!";
    \$fh->autoflush(1);

    my \$local_address;
    my \$local_port;
    my \$self;
    my \@args = \@_;
    my \$class = \$args[0];
    if(\$#args > 1) {
        \$local_address = \$args[1];
        \$local_port = \$args[2];
    } else {
        \$local_port = $local_port;
        my \$hostname = "$hostname";
        ( my \$nombre, my \$alias, my \$addr_tipo, my \$largo, my \@direcciones )= gethostbyname(\$hostname);
        ( my \$a, my \$e, my \$i, my \$o )  = unpack("C4", \$direcciones[0]);
        \$local_address = \$a . "." . \$e . "." . \$i ."." . \$o;
    }

    print \$fh "Local Address: \$local_address\\n";
    print \$fh "Local Port: \$local_port\\n";

    my \$snmptrapd = Net::SNMPTrapd -> new( -LocalAddr=>\$local_address, -LocalPort=>\$local_port, -timeout=>1);

    if(!defined(\$snmptrapd)) {
        exit(1);
    } else {
      \$self = bless({ snmptrapd => \$snmptrapd }, \$class);
    }

    close \$fh or warn "Advertencia: No se pudo cerrar el archivo log: \$!";

    return \$self;
}

sub get_trap {
    my \$self     = shift;
    my \$onPrints = shift;
    my \$trap;
    my \$trap_version;

    \$trap = \$self -> { snmptrapd } -> get_trap();

    if (!defined(\$trap)) {
        exit 1;
    } elsif (\$trap == 0) {
        undef(\$trap);
        return \$trap;
    }

    if (!defined(\$trap->process_trap())) {
        undef(\$trap);
        return \$trap;
    } else {
        \$trap_version = \$trap->version();
        if(\$trap_version == 1) {
          \$self -> processV1(\$trap,\$onPrints);
        } elsif (\$trap_version == 2) {
          \$self -> processV2(\$trap,\$onPrints);
        }
    }
}

sub processV1 {
    my \@trap_array;
    my \$self              = shift;
    my \$trap              = shift;
    my \$onPrints          = shift;
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

    for my \$vals (\@varbinds) {
        foreach(keys(%\$vals)) {
            push(\@trap_array, \$vals->{\$_});
        }
    }

    return \@varbinds;
}

sub processV2 {
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

    externo: for my \$vals (\@\$arreglo_varbind) {
        foreach(keys(%\$vals)) {
            if(\$_ eq "1.3.6.1.6.3.1.1.4.1.0") {
                \$e_oid = \$vals -> {\$_};
                \$e_oid_ref = { "EOID" => \$e_oid };
                if(\$bandera == 1) {
                    last externo;
                }
                \$bandera = 1;
            }

            if(\$_ eq "1.3.6.1.6.3.18.1.3.0") {
                \$remoteaddr = \$vals -> {\$_};
                \$remoteaddr_ref = { "IPADDR" => \$remoteaddr };
                if(\$bandera == 1) {
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

    for my \$vals (\@varbinds) {
        foreach(keys(%\$vals)) {
        }
    }

    return \@varbinds;
}



1;
END_CODE

    close $fh;
    herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se creo correctamente el archivo \$archivo_snmpagente", 'success');
    return 1;
}
1;
