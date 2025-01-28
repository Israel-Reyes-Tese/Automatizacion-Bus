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
$texto_implementacion
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
        \$alarm_txt = \$func_ref->(\%entrada_val, \$trap_name, \$config);
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
