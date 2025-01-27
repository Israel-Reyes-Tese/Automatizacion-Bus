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

1;
