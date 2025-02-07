#!/usr/bin/perl

use strict;
use warnings;
use Carp;

use Data::Dumper; # Importar el modulo Data::Dumper

use FindBin;  # Añadir FindBin para obtener la ruta del script
# Añadir la carpeta donde se encuentran los modulos
use lib $FindBin::Bin . "/herramientas";  # Añadir la carpeta donde se encuentran los módulos
use lib $FindBin::Bin . "./Script Generacion de Agentes SNMP/utilidades";

use SNMP::MIB::Compiler;

# Ventanas secundarias
use MIB_utils;


use File::Path qw(make_path rmtree);
use File::Temp qw(tempfile);
use File::Spec;
use File::Basename;

use Cwd 'abs_path';


# Modulos
use Complementos;
use Estilos;
use Logic;
use LogicEstructura;
use LogicEstructuraLegacy;
use LogicMIB;
use Rutas;
use Toolbar;
use Validaciones;

# Logs
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

#my $file_mib_test = Rutas::RUTA_ARCHIVOS_TEST(). 'MIBS\DISMAN-EVENT-MIB.mib';
my $file_mib_test = Rutas::RUTA_ARCHIVOS_TEST(). 'MIBS\IF-MIB.mib';
#my $file_mib_test = Rutas::RUTA_ARCHIVOS_TEST(). 'MIBS\HOST-RESOURCES-MIB.mib';

my $temp_file_all = Rutas::RUTA_ARCHIVOS_TEST(). 'Logs\(Registros)_Object_Identifiers.logs';
#my $temp_file_all = Rutas::RUTA_ARCHIVOS_TEST(). 'Logs\(Registros)_Textual_Convention.logs';
#my $temp_file_all = Rutas::RUTA_ARCHIVOS_TEST(). 'Logs\(Registros)_Object_Types.logs';
#my $temp_file_all = Rutas::RUTA_ARCHIVOS_TEST(). 'Logs\(Registros)_Module_Compliance.logs';
#my $temp_file_all = Rutas::RUTA_ARCHIVOS_TEST(). 'Logs\(Registros)_Object_Group.logs';
#my $temp_file_all = Rutas::RUTA_ARCHIVOS_TEST(). 'Logs\(Registros)_Notification_Group.logs';

$temp_file_all = LogicMIB::validar_o_crear_archivo_temporal($temp_file_all);

$logger->info("Extrayendo Object Identifiers del archivo MIB: $file_mib_test");
$logger->info("Guardando en: $temp_file_all");
my %elements_extracted;

my $extracted_element = LogicMIB::extraer_object_identifiers($file_mib_test, $temp_file_all);
#my $extracted_element = LogicMIB::extraer_textual_conventions($file_mib_test, $temp_file_all);
#my $extracted_element = LogicMIB::extraer_object_types($file_mib_test, $temp_file_all);
#my $extracted_element = LogicMIB::extraer_module_compliance($file_mib_test, $temp_file_all);
#my $extracted_element =  LogicMIB::extraer_objects_status_description($file_mib_test, $temp_file_all, 'OBJECT-GROUP');
#my $extracted_element =  LogicMIB::extraer_objects_status_description($file_mib_test, $temp_file_all, 'NOTIFICATION-GROUP');

@elements_extracted{keys %$extracted_element} = values %$extracted_element;

# Escribir los datos en el archivo temporal con el tipo OBJECT_GROUPS
LogicMIB::escribir_datos_en_archivo($temp_file_all, \%elements_extracted, "OBJECT_IDENTIFIERS", 1);
#LogicMIB::escribir_datos_en_archivo($temp_file_all, \%elements_extracted, "TEXTUAL_CONVENTION", 1);
#LogicMIB::escribir_datos_en_archivo($temp_file_all, \%elements_extracted, "OBJECT_TYPES", 1);
#LogicMIB::escribir_datos_en_archivo($temp_file_all, \%elements_extracted, "MODULE_COMPLIANCE", 1);
#LogicMIB::escribir_datos_en_archivo($temp_file_all, \%elements_extracted, "OBJECT_GROUP", 1);
#LogicMIB::escribir_datos_en_archivo($temp_file_all, \%elements_extracted, "NOTIFICATION_GROUP", 1);
