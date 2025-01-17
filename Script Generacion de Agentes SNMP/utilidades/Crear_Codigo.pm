# #!/usr/bin/perl

package utilidades::Crear_Codigo;


use strict;
use warnings;
use Tk;
use Tk::Pane;
use Tk::FileSelect;

use FindBin;
use lib $FindBin::Bin . "/../herramientas";
use lib $FindBin::Bin . "/../../herramientas";  # Añadir la carpeta donde se encuentran los modulos
use File::Path qw(make_path rmtree);
use File::Temp qw(tempfile);
use File::Spec;
use Cwd 'abs_path';

use Estilos;
use Complementos;
use Rutas;
use Logic;
use LogicMIB;
use Validaciones;

use Data::Dumper; # Importar el modulo Data::Dumper


sub Inicio_Crear_Codigo {
    my ($agente, $ruta_agente, $alarmas_principales, $alarmas_secundarias) = @_;
    if (!$agente) {
        $agente = 'agente_snmp';
    }
    if (!$ruta_agente) {
        $ruta_agente = Rutas::temp_agents_path();
    }
    if (!$alarmas_principales) {
        $alarmas_principales = {
          'networkInterfaceAlarm' => {
                                       'OID' => '1.3.6.1.4.1.20858.10.104.101.2.1.7',
                                       'OBJECTS' => '  neIdentity, alarmID, notificationType, eventType, probableCause,  specificProblem, perceivedSeverity, additionalText, additionalInformation, eventTime ',
                                       'DESCRIPTION' => 'AeMS Network interface alarm'
                                     },

          'forcedReboot' => {
                              'OID' => '1.3.6.1.4.1.20858.10.104.101.2.2.41',
                              'DESCRIPTION' => 'Self-healing agent raises this alarm upon detection of major failure requiring a reboot',   
                              'OBJECTS' => '  neIdentity, alarmID, notificationType, eventType, probableCause,  specificProblem, perceivedSeverity, additionalText, additionalInformation, eventTime '
                            },
        };
    }


    if (!$alarmas_secundarias)  {
         $alarmas_secundarias = { 
            'congestion' => {
                            'specificProblem' => '1.3.6.1.4.1.20858.10.104.101.1.6',
                            'perceivedSeverity' => '1.3.6.1.4.1.20858.10.104.101.1.7',
                            'additionalText' => '1.3.6.1.4.1.20858.10.104.101.1.8',
                            'alarmID' => '1.3.6.1.4.1.20858.10.104.101.1.2',
                            'eventTime' => '1.3.6.1.4.1.20858.10.104.101.2.2.50',
                            'additionalInformation' => '1.3.6.1.4.1.20858.10.104.101.1.9',
                            'notificationType' => '1.3.6.1.4.1.20858.10.104.101.1.3',
                            'eventType' => '1.3.6.1.4.1.20858.10.104.101.1.4',
                            'probableCause' => '1.3.6.1.4.1.20858.10.104.101.1.5',
                            'neIdentity' => '1.3.6.1.4.1.20858.10.104.101.1.1'
                          },
          'casaHeMSSmallCellGWAlarm' => {
                                          'eventType' => '1.3.6.1.4.1.20858.10.104.101.1.4',
                                          'notificationType' => '1.3.6.1.4.1.20858.10.104.101.1.3',
                                          'probableCause' => '1.3.6.1.4.1.20858.10.104.101.1.5',
                                          'neIdentity' => '1.3.6.1.4.1.20858.10.104.101.1.1',
                                          'specificProblem' => '1.3.6.1.4.1.20858.10.104.101.1.6',
                                          'alarmID' => '1.3.6.1.4.1.20858.10.104.101.1.2',
                                          'additionalInformation' => '1.3.6.1.4.1.20858.10.104.101.1.9',
                                          'eventTime' => '1.3.6.1.4.1.20858.10.104.101.2.2.50',
                                          'perceivedSeverity' => '1.3.6.1.4.1.20858.10.104.101.1.7',
                                          'additionalText' => '1.3.6.1.4.1.20858.10.104.101.1.8'
                                        },
        };
    }

    my $mw = herramientas::Complementos::create_main_window('Creacion de codigo', 'maximizada', 1 , 0 , 'Codigo', 'Titulo-Principal', 0);
    
    my $existe_agente = 1;
    # Validar que la ruta del agente exista
    if (!-d $ruta_agente) {
        herramientas::Complementos::show_alert($mw, 'ERROR', 'La ruta del agente no existe', 'error');
        $existe_agente = 0;
        return;
    } # Validar que la ruta del agente exista con el nombre del agente
    
    my $ruta_agente_ruta = File::Spec->catfile($ruta_agente, $agente);

    if (!-d $ruta_agente_ruta) {
        herramientas::Complementos::show_alert($mw, 'ERROR', 'La ruta del agente no existe', 'error');
        $existe_agente = 0;
        return;
    } 

    if ($existe_agente){
        print "Creando codigo del agente SNMP\n";
    }




}

1;

