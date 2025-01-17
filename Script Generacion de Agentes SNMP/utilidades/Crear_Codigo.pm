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
use lib $FindBin::Bin . "../utilidades";

use File::Path qw(make_path rmtree);
use File::Temp qw(tempfile);
use File::Spec;
use Cwd 'abs_path';

use Estilos;
use Complementos;
use Rutas;
use Logic;
use LogicMIB;
use LogicEstructura;
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
    print "Nombre del agente: $agente\n";
    print "Ruta del agente: $ruta_agente\n";

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


    print "Creando codigo del agente SNMP\n";
    crear_panel_scrolleable($mw, $agente, $ruta_agente, $alarmas_principales, $alarmas_secundarias);


}

# Function to create a scrollable panel with cards
sub crear_panel_scrolleable {
    my ($parent, $agente, $ruta_agente_ruta, $alarmas_principales, $alarmas_secundarias) = @_;

    # Create a frame for the scrollable panel
    my $scroll_frame = $parent->Frame(-background => $herramientas::Estilos::bg_color)->pack(-side => 'top', -fill => 'both', -expand => 1);
    my $scroll = $scroll_frame->Scrolled('Pane', -scrollbars => 'osoe', -bg => $herramientas::Estilos::bg_color)->pack(-side => 'top', -fill => 'both', -expand => 1);

    # Create cards
    my @cards = (
        { title => 'Crear Codigo Principal', button_text => 'Ejecutar', command => sub { LogicEstructura::crear_codigo_principal() } },
        { title => 'Crear Codigo Parseador', button_text => 'Ejecutar', command => sub { LogicEstructura::crear_codigo_parseador() } },
        { title => 'Crear Archivo de Subrutinas', button_text => 'Ejecutar', command => sub { LogicEstructura::crear_archivo_subrutinas($parent, $agente, $ruta_agente_ruta, $alarmas_principales, $alarmas_secundarias) } },
        { title => 'Crear Archivos Genericos', button_text => 'Ejecutar', command => sub { LogicEstructura::crear_archivos_genericos() } },
    );

    foreach my $card (@cards) {
        my $card_frame = $scroll->Frame(-background => $herramientas::Estilos::bg_color, -relief => 'raised', -borderwidth => 2)->pack(-side => 'top', -fill => 'x', -pady => 5, -padx => 5);
        $card_frame->Label(
            -text => $card->{title},
            -background => $herramientas::Estilos::bg_color,
            -foreground => $herramientas::Estilos::fg_color,
            -font => $herramientas::Estilos::label_font
        )->pack(-side => 'top', -anchor => 'w', -padx => 10, -pady => 5);
        $card_frame->Button(
            -text => $card->{button_text},
            -command => $card->{command},
            -background => $herramientas::Estilos::button_color,
            -foreground => $herramientas::Estilos::fg_color,
            -font => $herramientas::Estilos::button_font,
            -activebackground => $herramientas::Estilos::activebackground_button_color_snmp,
            -activeforeground => $herramientas::Estilos::activeforeground_button_color_snmp
        )->pack(-side => 'bottom', -padx => 10, -pady => 5);
    }
}


1;

