#!/usr/bin/perl
package utilidades::Crear_agente_snmp;

use strict;
use warnings;
use Tk;
use Tk::Pane;
use FindBin;
use lib $FindBin::Bin . "/../herramientas";
use Estilos;
use Complementos;
use Rutas;
use Logic;
use Validaciones;

# Función para crear la interfaz gráfica y validar los checkbuttons
# Función para crear la interfaz gráfica y validar los checkbuttons
sub crear_interfaz_personalizacion {
    my ($frame_principal, $ventana_principal, $agente, $ruta_agente) = @_;
    if (defined $ventana_principal) {
        $ventana_principal = $frame_principal;
    }
    # Ruta completa del agente
    my $ruta_agente_ruta = $ruta_agente . '/' . $agente;  
    my $response;  


    # Crear un frame para la personalización del agente
    my $frame_personalizacion = $frame_principal->Frame(-bg => $herramientas::Estilos::bg_color_snmp)->pack(-pady => 20, -fill => 'both', -expand => 1);
    my $label_personalizacion = $frame_personalizacion->Label(
        -text => 'Personalizacion del Agente SNMP',
        -bg => $herramientas::Estilos::bg_color_snmp,
        -fg => $herramientas::Estilos::fg_color_snmp,
        -font => $herramientas::Estilos::label_font_snmp)->pack(-side => 'top', -padx => 5, -pady => 5);

    my $frame_configuracion = $frame_personalizacion->Frame(-bg => $herramientas::Estilos::bg_color_snmp)->pack(-pady => 20);

    my $var_local = 0;
    my $var_produccion = 0;

    my $checkbutton_local = $frame_configuracion->Checkbutton(
        -text => 'Local',
        -bg => $herramientas::Estilos::bg_color_snmp,
        -fg => $herramientas::Estilos::fg_color_snmp,
        -font => $herramientas::Estilos::label_font_snmp,
        -variable => \$var_local,
        -command => sub { Validaciones::validar_checkbuttons($ventana_principal, \$var_local, \$var_produccion, $frame_personalizacion, 'agent_properties', $agente, $ruta_agente_ruta) }
    )->pack(-side => 'left', -padx => 5, -pady => 5);

    my $checkbutton_produccion = $frame_configuracion->Checkbutton(
        -text => 'En produccion',
        -bg => $herramientas::Estilos::bg_color_snmp,
        -fg => $herramientas::Estilos::fg_color_snmp,
        -font => $herramientas::Estilos::label_font_snmp,
        -variable => \$var_produccion,
        -command => sub { 
            $response = Validaciones::validar_checkbuttons($ventana_principal, \$var_local, \$var_produccion, $frame_personalizacion, 'agent_properties', $agente, $ruta_agente_ruta
            ) }
    )->pack(-side => 'right', -padx => 5, -pady => 5);


    return $frame_personalizacion;


}




sub crear_agente_snmp {
    # Variables para el manejo del proceso 
    my $primer_paso;
    
    my $mw = herramientas::Complementos::create_main_window('Crear Agente SNMP', 'maximizada', 1 , 1 , 'Agente SNMP', 'Titulo-Principal');
    # Crear un frame para los campos de entrada
    my $frame_principal = $mw->Frame(-bg => $herramientas::Estilos::bg_color_snmp)->pack(-pady => 20);
    # Crear etiquetas y campos de entrada
    my $entry_nombre_agente = herramientas::Complementos::create_entry_with_label_and_button($frame_principal, 'Ingresa el nombre del agente', 'Guardar');
    # Ruta donde se van a crear los elementos del agente
    my $entry_ruta_agente = herramientas::Complementos::register_directory($frame_principal, 'Selecciona la ruta donde se creara el agente', "Buscar");

    # Boton para crear el agente
    my $boton_crear_agente = $frame_principal->Button(
    -text => 'Crear Agente', 
    -bg => $herramientas::Estilos::bg_color_snmp, 
    -fg => $herramientas::Estilos::fg_color_snmp, 
    -font => $herramientas::Estilos::agents_button_font, -command => sub {
        my $nombre_agente = $entry_nombre_agente->get();
        my $ruta_agente = $entry_ruta_agente->get();
        # Ruta completa del agente
        my $ruta_agente_ruta =   File::Spec->catfile($ruta_agente, $nombre_agente);
        eval {
            my $respuesta_arbol = Logic::crear_arbol_directorio($mw, $ruta_agente, $nombre_agente);
            if ($respuesta_arbol) {
                herramientas::Complementos::show_alert($mw, 'PROCESO EXITOSO', 'Se ha creado el arbol de directorios correctamente', 'success');
                # Ocultar el frame principal
                $frame_principal->packForget();
                # Validar la existencia del archivo AGENT.properties
                if (Logic::validar_existencia_archivo_properties($mw, $ruta_agente_ruta)) {
                    # Se inicializa la personalización del agente.
                    my $response_properties = crear_interfaz_personalizacion($mw, $mw, $nombre_agente, $ruta_agente);
                }
            
            } else {
                herramientas::Complementos::show_alert($mw, 'PROCESO CANCELADO', 'El proceso ha sido cancelado', 'warning');
            }
            $primer_paso = 1;
        };
        if ($@) {
            print "Error al crear el árbol de directorios: $@\n";
            herramientas::Complementos::show_alert($mw, 'ERROR', 'Error al crear el arbol de directorios ', 'error');
            $primer_paso = 0;
        }
    })->pack(-side => 'top', -padx => 5, -pady => 5);
    
    

    MainLoop();
}



1;