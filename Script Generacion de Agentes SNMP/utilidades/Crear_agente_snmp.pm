#!/usr/bin/perl
package utilidades::Crear_agente_snmp;

use strict;
use warnings;
use Tk;
use FindBin;
use lib $FindBin::Bin . "/../herramientas";
use Estilos;
use Complementos;
use Rutas;
use Logic;

sub crear_agente_snmp {
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
        eval {
            my $respuesta_arbol = Logic::crear_arbol_directorio($mw, $ruta_agente, $nombre_agente);
            if ($respuesta_arbol) {
                herramientas::Complementos::show_alert($mw, 'PROCESO EXITOSO', 'Se ha creado el arbol de directorios correctamente', 'success');
            } else {
                herramientas::Complementos::show_alert($mw, 'PROCESO CANCELADO', 'El proceso ha sido cancelado', 'warning');
            }
        };
        if ($@) {
            print "Error al crear el árbol de directorios: $@\n";
            herramientas::Complementos::show_alert($mw, 'ERROR', 'Error al crear el arbol de directorios ', 'error');
        }
    })->pack(-side => 'top', -padx => 5, -pady => 5);
    




    
    MainLoop();
}



1;