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
use File::Spec;

# Función principal para crear el agente SNMP
sub crear_agente_snmp {
    my $mw = herramientas::Complementos::create_main_window('Crear Agente SNMP', 'maximizada', 1 , 1 , 'Agente SNMP', 'Titulo-Principal');
    my $frame_principal = $mw->Frame(-bg => $herramientas::Estilos::bg_color_snmp)->pack(-pady => 20);

    my $entry_nombre_agente = herramientas::Complementos::create_entry_with_label_and_button($frame_principal, 'Ingresa el nombre del agente', 'Guardar');
    my $entry_ruta_agente = herramientas::Complementos::register_directory($frame_principal, 'Selecciona la ruta donde se creara el agente', "Buscar");

    my $boton_crear_agente = $frame_principal->Button(
        -text => 'Crear Agente', 
        -bg => $herramientas::Estilos::bg_color_snmp, 
        -fg => $herramientas::Estilos::fg_color_snmp, 
        -font => $herramientas::Estilos::agents_button_font, 
        -command => sub {
            eval {
                procesar_creacion_agente($mw, $frame_principal, $entry_nombre_agente, $entry_ruta_agente);
            };
            if ($@) {
                print "Error al crear el agente SNMP: $@\n";
                herramientas::Complementos::show_alert($mw, 'ERROR', 'Error al crear el agente SNMP', 'error');
            }
        }
    )->pack(-side => 'top', -padx => 5, -pady => 5);

    MainLoop();
}

# Función para procesar la creación del agente
sub procesar_creacion_agente {
    my ($mw, $frame_principal, $entry_nombre_agente, $entry_ruta_agente) = @_;
    my $nombre_agente = $entry_nombre_agente->get();
    my $ruta_agente = $entry_ruta_agente->get();
    my $ruta_agente_ruta = File::Spec->catfile($ruta_agente, $nombre_agente);
    # Normalizar el nombre del agente
    $nombre_agente =~ s/^\s+|\s+$//g;  # Eliminar espacios en blanco al principio y al final
    $nombre_agente =~ s/\s+/ /g;  # Eliminar espacios en blanco duplicados
    $nombre_agente =~ s/\s+/_/g;  # Reemplazar espacios en blanco por guiones bajos
    $nombre_agente = lc($nombre_agente);  # Convertir a minúsculas

    my $respuesta_arbol = Logic::crear_arbol_directorio($mw, $ruta_agente, $nombre_agente);
    if ($respuesta_arbol) {
        herramientas::Complementos::show_alert($mw, 'PROCESO EXITOSO', 'Se ha creado el arbol de directorios correctamente', 'success');
        $frame_principal->packForget();
        if (Logic::validar_existencia_archivo_properties($mw, $ruta_agente_ruta)) {
            crear_interfaz_personalizacion($mw, $mw, $nombre_agente, $ruta_agente);
        }
    } else {
        herramientas::Complementos::show_alert($mw, 'PROCESO CANCELADO', 'El proceso ha sido cancelado', 'warning');
    }
}

# Función para crear la interfaz gráfica y validar los checkbuttons
sub crear_interfaz_personalizacion {
    my ($frame_principal, $ventana_principal, $agente, $ruta_agente) = @_;
    $ventana_principal = $frame_principal if defined $ventana_principal;
    my $ruta_agente_ruta = $ruta_agente . '/' . $agente;  
    my $response;  

    my $frame_personalizacion = $frame_principal->Frame(-bg => $herramientas::Estilos::bg_color_snmp)->pack(-pady => 20, -fill => 'both', -expand => 1);
    my $label_personalizacion = $frame_personalizacion->Label(
        -text => 'Personalizacion del Agente SNMP',
        -bg => $herramientas::Estilos::bg_color_snmp,
        -fg => $herramientas::Estilos::fg_color_snmp,
        -font => $herramientas::Estilos::label_font_snmp
    )->pack(-side => 'top', -padx => 5, -pady => 5);

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
            $response = Validaciones::validar_checkbuttons($ventana_principal, \$var_local, \$var_produccion, $frame_personalizacion, 'agent_properties', $agente, $ruta_agente_ruta)
        }
    )->pack(-side => 'right', -padx => 5, -pady => 5);

    return $frame_personalizacion;
}

1;