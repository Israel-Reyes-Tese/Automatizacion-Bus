#!/usr/bin/perl

package utilidades::MIB_utils;

use strict;
use warnings;
use Tk;
use Tk::Pane;
use Tk::FileSelect;

use FindBin;
use lib $FindBin::Bin . "/../herramientas";
use lib $FindBin::Bin . "/../../herramientas";  # Añadir la carpeta donde se encuentran los modulos
use File::Spec;

use Estilos;
use Complementos;
use Rutas;
use Logic;
use LogicMIB;
use Validaciones;

sub Inicio_MIBS {
    my $mw = herramientas::Complementos::create_main_window('Inicio MIB', 'maximizada', 1 , 0 , 'MIB', 'Titulo-Principal', 0);

    # Crear un frame principal para el menú
    my $frame_principal_mib = $mw->Frame(-bg => $herramientas::Estilos::bg_color)->pack(-expand => 1, -fill => 'both');

    # Crear un frame para los botones de acciones con desplazamiento horizontal
    my $actions_frame = $frame_principal_mib->Scrolled('Frame', -scrollbars => 'x', -bg => $herramientas::Estilos::forest_shadow)->pack(-side => 'top', -fill => 'x');

    # Crear un frame principal
    my $main_frame = $frame_principal_mib->Frame(-bg => $herramientas::Estilos::soil_black)->pack(-expand => 1, -fill => 'both');

    # Crear un panel de desplazamiento para el árbol MIB
    my $mib_tree_pane = $main_frame->Scrolled('Pane', -scrollbars => 'osoe', -bg => $herramientas::Estilos::twilight_grey)->pack(-side => 'left', -fill => 'y');

    # Crear un panel de desplazamiento para la tabla de resultados
    my $result_table_pane = $main_frame->Scrolled('Pane', -scrollbars => 'osoe', -bg => $herramientas::Estilos::forest_shadow)->pack(-side => 'right', -fill => 'both', -expand => 1);


    my $extension_mib = 1;
    my $extension_txt = 0;
    my $extension_vacio = 0;

    # Check button para confirmar si se busca todos los archivos con extension .mib - Por defecto activado - Ubicado en el panel de resultados hasta arriba
    my $check_button_mib = $result_table_pane->Checkbutton(
        -text => 'Buscar todos los archivos con extension .mib',
        -bg => $herramientas::Estilos::forest_shadow,
        -fg => $herramientas::Estilos::soil_black,
        -font => $herramientas::Estilos::button_font,
        -variable => \$extension_mib,
    )->pack(-side => 'left', -padx => 5, -pady => 5);
        # Check button para confirmar si se busca todos los archivos con extension .txt - Por defecto activado - Ubicado en el panel de resultados hasta arriba
    my $check_button_txt = $result_table_pane->Checkbutton(
        -text => 'Buscar todos los archivos con extension .txt',
        -bg => $herramientas::Estilos::forest_shadow,
        -fg => $herramientas::Estilos::soil_black,
        -font => $herramientas::Estilos::button_font,
        -variable => \$extension_txt,
    )->pack(-side => 'left', -padx => 5, -pady => 5);
    # Check button para confirmar si se busca todos los archivos con extension vacia - Por defecto activado - Ubicado en el panel de resultados hasta arriba
    my $check_button_vacio = $result_table_pane->Checkbutton(
        -text => 'Buscar todos los archivos sin extension',
        -bg => $herramientas::Estilos::forest_shadow,
        -fg => $herramientas::Estilos::soil_black,
        -font => $herramientas::Estilos::button_font,
        -variable => \$extension_vacio,
    )->pack(-side => 'left', -padx => 5, -pady => 5);


    # Crear botones de acciones
    $actions_frame->Button(
        -text => 'Cargar MIB',
        -command => sub { LogicMIB::cargar_mib($main_frame, $result_table_pane, $mib_tree_pane, $extension_mib, $extension_txt, $extension_vacio) },
        -bg => $herramientas::Estilos::hoja_verde,
        -fg => $herramientas::Estilos::soil_black,
        -font => $herramientas::Estilos::button_font
    )->pack(-side => 'left', -padx => 5, -pady => 5);

    MainLoop();
}



# Funciones de manejo de menús
sub listar_modulos_mib {
    my ($parent) = @_;
    # Implementar la logica para listar modulos MIB
}

sub cambiar_direccion_servidor {
    my ($parent) = @_;
    # Implementar la logica para cambiar la direccion del servidor
}

sub abrir_sesion {
    my ($parent) = @_;
    # Implementar la logica para abrir una sesion
}

sub abrir_datos_grafico {
    my ($parent) = @_;
    # Implementar la logica para abrir datos de gráfico
}

sub guardar_sesion {
    my ($parent) = @_;
    # Implementar la logica para guardar una sesion
}

sub buscar_en_arbol_mib {
    my ($parent) = @_;
    # Implementar la logica para buscar en el árbol MIB
}

sub buscar_en_tabla_resultados {
    my ($parent) = @_;
    # Implementar la logica para buscar en la tabla de resultados
}

1;