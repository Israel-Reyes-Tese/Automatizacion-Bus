# #!/usr/bin/perl

package utilidades::Crear_Codigo;


use strict;
use warnings;
use Tk;
use Tk::Pane;
use Tk::FileSelect;
use Tk::JcomboBox;

use FindBin;
use lib $FindBin::Bin . "/../herramientas";
use lib $FindBin::Bin . "/../../herramientas";  # Añadir la carpeta donde se encuentran los modulos
use lib $FindBin::Bin . "../utilidades";
use lib $FindBin::Bin . "../terminal";

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
use LogicEstructuraLegacy;
use Validaciones;
use Create_terminal;
use Data::Dumper; # Importar el modulo Data::Dumper


# Function to extract alarm information from log files
sub extraer_informacion_alarmas {
    my ($file_path) = @_;
    my %alarmas;

    if (-e $file_path && -s $file_path) {
        open my $fh, '<', $file_path or die "Error al abrir el archivo $file_path: $!";
        my $current_alarm;
        while (my $line = <$fh>) {
            chomp $line;
            if ($line =~ /^(\w+):$/) {
                $current_alarm = $1;
                $alarmas{$current_alarm} = {};
            } elsif ($line =~ /^\s*(\w+):\s*(.+)$/) {
                $alarmas{$current_alarm}{$1} = $2 if $current_alarm;
            }
        }
        close $fh;
    } else {
        die "El archivo $file_path no existe o está vacío.";
    }

    return \%alarmas;
}

sub Inicio_Crear_Codigo {
    my ($agente, $ruta_agente, $alarmas_principales, $alarmas_secundarias) = @_;
    if (!$agente) {
        $agente = 'agente_snmp';
    }
    if (!$ruta_agente) {
        $ruta_agente = Rutas::temp_agents_path();
    }

    # Extract alarm information from log files
    my $alarmas_principales_path = Rutas::temp_files_logs_objects_mibs_path(). '/Alarmas_principales.logs';
    my $alarmas_secundarias_path = Rutas::temp_files_logs_objects_mibs_path(). '/Objetos_principales.logs';

    $alarmas_principales = herramientas::Complementos::extraer_informacion_alarmas($alarmas_principales_path);
    $alarmas_secundarias = herramientas::Complementos::extraer_informacion_alarmas($alarmas_secundarias_path);

    my $mw = herramientas::Complementos::create_main_window('Creacion de codigo', 'maximizada', 1 , 0 , 'Codigo', 'Titulo-Principal', 0);
    
    my $existe_agente = 1;

    crear_panel_scrolleable($mw, $agente, $ruta_agente, $alarmas_principales, $alarmas_secundarias);

}

# Function to create a scrollable panel with cards
sub crear_panel_scrolleable {
    my ($parent, $agente, $ruta_agente_ruta, $alarmas_principales, $alarmas_secundarias) = @_;

    # Create a frame for the scrollable panel
    my $scroll_frame = $parent->Frame(-background => $herramientas::Estilos::bg_color)->pack(-side => 'top', -fill => 'both', -expand => 1);
    my $scroll = $scroll_frame->Scrolled('Pane', -scrollbars => 'osoe', -bg => $herramientas::Estilos::bg_color)->pack(-side => 'top', -fill => 'both', -expand => 1);

    my $legacy = 1;
    my $implementacion;
    my $impresiones_logs = 1;
    # Checkbutton para la opcion legacy 
    my $checkbutton_legacy = $parent->Checkbutton(
        -text => 'Legacy',
        -background => $herramientas::Estilos::bg_color,
        -foreground => $herramientas::Estilos::fg_color,
        -font => $herramientas::Estilos::label_font,
        -variable => \$legacy,
    )->pack(-side => 'top', -padx => 10, -pady => 5);
    # Checkbutton para la opcion impresiones_logs
    my $checkbutton_logs = $parent->Checkbutton(
        -text => 'Impresiones Logs',
        -background => $herramientas::Estilos::bg_color,
        -foreground => $herramientas::Estilos::fg_color,
        -font => $herramientas::Estilos::label_font,
        -variable => \$impresiones_logs,
    )->pack(-side => 'top', -padx => 10, -pady => 5);
    # ComboBox para la opcion local windows o local linux
    my @opciones = ('Local Windows', 'Local Linux', 'Desarrollo');
    $implementacion = 'Local Windows';
    my $combobox = $parent->JComboBox(
        -choices => \@opciones,
        -background => $herramientas::Estilos::bg_color,
        -foreground => $herramientas::Estilos::fg_color,
        -font => $herramientas::Estilos::label_font,
        -textvariable  => \$implementacion,
    )->pack(-side => 'top', -padx => 10, -pady => 5);

    my $comando_ejecutar_local_agente = "perl $ruta_agente_ruta/$agente.pl";
    # Create cards
    my @cards = (
        { title => 'Crear Codigo Principal', button_text => 'Ejecutar', command => sub {if ($legacy){
            LogicEstructuraLegacy::crear_codigo_principal($parent, $agente, $ruta_agente_ruta, $alarmas_principales, $alarmas_secundarias, $implementacion, $impresiones_logs)
        } else {
            LogicEstructura::crear_codigo_principal($parent, $agente, $ruta_agente_ruta, $alarmas_principales, $alarmas_secundarias, $implementacion, $impresiones_logs)
        }
            }, },
        { title => 'Crear Codigo Parseador', button_text => 'Ejecutar', command => sub {
            if ($legacy) {
                LogicEstructuraLegacy::crear_codigo_parseador($parent, $agente, $ruta_agente_ruta, $alarmas_principales, $alarmas_secundarias, $implementacion, $impresiones_logs);
            } else {
                LogicEstructura::crear_codigo_parseador($parent, $agente, $ruta_agente_ruta, $alarmas_principales, $alarmas_secundarias, $implementacion, $impresiones_logs);
            }
            }, },
        { title => 'Crear Archivo de Subrutinas', button_text => 'Ejecutar', command => sub {
            if ($legacy) {
                LogicEstructuraLegacy::crear_archivo_subrutinas($parent, $agente, $ruta_agente_ruta, $alarmas_principales, $alarmas_secundarias, $implementacion, $impresiones_logs);
            } else {
                LogicEstructura::crear_archivo_subrutinas($parent, $agente, $ruta_agente_ruta, $alarmas_principales, $alarmas_secundarias, $implementacion, $impresiones_logs);
            }
            }, },
        { title => 'Crear Archivos Genericos', button_text => 'Ejecutar', command => sub {
            if ($legacy) {
                LogicEstructuraLegacy::crear_archivos_genericos($parent, $agente, $ruta_agente_ruta, $implementacion, $impresiones_logs);
            } else {
                LogicEstructura::crear_archivos_genericos($parent, $agente, $ruta_agente_ruta, $implementacion, $impresiones_logs);
            }
            }, },
        { title => 'Crear Archivos de Mapeo', button_text => 'Ejecutar', command => sub {
            if ($legacy) {
                LogicEstructuraLegacy::crear_archivos_mapeo($parent, $agente, $ruta_agente_ruta, $implementacion, $impresiones_logs);
            } else {
                LogicEstructura::crear_archivos_mapeo($parent, $agente, $ruta_agente_ruta, $implementacion, $impresiones_logs);
            }
            },},
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

    my $footer = $scroll_frame->Scrolled('Pane', -scrollbars => 'osoe', -bg => $herramientas::Estilos::bg_color)->pack(-side => 'top', -fill => 'both', -expand => 1);

    # Buttons
    $footer->Button(
        -text => 'Abrir Carpeta',
        -command => sub { Logic::abrir_carpeta($parent, $ruta_agente_ruta) },
        -background => $herramientas::Estilos::button_color,
        -foreground => $herramientas::Estilos::fg_color,
        -font => $herramientas::Estilos::button_font,
        -activebackground => $herramientas::Estilos::activebackground_button_color_snmp,
        -activeforeground => $herramientas::Estilos::activeforeground_button_color_snmp
    )->pack(-side => 'left', -padx => 10, -pady => 5);

    $footer->Button(
        -text => 'Transformar archivos formato Unix',
        -command => sub { 
            Logic::transformar_archivos_unix($parent, $ruta_agente_ruta, $agente, "AGENT.properties"),
            $parent->destroy();
        },
        -background => $herramientas::Estilos::button_color,
        -foreground => $herramientas::Estilos::fg_color,
        -font => $herramientas::Estilos::button_font,
        -activebackground => $herramientas::Estilos::activebackground_button_color_snmp,
        -activeforeground => $herramientas::Estilos::activeforeground_button_color_snmp
    )->pack(-side => 'right', -padx => 10, -pady => 5);

    $footer->Button(
        -text => 'Pruebas Locales',
        -command => sub { 
            terminal::Create_terminal::create_terminal_window(0, $comando_ejecutar_local_agente, "Agente escuchando.."),
            $parent->destroy();
        },
        -background => $herramientas::Estilos::button_color,
        -foreground => $herramientas::Estilos::fg_color,
        -font => $herramientas::Estilos::button_font,
        -activebackground => $herramientas::Estilos::activebackground_button_color_snmp,
        -activeforeground => $herramientas::Estilos::activeforeground_button_color_snmp
    )->pack(-side => 'right', -padx => 10, -pady => 5);


}



1;

