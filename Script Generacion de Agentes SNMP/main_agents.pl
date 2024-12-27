#!/usr/bin/perl
use strict;
use warnings;

use FindBin;
use lib $FindBin::Bin . "/../herramientas";
use Toolbar;

use Tk;

# Colores de la paleta
my $bg_color = '#723185';      # Color de fondo
my $fg_color = 'white';        # Color de texto
my $button_color = '#5b2b6e';  # Color del botón

# Función principal para iniciar la aplicación
sub main {
    eval {
        my $mw = MainWindow->new();

        # Establecer el título de la ventana
        $mw->title('Inicio Agentes');
        
        # Maximizar la ventana
        $mw->state('zoomed');

        # Configurar el color de fondo de la ventana
        $mw->configure(bg => $bg_color);

        # Crear la barra de herramientas
        my $toolbar = herramientas::Toolbar->new($mw);

        # Crear un frame para los botones de agentes
        my $frame = $mw->Frame(-bg => $bg_color)->pack(-pady => 20);

        # Crear botones de agentes con etiquetas
        create_button_with_label($frame, 'SNMP', sub { print "SNMP button clicked\n"; });
        create_button_with_label($frame, 'CORBA', sub { print "CORBA button clicked\n"; });
        create_button_with_label($frame, 'ASCII', sub { print "ASCII button clicked\n"; });

        # Mantener la ventana abierta
        MainLoop();
    };

    # Manejo de errores
    if ($@) {
        die "Error al inicializar la aplicación: $@";
    }
}

# Subrutina para crear un botón con un label debajo
sub create_button_with_label {
    my ($parent, $label_text, $command) = @_;

    my $button_frame = $parent->Frame(-bg => $bg_color);
    $button_frame->pack(-side => 'left', -padx => 10);

    my $button = $button_frame->Button(
        -text => $label_text,
        -command => $command,
        -bg => $button_color,
        -fg => $fg_color,
        -font => ['Verdana', 16, 'bold']
    );
    $button->pack(-side => 'top');

    my $label = $button_frame->Label(
        -text => $label_text,
        -bg => $bg_color,
        -fg => $fg_color,
        -font => ['Verdana', 12]
    );
    $label->pack(-side => 'top');
}

# Ejecutar la función principal
main();
