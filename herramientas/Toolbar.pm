# herramientas/Toolbar.pm
package herramientas::Toolbar;
use lib $FindBin::Bin . "/herramientas";  # Añadir la carpeta donde se encuentran los módulos

use strict;
use warnings;
use Tk;
use Rutas;                       # Importar el módulo de rutas

# Constructor
sub new {
    my ($class, $parent) = @_;
    my $self = {};
    bless $self, $class;

    eval {
        # Crear la barra de herramientas
        $self->{toolbar} = $parent->Frame(-bg => '#723185')->pack(-fill => 'x');
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al crear la barra de herramientas en el constructor: $error";
    };

    eval {
        # Crear el botón de inicio con el label
        $self->create_button_with_label($parent, 'Inicio', Rutas::home_image_path(), sub { print "Redirigiendo a la página principal...\n"; });
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al crear el botón de inicio en el constructor: $error";
    };

    eval {
        # Crear el botón de agentes con el label
        $self->create_button_with_label($parent, 'Agentes', Rutas::agentes_home_image_path(), \&go_to_agents);
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al crear el botón de agentes en el constructor: $error";
    };


    eval {
        # Crear el botón de salir con el label
        $self->create_button_with_label($parent, 'Salir', Rutas::exit_image_path(), sub { exit });
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al crear el botón de salir en el constructor: $error";
    };

    return $self;
}

# Subrutina para crear un botón con un label debajo
sub create_button_with_label {
    my ($self, $parent, $label_text, $image_path, $command) = @_;

    my $image;
    eval {
        $image = $parent->Photo(-file => $image_path);  # Cargar la imagen desde la ruta
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al cargar la imagen en create_button_with_label: $error";
    };

    eval {
        # Crear un frame para contener el botón y el label
        my $button_frame = $self->{toolbar}->Frame(-bg => '#723185');
        $button_frame->pack(-side => 'left', -padx => 5, -pady => 5);

        my $button = $button_frame->Button(
            -image => $image,
            -command => $command,
            -bg => '#723185',
            -fg => 'white',
            -activebackground => '#5b2b6e',
            -borderwidth => 0,
        );
        $button->pack(-side => 'top');

        my $label = $button_frame->Label(
            -text => $label_text,
            -bg => '#723185',
            -fg => 'white',
        );
        $label->pack(-side => 'top');
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al crear el botón y el label en create_button_with_label: $error";
    };
}

# Función para redirigir a la ventana de agentes
sub go_to_agents {
    eval {
        system($^X, "./Script Generacion de Agentes SNMP/main_agents.pl");
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al redirigir a la ventana de agentes: $error";
    };
}

1;  # Fin del módulo