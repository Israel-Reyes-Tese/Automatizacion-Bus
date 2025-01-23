# herramientas/Toolbar.pm
package herramientas::Toolbar;
use lib $FindBin::Bin . "/herramientas";  # Añadir la carpeta donde se encuentran los módulos
use lib $FindBin::Bin . "./Script Generacion de Agentes SNMP/";
use lib $FindBin::Bin . "./Script Generacion de Agentes SNMP/utilidades";
use lib $FindBin::Bin . "./Script Generacion de Agentes SNMP/terminal";

use strict;
use warnings;
use Tk;
use Rutas; # Importar el módulo de rutas
# Ventanas secundarias
use MIB_utils;
use Crear_Codigo;
use Create_terminal;


# Constructor
sub new {
    my ($class, $parent, $exit) = @_;
    $exit = 1 unless defined $exit;
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
        $self->herramientas::Complementos::create_button_with_picture_and_label($parent, 'Inicio', Rutas::home_image_path(), sub { print "Redirigiendo a la página principal...\n"; });
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al crear el botón de inicio en el constructor: $error";
    };

    eval {
        # Crear el botón de agentes con el label
        $self->herramientas::Complementos::create_button_with_picture_and_label($parent, 'Agentes', Rutas::agentes_home_image_path(), \&go_to_agents);
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al crear el botón de agentes en el constructor: $error";
    };

    eval {
        # Crear el botón de MIB con el label
        $self->herramientas::Complementos::create_button_with_picture_and_label($parent, 'MIB', Rutas::mib_home_image_path(), \&go_to_mib);
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al crear el botón de MIB en el constructor: $error";
    };



    eval {
        # Crear el botón de codificación con el label
        $self->herramientas::Complementos::create_button_with_picture_and_label($parent, 'Codigo', Rutas::codificacion_image_path(), \&go_to_codificacion);
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al crear el botón de codificación en el constructor: $error";
    };



    eval {
        # Crear el botón de terminal con el label
        $self->herramientas::Complementos::create_button_with_picture_and_label($parent, 'Terminal', Rutas::terminal_image_path(), \&go_to_terminal);
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al crear el botón de terminal en el constructor: $error";
    };

    eval {
        # Crear el botón de salir con el label
        $self->herramientas::Complementos::create_button_with_picture_and_label($parent, 'Salir', Rutas::exit_image_path(), sub { 
            if ($exit) {
                exit;
            } else {
                $parent->destroy();
                }
            
            
             });
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al crear el botón de salir en el constructor: $error";
    };


    return $self;
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
# Función para redirigir a la ventana de MIB
sub go_to_mib {
    eval {
        utilidades::MIB_utils::Inicio_MIBS();
        #system($^X, "./Script Generacion de Agentes SNMP/utilidades/MIB_utils.pm");
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al redirigir a la ventana de MIB: $error";
    };
}

# Función para redirigir a la ventana de codificación
sub go_to_codificacion {
    eval {
        utilidades::Crear_Codigo::Inicio_Crear_Codigo();
        #system($^X, "./Script Generacion de Agentes SNMP/utilidades/Crear_Codigo.pm");
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al redirigir a la ventana de codificacion: $error";
    };
}

# Función para redirigir a la terminal
sub go_to_terminal {
    eval {
        terminal::Create_terminal::create_terminal_window();
        #system($^X, "./Script Generacion de Agentes SNMP/terminal/terminal.pm");
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al redirigir a la terminal: $error";
    };

}

1;  # Fin del módulo