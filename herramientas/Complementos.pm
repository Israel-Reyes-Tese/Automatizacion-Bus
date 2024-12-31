# herramientas/Complementos.pm
package herramientas::Complementos;
# Importar módulos
use strict;
use warnings;
use Tk;
use Tk::FileDialog;

use FindBin;  # Añadir FindBin para obtener la ruta del script
use lib $FindBin::Bin . "/herramientas";  # Añadir la carpeta donde se encuentran los módulos

# Importar los estilos
use Estilos;
use Rutas;
use Logic;


# Dentro de la misma ventana principal

# Función para crear una label con un texto

sub create_label {
    my ($main_window, $text, $posicion) = @_;

    if ($posicion eq 'Titulo-Principal'){
        $main_window->Label(
            -text => $text, 
            -font => $herramientas::Estilos::label_font,
            -bg => $herramientas::Estilos::bg_color,
            -fg => $herramientas::Estilos::fg_color
            )->pack(-pady => 20);     
    } 

}


# Función para crear un botón con imagen y etiqueta
sub create_button_with_picture_and_label {
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

# Función para crear un botón con imagen y etiqueta
sub create_button_with_picture_and_label_main_window {
    my ($parent, $frame, $label_text, $image_path, $command) = @_;
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
        my $button_frame = $frame->Frame(-bg => '#723185');
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


# Subrutina para crear un botón con un label debajo
sub create_button_with_label {
    my ($parent, $label_text, $command) = @_;

    my $button_frame = $parent->Frame(-bg => $herramientas::Estilos::bg_color);
    $button_frame->pack(-side => 'left', -padx => 10);

    my $button = $button_frame->Button(
        -text => $label_text,
        -command => $command,
        -bg => $herramientas::Estilos::button_color,
        -fg => $herramientas::Estilos::fg_color,
        -font => ['Verdana', 16, 'bold']
    );
    $button->pack(-side => 'top');

    my $label = $button_frame->Label(
        -text => $label_text,
        -bg => $herramientas::Estilos::bg_color,
        -fg => $herramientas::Estilos::fg_color,
        -font => ['Verdana', 12]
    );
    $label->pack(-side => 'top');
}

# Subrutina para crear entradas de texto con etiquetas y botones
sub create_entry_with_label_and_button {
    my ($parent, $label_text, $button_text) = @_;
    my $entry_name = '';

    # Crear un frame para el campo de entrada
    my $entry_frame = $parent->Frame(-bg => '#e5d0bf', -relief => 'solid', -bd => 1)->pack(-side => 'top', -padx => 5, -pady => 5);

    # Añadir etiqueta si se proporciona
    if ($label_text) {
        $entry_frame->Label(
            -text => $label_text, 
            -bg => $herramientas::Estilos::label_color_snmp, 
            -fg => $herramientas::Estilos::label_fg_color_snmp, 
            -font => $herramientas::Estilos::label_font_snmp
        )->pack(-side => 'top', -pady => 10);
    }

    # Crear el campo de entrada
    my $entry_nombre_agente = $entry_frame->Entry(
        -textvariable => \$entry_name, 
        -width => 40, 
        -bg => $herramientas::Estilos::bg_color_snmp, 
        -fg => $herramientas::Estilos::fg_color_snmp, 
        -bd => 0, 
        -highlightthickness => 0, 
        -insertbackground => $herramientas::Estilos::insertbackground,
        -font => $herramientas::Estilos::input_font_snmp
    )->pack(-padx => 20, -pady => 20);

    # Añadir botón si se proporciona
    if ($button_text) {
        $entry_frame->Button(
            -text => $button_text, 
            -bg => $herramientas::Estilos::button_color_snmp, 
            -fg => $herramientas::Estilos::fg_color_snmp, 
            -bd => 0, 
            -font => $herramientas::Estilos::button_font_snmp,
            -activebackground => $herramientas::Estilos::bg_button_color_snmp, 
            -activeforeground => $herramientas::Estilos::fg_button_color_snmp, 
            -relief => 'flat', 
            -highlightthickness => 0, 
            -padx => 10, 
            -pady => 5, 
            -command => sub {
                print "Name: $entry_name\n";
            }
        )->pack(-side => 'left', -padx => 10, -pady => 10);
    }

    return $entry_nombre_agente;
}

# Function to create an alert with picture, label, and button(s)
sub create_alert_with_picture_label_and_button {
    my ($parent, $title, $message, $type) = @_;
    my $alert_window = $parent->Toplevel();
    $alert_window->title($title);
    $alert_window->geometry('300x200+400+200');

    my $bg_color;
    my $image_path;
    if ($type eq 'success') {
        $bg_color = $herramientas::Estilos::bg_color_success;
        $image_path = Rutas::success_image_path();
    } elsif ($type eq 'error') {
        $bg_color = $herramientas::Estilos::bg_color_error;
        $image_path = Rutas::error_image_path();
    } elsif ($type eq 'warning') {
        $bg_color = $herramientas::Estilos::bg_color_warning;
        $image_path = Rutas::warning_image_path();
    } elsif ($type eq 'info') {
        $bg_color = $herramientas::Estilos::bg_color_info;
        $image_path = Rutas::info_image_path();
    } elsif ($type eq 'question') {
        $bg_color = $herramientas::Estilos::bg_color_question;
        $image_path = Rutas::question_image_path();
    }

    $alert_window->configure(-bg => $bg_color);

    my $frame = $alert_window->Frame(-bg => $bg_color)->pack(-expand => 1, -fill => 'both');
    $frame->Label(-image => $alert_window->Photo(-file => $image_path), -bg => $bg_color)->pack(-side => 'top', -pady => 10);
    $frame->Label(-text => $message, -bg => $bg_color, -fg => 'white', -font => $herramientas::Estilos::label_font_alert)->pack(-side => 'top', -pady => 10);

    if ($type eq 'success' || $type eq 'error') {
        $frame->Button(-text => 'Aceptar', -command => sub { $alert_window->destroy() }, -bg => 'white', -fg => $bg_color)->pack(-side => 'top', -pady => 10);
    } elsif ($type eq 'question') {
        my $response;
        $frame->Button(-text => 'Si', -command => sub { $alert_window->destroy(); $response = 1; }, -bg => 'white', -fg => $bg_color)->pack(-side => 'left', -padx => 10, -pady => 10);
        $frame->Button(-text => 'No', -command => sub { $alert_window->destroy(); $response = 0; }, -bg => 'white', -fg => $bg_color)->pack(-side => 'right', -padx => 10, -pady => 10);
         # Wait for the window to be destroyed before returning the response
        $alert_window->waitWindow();
        return $response;
    } elsif ($type eq 'warning' || $type eq 'info') {
        $frame->Button(-text => 'Aceptar', -command => sub { $alert_window->destroy() }, -bg => 'white', -fg => $bg_color)->pack(-side => 'top', -pady => 10);
    }
}
# Subrutina para crear el campo de entrada de directorio
sub register_directory {
    my ($parent, $label_text, $button_text) = @_;
    my $directorio = '/';  # Inicializar la variable con una cadena vacía
    my $entry_frame;

    # Validar si se trata de un widget hijo colocarlo en la parte inferior suponiendo hay un frame superior
    $entry_frame = $parent->Frame(
        -bg => $herramientas::Estilos::bg_color_directory, 
        -relief => 'solid', 
        -bd => 1
    )->pack(-side => 'top', -padx => 5, -pady => 5);

    # Añadir etiqueta si se proporciona
    if ($label_text) {
        $entry_frame->Label(
            -text => $label_text, 
            -bg => $herramientas::Estilos::bg_color_directory, 
            -fg => $herramientas::Estilos::fg_color_directory, 
            -font => $herramientas::Estilos::label_font_directory
        )->pack(-side => 'top', -pady => 10);
    }

    # Crear el campo de entrada
    my $entry_directorio = $entry_frame->Entry(
        -textvariable => \$directorio, 
        -width => 40, 
        -bg => $herramientas::Estilos::bg_color_directory, 
        -fg => $herramientas::Estilos::fg_color_directory, 
        -bd => 0, 
        -highlightthickness => 0, 
        -insertbackground => $herramientas::Estilos::fg_color_directory,
        -font => $herramientas::Estilos::input_font_directory
    )->pack(-padx => 20, -pady => 20);

    # Añadir botón si se proporciona
    $entry_frame->Button(
        -text => $button_text, 
        -bg => '#7a748e', 
        -fg => '#f2e6da', 
        -bd => 0, 
        -font => ['Arial', 12, 'bold'],
        -activebackground => '#5e5673', 
        -activeforeground => '#f2e6da', 
        -relief => 'flat', 
        -highlightthickness => 0, 
        -padx => 10, 
        -pady => 5, 
        -command => sub {
            choose_directory($parent, $directorio, $entry_directorio);
        }
    )->pack(-side => 'left', -padx => 10, -pady => 10);

    return $entry_directorio;
}



# Ventas extras - emergentes
# Función para mostrar información "Acerca de"
sub show_about {
    my ($main_window) = @_;
    my $about_window = $main_window->Toplevel();
    $about_window->title("Acerca de");
    $about_window->Label(-text => "AutoManage GUI\nVersión 1.0\nDesarrollado en Perl", -font => $Estilo::label_font)->pack(padx => 20, pady => 20);
    $about_window->Button(-text => 'Cerrar', -command => sub { $about_window->destroy() })->pack(pady => 10);
}

# Crear ventana de aviso con un mensaje personalizado y un botón para cerrar
sub show_alert {
    my ($main_window, $title, $message, $type) = @_;
    create_alert_with_picture_label_and_button($main_window, $title, $message, $type);
}


# Crear ventan principal y retornar el objeto
sub create_main_window {
    my ($title, $estado, $toolbar, $menu, $create_label_text, $create_label_position) = @_;
    # Inicializar la ventana principal
    my $mw = MainWindow->new();
    # Establecer el título de la ventana
    $mw->title($title);
    # Configurar el color de fondo de la ventana
    $mw->configure(bg => $herramientas::Estilos::bg_color);
    # Maximizar la ventana
    if ($estado eq 'maximizada') {
        $mw->state('zoomed');
    }
    # Crear la barra de herramientas
    if ($toolbar) {
        my $toolbar = herramientas::Toolbar->new($mw);
    }
    # Menu ...............................................
    if ($menu) {
        # Crear la barra de menús
        my $menu_bar = $mw->Menu();
        # Añadir menú "Archivo"
        my $file_menu = $menu_bar->cascade(-label => 'Archivo');
        $file_menu->command(-label => 'Salir', -command => sub { exit });
        # Añadir menú "Ayuda"
        my $help_menu = $menu_bar->cascade(-label => 'Ayuda');
        $help_menu->command(-label => 'Acerca de', -command => sub { herramientas::Complementos::show_about($mw) });
        # Configurar la barra de menús en la ventana principal
        $mw->configure(-menu => $menu_bar);
    }
    # Etiqueta de bienvenida
    if ($create_label_text && $create_label_position) {
        herramientas::Complementos::create_label($mw, $create_label_text, $create_label_position);
    }
    # Retornar la ventana principal
    return $mw;
}

# Funciones de apoyo

sub choose_directory {
    my ($parent, $var_entry, $var_direc ) = @_;
    my $dir = $parent->chooseDirectory(
        -initialdir => '.', 
        -title => 'Selecciona un directorio'
    );
    if (defined $dir && $dir ne '') {
        $var_entry = $dir;
        $var_direc->delete(0, 'end');
        $var_direc->insert(0, $dir);
    } else {
        warn "Error al seleccionar el directorio en la función register_directory\n";
    }

    return $var_entry;
}



1;  # Finalizar el módulo con un valor verdadero