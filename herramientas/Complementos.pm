# herramientas/Complementos.pm
package herramientas::Complementos;
# Importar módulos
use strict;
use warnings;
use Tk;

use FindBin;  # Añadir FindBin para obtener la ruta del script
use lib $FindBin::Bin . "/herramientas";  # Añadir la carpeta donde se encuentran los módulos

# Importar los estilos
use Estilos;
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




# Ventas extras - emergentes
# Función para mostrar información "Acerca de"
sub show_about {
    my ($main_window) = @_;
    my $about_window = $main_window->Toplevel();
    $about_window->title("Acerca de");
    $about_window->Label(-text => "AutoManage GUI\nVersión 1.0\nDesarrollado en Perl", -font => $Estilo::label_font)->pack(padx => 20, pady => 20);
    $about_window->Button(-text => 'Cerrar', -command => sub { $about_window->destroy() })->pack(pady => 10);
}



1;  # Finalizar el módulo con un valor verdadero