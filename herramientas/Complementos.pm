# herramientas/Complementos.pm
package herramientas::Complementos;
# Importar módulos
use strict;
use warnings;
use Tk;
use Tk::FileDialog;
use Tk::TableMatrix;
use Tk::Pane;

use Data::Dumper;
use Log::Log4perl qw(get_logger :levels);

use FindBin;  # Añadir FindBin para obtener la ruta del script
use lib $FindBin::Bin . "/herramientas";  # Añadir la carpeta donde se encuentran los módulos

# Importar los estilos
use Estilos;
use Rutas;
use Logic;


# Initialize logger
Log::Log4perl->init(\<<'EOT');
log4perl.logger = DEBUG, File

log4perl.appender.File = Log::Log4perl::Appender::File
log4perl.appender.File.filename = terminal.log
log4perl.appender.File.layout = Log::Log4perl::Layout::PatternLayout
log4perl.appender.File.layout.ConversionPattern = %d %p %m %n
EOT

my $logger = get_logger();




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
    my $bg_color_canvas;
    my $image_path;
    if ($type eq 'success') {
        $bg_color = $herramientas::Estilos::bg_color_success;
        $bg_color_canvas = $herramientas::Estilos::forest_shadow;
        $image_path = Rutas::success_image_path();
    } elsif ($type eq 'error') {
        $bg_color = $herramientas::Estilos::bg_color_error;
        $bg_color_canvas = $herramientas::Estilos::forest_shadow;
        $image_path = Rutas::error_image_path();
    } elsif ($type eq 'warning') {
        $bg_color = $herramientas::Estilos::bg_color_warning;
        $bg_color_canvas = $herramientas::Estilos::forest_shadow;
        $image_path = Rutas::warning_image_path();
    } elsif ($type eq 'info') {
        $bg_color = $herramientas::Estilos::bg_color_info;
        $bg_color_canvas = $herramientas::Estilos::forest_shadow;
        $image_path = Rutas::about_image_path();
    } elsif ($type eq 'question') {
        $bg_color = $herramientas::Estilos::bg_color_question;
        $bg_color_canvas = $herramientas::Estilos::forest_shadow;
        $image_path = Rutas::question_image_path();
    }

    $alert_window->configure(-bg => $bg_color);
    my $frame = $alert_window->Frame(-bg => $bg_color)->pack(-expand => 1, -fill => 'both');
    $frame->Label(-image => $alert_window->Photo(-file => $image_path), -bg => $bg_color)->pack(-side => 'top', -pady => 10);
    my $button_frame = $frame->Frame(-bg => $bg_color, -relief => 'flat')->pack(-side => 'top', -fill => 'x', -pady => 10);

    # Frame for the message establecer un dimensiones maximas para el frame que no se expanda por toda la pantalla que deje espacio para el botones y scroll
    my $message_frame = $frame->Frame(-bg => $bg_color)->pack(-expand => 1, -fill => 'both');
    my $canvas = $message_frame->Canvas(-bg => $bg_color_canvas, -highlightthickness => 0)->pack(-expand => 1, -fill => 'both');
    my $scroll = $message_frame->Scrollbar(-command => ['yview', $canvas], -bg => $bg_color_canvas)->pack(-side => 'right', -fill => 'y');
    $canvas->configure(-yscrollcommand => ['set', $scroll]);
    my $text = $canvas->Text(-bg => $bg_color_canvas, -fg => $herramientas::Estilos::fg_color, -font => $herramientas::Estilos::label_font_alert);
    $text->pack(-expand => 1, -fill => 'both');
    $canvas->createWindow(0, 0, -window => $text, -anchor => 'nw');
    $text->insert('end', $message);
    

    # Capture all events to this window
    $alert_window->grab();

    if ($type eq 'success' || $type eq 'error') {
        $button_frame->Button(-text => 'Aceptar', -command => sub { $alert_window->destroy() }, 
        -bg => $herramientas::Estilos::modern_button_bg, 
        -fg => $herramientas::Estilos::modern_button_fg, 
        -font => $herramientas::Estilos::modern_button_font,
        -activebackground => $herramientas::Estilos::modern_button_active_bg, 
        -activeforeground => $herramientas::Estilos::modern_button_active_fg
        )->pack(-side => 'top', -padx => 10, -pady => 5);
    } elsif ($type eq 'question') {
        my $response;
        $button_frame->Button(-text => 'Si', -command => sub { $alert_window->destroy(); $response = 1; }, 
            -bg => $herramientas::Estilos::modern_button_bg, 
            -fg => $herramientas::Estilos::modern_button_fg, 
            -font => $herramientas::Estilos::modern_button_font,
            -activebackground => $herramientas::Estilos::modern_button_active_bg, 
            -activeforeground => $herramientas::Estilos::modern_button_active_fg
        )->pack(-side => 'left', -padx => 10, -pady => 5);
        $button_frame->Button(-text => 'No', -command => sub { $alert_window->destroy(); $response = 0; }, 
            -bg => $herramientas::Estilos::modern_button_bg, 
            -fg => $herramientas::Estilos::modern_button_fg, 
            -font => $herramientas::Estilos::modern_button_font,
            -activebackground => $herramientas::Estilos::modern_button_active_bg, 
            -activeforeground => $herramientas::Estilos::modern_button_active_fg
        )->pack(-side => 'right', -padx => 10, -pady => 5);
        # Wait for the window to be destroyed before returning the response
        $alert_window->waitWindow();
        return $response;
    } elsif ($type eq 'warning' || $type eq 'info' || $type eq 'WARNING' || $type eq 'INFO') {
        $button_frame->Button(-text => 'Aceptar', -command => sub { $alert_window->destroy() }, 
            -bg => $herramientas::Estilos::modern_button_bg, 
            -fg => $herramientas::Estilos::modern_button_fg, 
            -font => $herramientas::Estilos::modern_button_font,
            -activebackground => $herramientas::Estilos::modern_button_active_bg, 
            -activeforeground => $herramientas::Estilos::modern_button_active_fg
        )->pack(-side => 'right', -padx => 10, -pady => 5);
    }

    # Release the grab when the window is destroyed
    $alert_window->waitWindow();
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
    my ($title, $estado, $toolbar, $menu, $create_label_text, $create_label_position, $exit) = @_;
    $exit = 1 unless defined $exit;
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
        my $toolbar = herramientas::Toolbar->new($mw, $exit);
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


# Function to create the main window
sub create_top_level_window {
    my ($main_window, $title, $estado) = @_;
    my $mw = $main_window->Toplevel();
    $mw->title($title);
    $mw->configure(-background => $herramientas::Estilos::twilight_grey);
    if ($estado eq 'maximizada') {
        $mw->state('zoomed');
    }
    return $mw;
}
# Nueva función para crear un panel scrolleable con checkboxes, entradas de texto y combo boxes
sub create_scrollable_panel_with_checkboxes_and_entries {
    my ($ventana_principal, $titulo_principal, $checkbox_data, $entry_data, $combo_box_data, $text_entry_data) = @_;
    
    # Crear la ventana principal
    my $mw = create_top_level_window($ventana_principal, $titulo_principal, 'maximizada');
    
    # Crear un frame con scrollbar
    my $scroll_frame = $mw->Frame(-bg => $herramientas::Estilos::bg_color)->pack(-side => 'top', -fill => 'both', -expand => 1);
    my $scroll = $scroll_frame->Scrolled('Pane', -scrollbars => 'osoe', -bg => $herramientas::Estilos::bg_color)->pack(-side => 'top', -fill => 'both', -expand => 1);
    
    my %checkboxes;
    my %entries;
    my %combo_boxes;
    my %text_entries;
    my $row = 0;
    # Crear el hash con el formato requerido
    my %lista_opciones;

    # Añadir tarjetas con labels y checkboxes si se proporciona checkbox_data
    if ($checkbox_data) {
        foreach my $nombre (keys %{$checkbox_data->{opciones}}) {
            my $card_frame = $scroll->Frame(-bg => $herramientas::Estilos::card_frame_bg, -borderwidth => 2, -relief => 'solid')->grid(-row => $row, -column => 0, -padx => 10, -pady => 10);
            my $label = $card_frame->Label(
                -text => $nombre,
                -font => $herramientas::Estilos::label_font,
                -bg => $herramientas::Estilos::label_bg_color,
                -fg => $herramientas::Estilos::label_fg_color,
                -relief => 'raised',
                -borderwidth => 3
                )->pack(-side => 'left');
            my $checkbox = $card_frame->Checkbutton(
                -bg => $herramientas::Estilos::checkbox_bg, 
                -activebackground => $herramientas::Estilos::checkbox_active_bg,
                -selectcolor => $herramientas::Estilos::checkbox_selectcolor,
                -relief => 'flat', 
                -highlightthickness => 0, 
                -padx => 10, 
                -pady => 5, 
                -variable => \$checkbox_data->{opciones}{$nombre}
            )->pack(-side => 'right');
            $checkboxes{$nombre} = $checkbox;
            $row++;
        }
    }

    # Añadir tarjetas con labels y entradas de texto si se proporciona entry_data
    if ($entry_data) {
        foreach my $nombre (keys %{$entry_data->{opciones}}) {
            my $card_frame = $scroll->Frame(-bg => $herramientas::Estilos::entry_card_frame_bg, -borderwidth => 2, -relief => 'solid')->grid(-row => $row, -column => 0, -padx => 10, -pady => 10);
            my $label = $card_frame->Label(
                -text => $nombre, 
                -font => $herramientas::Estilos::label_font, 
                -bg => $herramientas::Estilos::label_bg_color, 
                -fg => $herramientas::Estilos::label_fg_color

                )->pack(-side => 'left');

            my $entry = $card_frame->Entry(
                -bg => $herramientas::Estilos::entry_bg, 
                -fg => $herramientas::Estilos::entry_fg,
                -textvariable => \$entry_data->{opciones}{$nombre}
            )->pack(-side => 'right');
            $entries{$nombre} = $entry;
            $row++;
        }
    }

    # Añadir tarjetas con labels y combo boxes si se proporciona combo_box_data
    if ($combo_box_data) {
        foreach my $nombre (keys %{$combo_box_data->{opciones}}) {
            my $card_frame = $scroll->Frame(
                -bg => $herramientas::Estilos::combo_box_card_frame_bg,
                -borderwidth => 2,
                -relief => 'solid'
                )->grid(-row => $row, -column => 0, -padx => 10, -pady => 10);
            my $label = $card_frame->Label(
            -text => $nombre, 
            -font => $herramientas::Estilos::label_font,
            -bg => $herramientas::Estilos::label_bg_color,
            -fg => $herramientas::Estilos::label_fg_color,

            )->pack(-side => 'left');

            my $combo_box = $card_frame->BrowseEntry(
                -choices => $combo_box_data->{opciones}{$nombre},
                -bg => $herramientas::Estilos::combo_box_bg,
                -fg => $herramientas::Estilos::combo_box_fg
                )->pack(-side => 'right');

            $combo_box->insert(0, $combo_box_data->{opciones}{$nombre}[0]); # Valor predeterminado
            $combo_boxes{$nombre} = $combo_box;
            $row++;
        }
    }
    
    # Añadir tarjetas con labels y text entries si se proporciona text_entry_data
    if ($text_entry_data) {
        foreach my $nombre (keys %{$text_entry_data->{opciones}}) {
            my $card_frame = $scroll->Frame(
                -bg => $herramientas::Estilos::text_entry_card_frame_bg,
                -borderwidth => 2,
                -relief => 'solid'
                )->grid(-row => $row, -column => 0, -padx => 10, -pady => 10);
            my $label = $card_frame->Label(
            -text => $nombre, 
            -font => $herramientas::Estilos::label_font,
            -bg => $herramientas::Estilos::label_bg_color,
            -fg => $herramientas::Estilos::label_fg_color,

            )->pack(-side => 'left');

            my $text_entry = $card_frame->Text(
                -height => 5, # Altura del widget de texto
                -width => 40, # Ancho del widget de texto
                -bg => $herramientas::Estilos::text_entry_bg,
                -fg => $herramientas::Estilos::text_entry_fg
                )->pack(-side => 'right');

            $text_entry->insert('end', $text_entry_data->{opciones}{$nombre}); # Valor predeterminado
            $text_entries{$nombre} = $text_entry;
            $row++;
        }
    }


    # Crear el footer con el botón de guardar
    my $footer = $mw->Frame(-bg => $herramientas::Estilos::footer_bg)->pack(-side => 'bottom', -fill => 'x');
    my $save_button = $footer->Button(
        -text => 'Guardar', 
        -command => sub { 
                my %selected;
                my @selected_names;
                my %entry_values;
                my %combo_box_values;
                # Iterar sobre el hash %checkboxes y extraer los valores
                foreach my $key (keys %checkboxes) {
                    my $value = $checkboxes{$key}->cget('-variable');
                    $selected{$key} = $$value;
                }
                # Iterar sobre el hash %entries y extraer los valores
                foreach my $key (keys %entries) {
                    my $value = $entries{$key}->get();
                    # Convertir a número entero si es posible
                    if ($value =~ /^\d+$/) {
                        $value = int($value);
                    }
                    $entry_values{$key} = $value;
                }
                # Iterar sobre el hash %combo_boxes y extraer los valores
                foreach my $key (keys %combo_boxes) {
                    my $value = $combo_boxes{$key}->Subwidget('entry')->get();
                    $combo_box_values{$key} = $value;
                }
                # Iterar sobre el hash %text_entries y extraer los valores
                foreach my $key (keys %text_entries) {
                    my $value = $text_entries{$key}->get('1.0', 'end');
                    $text_entries{$key} = $value;
                }
                $lista_opciones{opciones} = \%selected if %selected;
                $lista_opciones{entries} = \%entry_values if %entry_values;
                $lista_opciones{combo_boxes} = \%combo_box_values if %combo_box_values;
                $lista_opciones{text_entries} = \%text_entries if %text_entries;
                show_alert($ventana_principal, 'Guardado', 'Los datos se han guardado correctamente.', 'info');
                # Cerrar la ventana
                $mw->destroy();
         },
        -bg => $herramientas::Estilos::save_button_bg,
        -fg => $herramientas::Estilos::save_button_fg,
        -font => $herramientas::Estilos::save_button_font,
        -activebackground => $herramientas::Estilos::save_button_active_bg,
        -activeforeground => $herramientas::Estilos::save_button_active_fg
    )->pack(-side => 'right', -padx => 10, -pady => 10);
    # Esperar hasta que la ventana se cierre
    $mw->waitWindow();
    return \%lista_opciones;
}
# Tabla con solo data set

sub create_table {
    my ($ventana_principal, $records_per_page, $data_ref, $search_fields) = @_;

    my $mv = create_top_level_window($ventana_principal, 'ARBOL MIB', 'maximizada');

    # Create search entry and button
    my $search_frame = $mv->Frame(-background => $herramientas::Estilos::mib_selection_bg)->pack(-side => 'top', -fill => 'x');
    my $search_entry = $search_frame->Entry(-font => $herramientas::Estilos::input_font)->pack(-side => 'left', -fill => 'x', -expand => 1, -padx => 10, -pady => 10);
    $search_frame->Button(
        -text => "Buscar",
        -command => sub {
            my $search_term = $search_entry->get();
            search_and_display_results($mv, $data_ref, $search_fields, $search_term, $records_per_page);
        },
        -background => $herramientas::Estilos::mib_selection_button_bg,
        -foreground => $herramientas::Estilos::mib_selection_button_fg,
        -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
        -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
        -font => $herramientas::Estilos::mib_selection_button_font
    )->pack(-side => 'right', -padx => 10, -pady => 10);

    # Create home button
    $search_frame->Button(
        -text => "Inicio",
        -command => sub {
            $mv->destroy();
            create_table($ventana_principal, $records_per_page, $data_ref, $search_fields);
        },
        -background => $herramientas::Estilos::nav_button_bg,
        -foreground => $herramientas::Estilos::nav_button_fg,
        -activebackground => $herramientas::Estilos::nav_button_active_bg,
        -activeforeground => $herramientas::Estilos::nav_button_active_fg,
        -font => $herramientas::Estilos::nav_button_font
    )->pack(-side => 'right', -padx => 10, -pady => 10);

    my $frame = $mv->Frame(-background => $herramientas::Estilos::table_fg)->pack(-side => 'top', -fill => 'both', -expand => 1);
    my $scrolled_table = $frame->Scrolled(
        'TableMatrix',
        -rows => $records_per_page + 1,  # +1 for header row
        -cols => 0,  # Se actualizará dinámicamente
        -cache => 1,
        -scrollbars => 'osoe',  # 'osoe' means both horizontal and vertical scrollbars
        -background => $herramientas::Estilos::pine_green,
        -foreground => $herramientas::Estilos::table_fg,
        -font => $herramientas::Estilos::table_font,
    )->pack(-side => 'top', -fill => 'both', -expand => 1);

    my $table = $scrolled_table->Subwidget('scrolled');

    # Function to clear the table
    my $clear_table = sub {
        my $rows = $table->cget('-rows');
        my $cols = $table->cget('-cols');
        for my $row (1 .. $rows - 1) {
            for my $col (0 .. $cols - 1) {
                $table->set("$row,$col", '');
            }
        }
    };

    # Function to adjust column widths
    my $adjust_column_widths = sub {
        my $cols = $table->cget('-cols');
        for my $col (0 .. $cols - 1) {
            my $max_width = 0;
            for my $row (0 .. $table->cget('-rows') - 1) {
                my $cell_value = $table->get("$row,$col");
                my $cell_width = length($cell_value);
                $max_width = $cell_width if $cell_width > $max_width;
            }
            $table->colWidth($col, $max_width + 2);  # Add some padding
        }
    };

    # Function to populate table with data
    my $populate_table = sub {
        my ($data_key) = @_;
        $clear_table->();  # Limpiar la tabla antes de mostrar nuevos datos

        my $data = $data_ref->{$data_key};
        my @header_fields;
        my $is_single_record = 0;

        # Determine if the data is a single record or multiple records
        if (ref $data eq 'HASH') {
            my ($first_key, $first_value) = each %$data;
            if (ref $first_value ne 'HASH') {
                @header_fields = keys %$data;
                $is_single_record = 1;
            } else {
                @header_fields = keys %$first_value;
                push @header_fields, 'OBJETO PRINCIPAL';
            }
        }

        # Actualizar el número de columnas
        $table->configure(-cols => scalar(@header_fields));

        # Create header row
        for my $col (0 .. $#header_fields) {
            $table->set("0,$col", $header_fields[$col]);
        }

        my $row = 1;
        if ($is_single_record) {
            my $col = 0;
            foreach my $field (@header_fields) {
                my $value = $data->{$field} // '';
                $table->set("$row,$col", $value);
                $col++;
            }
        } else {
            foreach my $key (keys %$data) {
                my $col = 0;
                foreach my $field (@header_fields) {
                    my $value = $field eq 'OBJETO PRINCIPAL' ? $key : $data->{$key}{$field} // '';
                    $table->set("$row,$col", $value);
                    $col++;
                }
                $row++;
                last if $row > $records_per_page;
            }
        }

        $adjust_column_widths->();  # Adjust column widths after populating the table
    };

    # Create buttons to switch data
    my $button_frame = $mv->Frame()->pack(-side => 'bottom', -fill => 'x');
    foreach my $key (keys %$data_ref) {
        $button_frame->Button(
            -text => $key,
            -command => sub { $populate_table->($key) },
            -background => $herramientas::Estilos::nav_button_bg,
            -foreground => $herramientas::Estilos::nav_button_fg,
            -activebackground => $herramientas::Estilos::nav_button_active_bg,
            -activeforeground => $herramientas::Estilos::nav_button_active_fg,
            -font => $herramientas::Estilos::nav_button_font
        )->pack(-side => 'left', -padx => 10, -pady => 10);
    }

    # Populate table with initial data
    $populate_table->((keys %$data_ref)[0]);
}

# Tabla con dos data sets
sub create_table_doble_data {
    my ($ventana_principal, $records_per_page, $data_principal_ref, $data_secundaria_ref) = @_;
    my $mv = create_top_level_window($ventana_principal, 'Listado de alarmas', 'maximizada');

    #print "DATA SECUNDARIA: " . Dumper($data_secundaria_ref);

    my $frame = $mv->Frame(-background => $herramientas::Estilos::table_fg)->pack(-side => 'top', -fill => 'both', -expand => 1);
    my $scrolled_table = $frame->Scrolled(
        'TableMatrix',
        -rows => $records_per_page + 1,  # +1 for header row
        -cols => 0,  # Se actualizará dinámicamente
        -cache => 1,
        -scrollbars => 'osoe',  # 'osoe' means both horizontal and vertical scrollbars
        -background => $herramientas::Estilos::pine_green,
        -foreground => $herramientas::Estilos::table_fg,
        -font => $herramientas::Estilos::table_font,
    )->pack(-side => 'top', -fill => 'both', -expand => 1);

    my $table = $scrolled_table->Subwidget('scrolled');
    my $current_page = 1;
    my $current_data_ref = $data_principal_ref;
    my %selected_principal;
    my %selected_secundaria;

    my $selected_data_principal;
    my $selected_data_secundaria;

    # Function to clear the table
    my $clear_table = sub {
        my $rows = $table->cget('-rows');
        my $cols = $table->cget('-cols');
        for my $row (1 .. $rows - 1) {
            for my $col (0 .. $cols - 1) {
                $table->set("$row,$col", '');
                $table->windowConfigure("$row,$col", -window => '');
            }
        }
    };

    # Function to adjust column widths
    my $adjust_column_widths = sub {
        my $cols = $table->cget('-cols');
        for my $col (0 .. $cols - 1) {
            my $max_width = 0;
            for my $row (0 .. $table->cget('-rows') - 1) {
                my $cell_value = $table->get("$row,$col");
                my $cell_width = length($cell_value);
                $max_width = $cell_width if $cell_width > $max_width;
            }
            $table->colWidth($col, $max_width + 2);  # Add some padding
        }
    };

    # Function to populate table with data
    my $populate_table = sub {
        my ($data_ref, $page) = @_;
        $clear_table->();  # Limpiar la tabla antes de mostrar nuevos datos

        my @header_fields = (@{$data_ref->[0]}, 'Seleccionar');
        my @data_rows = @{$data_ref}[1 .. $#$data_ref];

        # Actualizar el número de columnas
        $table->configure(-cols => scalar(@header_fields));

        # Create header row
        for my $col (0 .. $#header_fields) {
            $table->set("0,$col", $header_fields[$col]);
        }

        my $start_index = ($page - 1) * $records_per_page;
        my $end_index = $start_index + $records_per_page - 1;
        $end_index = $#data_rows if $end_index > $#data_rows;

        my $row = 1;
        for my $i ($start_index .. $end_index) {
            my $data_row = $data_rows[$i];
            my $col = 0;
            foreach my $value (@$data_row) {
                $table->set("$row,$col", $value);
                $col++;
            }
            my $checkbutton_var = 1;
            #if ($data_ref == $data_secundaria_ref) {
            #    $checkbutton_var = 0;
            #}
            $table->windowConfigure("$row,$col", -window => $frame->Checkbutton(
                -variable => \$checkbutton_var,
                -background => $herramientas::Estilos::checkbutton_bg,
                -activebackground => $herramientas::Estilos::checkbutton_active_bg,
                -foreground => $herramientas::Estilos::checkbutton_active_fg,
                -activeforeground => $herramientas::Estilos::checkbutton_fg,
                -selectcolor => $herramientas::Estilos::table_header_bg,
                -font => $herramientas::Estilos::checkbutton_font,
                -command => sub {
                    if ($checkbutton_var) {
                        if ($data_ref == $data_principal_ref) {
                            $selected_principal{$data_row->[0]} = { map { $header_fields[$_] => $data_row->[$_] } (1 .. $#header_fields - 1) };
                        } else {
                            $selected_secundaria{$data_row->[0]} = { map { $header_fields[$_] => $data_row->[$_] } (1 .. $#header_fields - 1) };
                        }
                    } else {
                        if ($data_ref == $data_principal_ref) {
                            delete $selected_principal{$data_row->[0]};
                        } else {
                            delete $selected_secundaria{$data_row->[0]};
                        }
                    }
                }
            ));
            if ($checkbutton_var) {
                if ($data_ref == $data_principal_ref) {
                    $selected_principal{$data_row->[0]} = { map { $header_fields[$_] => $data_row->[$_] } (1 .. $#header_fields - 1) };
                } else {
                    $selected_secundaria{$data_row->[0]} = { map { $header_fields[$_] => $data_row->[$_] } (1 .. $#header_fields - 1) };
                }
            }
            $row++;
        }

        $adjust_column_widths->();  # Adjust column widths after populating the table
    };

    # Create buttons to switch data
    my $button_frame = $mv->Frame()->pack(-side => 'bottom', -fill => 'x');
    $button_frame->Button(
        -text => 'Data Principal',
        -command => sub {
            $current_data_ref = $data_principal_ref;
            $current_page = 1;
            $populate_table->($current_data_ref, $current_page);
        },
        -background => $herramientas::Estilos::nav_button_bg,
        -foreground => $herramientas::Estilos::nav_button_fg,
        -activebackground => $herramientas::Estilos::nav_button_active_bg,
        -activeforeground => $herramientas::Estilos::nav_button_active_fg,
        -font => $herramientas::Estilos::nav_button_font
    )->pack(-side => 'left', -padx => 10, -pady => 10);

    $button_frame->Button(
        -text => "Anterior",
        -command => sub {
            if ($current_page > 1) {
                $current_page--;
                $populate_table->($current_data_ref, $current_page);
            }
        },
        -background => $herramientas::Estilos::mib_selection_button_bg,
        -foreground => $herramientas::Estilos::mib_selection_button_fg,
        -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
        -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
        -font => $herramientas::Estilos::mib_selection_button_font
    )->pack(-side => 'left', -padx => 10, -pady => 10);

    $button_frame->Button(
        -text => "Siguiente",
        -command => sub {
            my $total_pages = int((scalar(@{$current_data_ref}) - 2) / $records_per_page) + 1;
            if ($current_page < $total_pages) {
                $current_page++;
                $populate_table->($current_data_ref, $current_page);
            }
        },
        -background => $herramientas::Estilos::mib_selection_button_bg,
        -foreground => $herramientas::Estilos::mib_selection_button_fg,
        -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
        -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
        -font => $herramientas::Estilos::mib_selection_button_font
    )->pack(-side => 'left', -padx => 10, -pady => 10);

    $button_frame->Button(
        -text => 'Data Secundaria',
        -command => sub {
            $current_data_ref = $data_secundaria_ref;
            $current_page = 1;
            $populate_table->($current_data_ref, $current_page);
        },
        -background => $herramientas::Estilos::nav_button_bg,
        -foreground => $herramientas::Estilos::nav_button_fg,
        -activebackground => $herramientas::Estilos::nav_button_active_bg,
        -activeforeground => $herramientas::Estilos::nav_button_active_fg,
        -font => $herramientas::Estilos::nav_button_font
    )->pack(-side => 'right', -padx => 10, -pady => 10);

    # Create search entry and button
    my $search_frame = $mv->Frame(-background => $herramientas::Estilos::mib_selection_bg)->pack(-side => 'top', -fill => 'x');
    my $search_entry = $search_frame->Entry(-font => $herramientas::Estilos::input_font)->pack(-side => 'left', -fill => 'x', -expand => 1, -padx => 10, -pady => 10);
    $search_frame->Button(
        -text => "Buscar",
        -command => sub {
            my $search_term = $search_entry->get();
            search_and_display_results($mv, $data_principal_ref, $data_secundaria_ref, $search_term, $records_per_page);
        },
        -background => $herramientas::Estilos::mib_selection_button_bg,
        -foreground => $herramientas::Estilos::mib_selection_button_fg,
        -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
        -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
        -font => $herramientas::Estilos::mib_selection_button_font
    )->pack(-side => 'right', -padx => 10, -pady => 10);

    # Create save button
    $button_frame->Button(
        -text => 'Guardar',
        -command => sub {
            $selected_data_principal = \%selected_principal;
            $selected_data_secundaria = \%selected_secundaria;
            # Advetir si no se ha seleccionado ningún dato
            if (!%$selected_data_principal && !%$selected_data_secundaria) {
                show_alert($mv, 'Error', 'No se ha seleccionado ningún dato', 'error');
                return;
            }
            # Confirmar si se desea guardar los datos seleccionados
            my $response = show_alert($mv, 'Confirmar', 'Desea guardar los datos seleccionados?', 'question');
            if ($response) {
                show_alert($mv, 'Guardado', 'Datos guardados con exito', 'success');
                # Cerrar la ventana después de guardar los datos
                $mv->destroy();
                return ($selected_data_principal, $selected_data_secundaria);
            }
        },
        -background => $herramientas::Estilos::save_button_bg,
        -foreground => $herramientas::Estilos::save_button_fg,
        -activebackground => $herramientas::Estilos::save_button_active_bg,
        -activeforeground => $herramientas::Estilos::save_button_active_fg,
        -font => $herramientas::Estilos::save_button_font
    )->pack(-side => 'bottom', -padx => 10, -pady => 10);

    # Populate table with initial data
    $populate_table->($data_principal_ref, 1);

    # Esperar a que la ventana sea destruida antes de retornar los datos seleccionados
    $mv->waitWindow();
    return ($selected_data_principal, $selected_data_secundaria);

}

# Function to search and display results
sub search_and_display_results {
    my ($parent, $data_principal_ref, $data_secundaria_ref, $search_term, $records_per_page) = @_;

    my $results_window = create_top_level_window($parent, 'Resultados de la Búsqueda', 'maximizada');

    my $frame = $results_window->Frame(-background => $herramientas::Estilos::table_fg)->pack(-side => 'top', -fill => 'both', -expand => 1);
    my $scrolled_table = $frame->Scrolled(
        'TableMatrix',
        -rows => $records_per_page + 1,  # +1 for header row
        -cols => 0,  # Se actualizará dinámicamente
        -cache => 1,
        -scrollbars => 'osoe',  # 'osoe' means both horizontal and vertical scrollbars
        -background => $herramientas::Estilos::pine_green,
        -foreground => $herramientas::Estilos::table_fg,
        -font => $herramientas::Estilos::table_font,
    )->pack(-side => 'top', -fill => 'both', -expand => 1);

    my $table = $scrolled_table->Subwidget('scrolled');

    # Function to clear the table
    my $clear_table = sub {
        my $rows = $table->cget('-rows');
        my $cols = $table->cget('-cols');
        for my $row (1 .. $rows - 1) {
            for my $col (0 .. $cols - 1) {
                $table->set("$row,$col", '');
            }
        }
    };

    # Function to adjust column widths
    my $adjust_column_widths = sub {
        my $cols = $table->cget('-cols');
        for my $col (0 .. $cols - 1) {
            my $max_width = 0;
            for my $row (0 .. $table->cget('-rows') - 1) {
                my $cell_value = $table->get("$row,$col");
                my $cell_width = length($cell_value);
                $max_width = $cell_width if $cell_width > $max_width;
            }
            $table->colWidth($col, $max_width + 2);  # Add some padding
        }
    };

    # Function to populate table with search results
    my $populate_search_results = sub {
        my ($filtered_data) = @_;

        $clear_table->();  # Limpiar la tabla antes de mostrar nuevos datos

        my @header_fields = @{$filtered_data->[0]};
        my @data_rows = @{$filtered_data}[1 .. $#$filtered_data];

        # Actualizar el número de columnasvcw
        $table->configure(-cols => scalar(@header_fields));

        # Create header row
        for my $col (0 .. $#header_fields) {
            $table->set("0,$col", $header_fields[$col]);
        }

        my $row = 1;
        foreach my $data_row (@data_rows) {
            my $col = 0;
            foreach my $value (@$data_row) {
                $table->set("$row,$col", $value);
                $col++;
            }
            $row++;
            last if $row > $records_per_page;
        }

        $adjust_column_widths->();  # Adjust column widths after populating the table
    };

    # Filter data based on search term
    my @filtered_data_principal = grep { join(' ', @$_) =~ /\Q$search_term\E/i } @$data_principal_ref;
    my @filtered_data_secundaria = grep { join(' ', @$_) =~ /\Q$search_term\E/i } @$data_secundaria_ref;

    # Populate table with search results
    if (@filtered_data_principal) {
        $populate_search_results->(\@filtered_data_principal);
    } elsif (@filtered_data_secundaria) {
        $populate_search_results->(\@filtered_data_secundaria);
    } else {
        $clear_table->();
    }
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

# Function to display a selection window for enterprise OIDs
sub mostrar_ventana_seleccion_empresa_oid {
    my ($ventana_principal, $enterprise_info) = @_;
    my $mw = $ventana_principal->Toplevel();
    $mw->title("Seleccionar Empresa OID");
    $mw->configure(-background => $herramientas::Estilos::twilight_grey);
    $mw->geometry('400x600');

    my $frame = $mw->Frame(-background => $herramientas::Estilos::twilight_grey)->pack(-side => 'top', -fill => 'both', -expand => 1);
    my $scroll = $frame->Scrolled('Pane', -scrollbars => 'osoe', -bg => $herramientas::Estilos::twilight_grey)->pack(-side => 'top', -fill => 'both', -expand => 1);

    my $selected_info;
    foreach my $oid (keys %$enterprise_info) {
        my $info = $enterprise_info->{$oid};
        my $card = $scroll->Frame(-background => $herramientas::Estilos::pine_green, -relief => 'raised', -borderwidth => 2)->pack(-side => 'top', -fill => 'x', -pady => 5, -padx => 5);
        
        foreach my $key (keys %$info) {
            $card->Label(
                -text => "$key: $info->{$key}",
                -background => $herramientas::Estilos::pine_green,
                -foreground => $herramientas::Estilos::fg_color,
                -font => $herramientas::Estilos::label_font
            )->pack(-side => 'top', -anchor => 'w');
        }
        
        $card->Button(
            -text => "Elegir",
            -command => sub {
                $selected_info = $info;
                $mw->destroy;
            },
            -background => $herramientas::Estilos::next_button_bg,
            -foreground => $herramientas::Estilos::next_button_fg,
            -activebackground => $herramientas::Estilos::next_button_active_bg,
            -activeforeground => $herramientas::Estilos::next_button_active_fg,
            -font => $herramientas::Estilos::next_button_font
        )->pack(-side => 'bottom', -pady => 10);
    }

    $mw->waitWindow;
    return $selected_info;
}


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

# Funcion para abrir y escribir en un archivo logs las imprimesiones de consola
# Subrutina para imprimir información en un archivo de log
sub log_to_file {
    my ($data) = @_;
    my $timestamp = localtime();
    # Añadir un appender para el archivo de log
    $logger->add_appender(Log::Log4perl::Appender->new(
        "Log::Dispatch::File",
        filename => Rutas::temp_files_logs_objects_mibs_path() . "/impresiones_de_consola.logs",
        mode     => "append",
        layout   => Log::Log4perl::Layout::PatternLayout->new("%d %p %m %n"),
    ));

    $logger->info("--------------- Impresion $timestamp ---------------");
    
    # Imprimir la información en el archivo
    if (ref $data eq 'HASH') {
        $logger->info(Dumper($data));
    } elsif (ref $data eq 'ARRAY') {
        $logger->info(join("\n", @$data));
    } else {
        $logger->info($data);
    }



}


# Reemplazar el uso de print con log_to_file
sub print_logs {
    log_to_file(@_);
}
# Extraer informacion de un archivo

sub parse_file {
    my ($filename) = @_;
    my %ip_data;
    my $key;

    open my $fh, '<', $filename or die "Could not open file '$filename' $!";

    while (my $line = <$fh>) {
        chomp $line;
        if ($line =~ /^\s*$/) {
            $key = undef;
        } elsif (!defined $key) {
            $key = $line;
            $ip_data{$key} = [];
        } else {
            push @{$ip_data{$key}}, $line;
        }
    }

    close $fh;
    return \%ip_data;
}


1;  # Finalizar el módulo con un valor verdadero