package terminal::Create_terminal;

use strict;
use warnings;
use Tk;
use Tk::Pane;
use Tk::FileSelect;

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
use Validaciones;

use Data::Dumper; # Importar el modulo Data::Dumper
use Log::Log4perl qw(get_logger :levels);

# Initialize logger
Log::Log4perl->init(\<<'EOT');
log4perl.logger = DEBUG, Screen, File

log4perl.appender.Screen = Log::Log4perl::Appender::Screen
log4perl.appender.Screen.layout = Log::Log4perl::Layout::PatternLayout
log4perl.appender.Screen.layout.ConversionPattern = %d %p %m %n

log4perl.appender.File = Log::Log4perl::Appender::File
log4perl.appender.File.filename = terminal.log
log4perl.appender.File.layout = Log::Log4perl::Layout::PatternLayout
log4perl.appender.File.layout.ConversionPattern = %d %p %m %n
EOT

my $logger = get_logger();

# Function to create a scrollable terminal window
sub create_terminal_window {
    my ($data, $commands_ref, $titulo) = @_;

    eval {
        $logger->info("Creating terminal window with title: $titulo");

        $data ||= '';
        $commands_ref ||= ['cd herramientas\Archivos_temporales\Agentes_temporales\agente_snmp', 'dir'];
        $titulo ||= 'Generic';

        my $mw = herramientas::Complementos::create_main_window('Terminal', 'maximizada', 1, 1, $titulo, 'Titulo-Principal');
        my $frame = $mw->Frame()->pack(-expand => 1, -fill => 'both');
        my $scroll_pane = $frame->Scrolled('Pane', -scrollbars => 'osoe', -sticky => 'nsew')->pack(-expand => 1, -fill => 'both');
        my $text_widget = $scroll_pane->Text(
            -wrap => 'none',
            -background => $herramientas::Estilos::bg_color_snmp,
            -foreground => $herramientas::Estilos::fg_color_snmp
        )->pack(-expand => 1, -fill => 'both');
        my $entry_frame = $frame->Frame()->pack(-fill => 'x');
        my $entry_widget = $entry_frame->Entry(
            -background => $herramientas::Estilos::entry_bg_color_snmp,
            -foreground => $herramientas::Estilos::entry_fg_color_snmp,
            -font => $herramientas::Estilos::entry_font_snmp
        )->pack(-side => 'left', -fill => 'x', -expand => 1);
        my $execute_button = $entry_frame->Button(
            -text => 'Execute',
            -command => sub { execute_entry_command($entry_widget, $text_widget) },
            -background => $herramientas::Estilos::button_color_snmp,
            -foreground => $herramientas::Estilos::fg_button_color_snmp,
            -font => $herramientas::Estilos::button_font_snmp
        )->pack(-side => 'right');

        # Quick actions header
        my $quick_actions_frame = $mw->Frame()->pack(-fill => 'x');
        my $quick_actions_scroll = $quick_actions_frame->Scrolled('Frame', -scrollbars => 'x', -height => 50)->pack(-fill => 'x');
        my $execute_local_button = $quick_actions_scroll->Button(
            -text => 'Ejecutar Agente Local',
            -command => sub { execute_local_agent($text_widget) },
            -background => $herramientas::Estilos::button_color_snmp,
            -foreground => $herramientas::Estilos::fg_button_color_snmp,
            -font => $herramientas::Estilos::button_font_snmp
        )->pack(-side => 'left', -padx => 5);
        my $change_dir_button = $quick_actions_scroll->Button(
            -text => 'Cambiar Directorio de Ejecución',
            -command => sub { change_execution_directory($mw, $text_widget) },
            -background => $herramientas::Estilos::button_color_snmp,
            -foreground => $herramientas::Estilos::fg_button_color_snmp,
            -font => $herramientas::Estilos::button_font_snmp
        )->pack(-side => 'left', -padx => 5);

        # Execute initial commands
        foreach my $command (@$commands_ref) {
            my $output = execute_command($command);
            $text_widget->insert('end', "$output\n");
        }

        # Bind Enter key to execute command from entry widget
        $entry_widget->bind('<Return>' => sub {
            execute_entry_command($entry_widget, $text_widget);
        });

        MainLoop();
    };
    if ($@) {
        $logger->error("Error in create_terminal_window: $@");
        die "Error al crear la ventana de terminal: $@";
    }
}

# Function to execute a command and return its output
sub execute_command {
    my ($command) = @_;
    $logger->info("Executing command: $command");

    my $output = `$command 2>&1`;  # Capture both stdout and stderr
    if ($?) {
        $logger->error("Command failed: $command");
        die "Error al ejecutar el comando: $command";
    }

    return $output;
}

# Function to execute command from entry widget and display output
sub execute_entry_command {
    my ($entry_widget, $text_widget) = @_;
    my $command = $entry_widget->get();
    $entry_widget->delete(0, 'end');
    eval {
        my $output = execute_command($command);
        $text_widget->insert('end', "$output\n");
    };
    if ($@) {
        $logger->error("Error executing command from entry: $@");
        $text_widget->insert('end', "Error: $@\n");
    }
}

# Function to execute local agent
sub execute_local_agent {
    my ($text_widget) = @_;
    my $command = 'path_to_local_agent_executable';  # Replace with actual command
    eval {
        my $output = execute_command($command);
        $text_widget->insert('end', "$output\n");
    };
    if ($@) {
        $logger->error("Error executing local agent: $@");
        $text_widget->insert('end', "Error: $@\n");
    }
}

# Function to change execution directory
sub change_execution_directory {
    my ($parent, $text_widget) = @_;
    my $dir = $parent->chooseDirectory(
        -initialdir => '.', 
        -title => 'Selecciona un directorio'
    );
    if ($dir) {
        chdir $dir or do {
            $logger->error("Failed to change directory to $dir: $!");
            $text_widget->insert('end', "Error: Failed to change directory to $dir: $!\n");
            return;
        };
        $logger->info("Changed execution directory to $dir");
        $text_widget->insert('end', "Changed execution directory to $dir\n");
        # Ejecutar el comando 'dir' para listar el contenido del directorio esperando un segundo
        my $output = execute_command("dir");
        $text_widget->insert('end', "$output\n");
    }

}

1;