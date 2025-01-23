package terminal::terminal;


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

# Function to create a scrollable terminal window
sub create_terminal_window {
    my ($data, $commando, $titulo) = @_;

    if (!$data) {
        $data = '';
    }
    if (!$commando) {
        $commando = '';
    }
    if (!$titulo) {
        $titulo = 'Generic';
    }


    my $mw = herramientas::Complementos::create_main_window('Terminal '$titulo , 'maximizada', 1 , 1 , $titulo, 'Titulo-Principal');


    my $frame = $mw->Frame()->pack(-expand => 1, -fill => 'both');
    my $scroll_pane = $frame->Scrolled('Pane', -scrollbars => 'osoe', -sticky => 'nsew')->pack(-expand => 1, -fill => 'both');
    my $text_widget = $scroll_pane->Text(-wrap => 'none')->pack(-expand => 1, -fill => 'both');

    # Redirect STDOUT and STDERR to the text widget
    open my $oldout, ">&STDOUT";
    open my $olderr, ">&STDERR";
    open STDOUT, '>', \$text_widget;
    open STDERR, '>', \$text_widget;

    # Function to execute a command and display the output
    sub execute_command {
        my ($command) = @_;
        eval {
            my $output = `$command 2>&1`;
            $text_widget->insert('end', $output);
            $text_widget->see('end');
        };
        if ($@) {
            $text_widget->insert('end', "Error executing command: $@\n");
            $text_widget->see('end');
        }
    }

    # Example usage: execute a command
    execute_command('echo Hello, World!');

    MainLoop;

    # Restore STDOUT and STDERR
    open STDOUT, ">&", $oldout;
    open STDERR, ">&", $olderr;
}


