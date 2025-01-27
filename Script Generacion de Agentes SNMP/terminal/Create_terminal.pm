package terminal::Create_terminal;

use strict;
use warnings;
use Tk;
use Tk::Text;
use Tk::Pane;
use Tk::FileSelect;

use IPC::Run qw(run start finish);
use Proc::Background;

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
            -command => sub { execute_local_agent($text_widget, $mw) },
            -background => $herramientas::Estilos::button_color_snmp,
            -foreground => $herramientas::Estilos::fg_button_color_snmp,
            -font => $herramientas::Estilos::button_font_snmp
        )->pack(-side => 'left', -padx => 5);
        my $create_alarm_example = $quick_actions_scroll->Button(
            -text => 'Crear ejemplo de alarma',
            -command => sub { create_alarm_example($mw, $text_widget) },
            -background => $herramientas::Estilos::button_color_snmp,
            -foreground => $herramientas::Estilos::fg_button_color_snmp,
            -font => $herramientas::Estilos::button_font_snmp
        )->pack(-side => 'left', -padx => 5);

        my $change_dir_button = $quick_actions_scroll->Button(
            -text => 'Cambiar Directorio de Ejecucion',
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

# Function to create an example alarm
sub create_alarm_example {
    my ($parent, $text_widget) = @_;
    
    eval {
        # Obtener el directorio actual
        my $current_dir = Cwd::getcwd();
        $logger->info("Current directory: $current_dir");

        # Leer el archivo AGENT.properties para obtener el nombre del agente
        open my $fh, '<', 'AGENT.properties' or die "Cannot open AGENT.properties: $!";
        my $agent_name;
        my $agent_host;
        my $agent_port;

        while (my $line = <$fh>) {
            if ($line =~ /^agt:=(\S+)/) {
                $agent_name = $1;
            } elsif ($line =~ /^host:=(\S+)/) {
                $agent_host = $1;
            } elsif ($line =~ /^port:=(\S+)/) {
                $agent_port = $1;
            }
        }
        print "Agent properties:\n";
        print "-----------------\n";
        print "Name: $agent_name\n";
        print "Host: $agent_host\n";
        print "Port: $agent_port\n";

        close $fh;
        die "Agent name not found in AGENT.properties" unless $agent_name;
        $logger->info("Agent name: $agent_name");

        # Leer el archivo del agente en la carpeta ABR
        my $agent_file = "ABR/$agent_name.pm";
        open my $afh, '<', $agent_file or die "Cannot open $agent_file: $!";
        my %alarms;
        my $current_alarm;
        while (my $line = <$afh>) {
            if ($line =~ /^# (\S+)/) {
                $current_alarm = $1;
            } elsif ($line =~ /^sub (_\S+)/) {
                my $oid = $1;
                $oid =~ s/_/./g;
                $alarms{$current_alarm}{oid} = $oid;
            } elsif ($line =~ /entrada->\{"(\S+)"\}/) {
                my $entry = $1;
                push @{$alarms{$current_alarm}{entries}}, $entry;
                my $data_text = $line;
                # Extraer data_text de la línea
                if ($data_text =~ /\$dat_additional_text \.= "\\n(.*)=/) {
                    my $description = $1;
                    $description =~ s/^\s+|\s+$//g;  # Trim leading and trailing whitespace
                    $description = "No data text found" unless $description;
                    push @{$alarms{$current_alarm}{entry_descriptions}{$entry}}, $description;
                }
            } 
        }
        close $afh;
        # Eliminar entradas duplicadas y registros innecesarios
        foreach my $alarm (keys %alarms) {
        # Remove 'IPADDR' and duplicates from entries
        my %seen;
        @{$alarms{$alarm}{entries}} = grep { $_ ne 'IPADDR' && !$seen{$_}++ } @{$alarms{$alarm}{entries}};
        # Eliminar el primer punto del oid .1.3.6.1.4.1.193.183.4.2.0.10  a 1.3.6.1.4.1.193.183.4.2.0.10
        $alarms{$alarm}{oid} =~ s/^\.//;

        # Remove duplicates from entry_descriptions
        foreach my $entry (keys %{$alarms{$alarm}{entry_descriptions}}) {
            my %desc_seen;
            @{$alarms{$alarm}{entry_descriptions}{$entry}} = grep { !$desc_seen{$_}++ } @{$alarms{$alarm}{entry_descriptions}{$entry}};
            }
        }

        
        foreach my $alarm (keys %alarms) {
            my $oid = $alarms{$alarm}{oid};
            my $base_command = "snmptrap -v 2c -c public $agent_host:$agent_port 0 $oid";
            my $commands = "";

            foreach my $entry (@{$alarms{$alarm}{entries}}) {
                my $entry_oid = $entry;
                my $entry_description = $alarms{$alarm}{entry_descriptions}{$entry}[0] // 'No description';
                $commands .= " $entry_oid s \"valor $entry_description\"";
            }

            my $final_command = "$base_command $commands";
            print "$final_command\n";
        }


    };
    if ($@) {
        $logger->error("Error in create_alarm_example: $@");
        $text_widget->insert('end', "Error: $@\n");
        $text_widget->see('end');
    }
}
# Function to execute local agent
sub execute_local_agent {
    my ($text_widget, $mw) = @_;  # Corrected parameter order
    my $command = 'perl agente_agente_snmp.pl';  # Reemplaza con la ruta real del script del agente

    # Verificar que $text_widget es un widget de texto
    if (!$text_widget->isa('Tk::Text')) {
        die "Error: \$text_widget no es un widget de texto valido";
    }
    eval {

        $text_widget->insert('end', "Ejecutando agente:\n");
        $text_widget->see('end');

        # Ejecutar el script en un subproceso
        my $process = Proc::Background->new("perl", 'agente_agente_snmp.pl');
        my $pid = $process->pid;

        # Actualizar el log
        $logger->info("Agente ejecutado con PID: $pid");

        # Mostrar el PID al usuario
        $text_widget->insert('end', "Agente ejecutado con éxito (PID: $pid).\n");
        $text_widget->see('end');

        # Opcional: Botón para detener el proceso
        my $stop_button = $mw->Button(
            -text => "Detener Agente",
            -command => sub {
                $process->terminate(); # Terminar el proceso
                $text_widget->insert('end', "Agente detenido (PID: $pid).\n");
                $text_widget->see('end');
                $logger->info("Agente detenido (PID: $pid)");
            },
            -background => $herramientas::Estilos::button_color_snmp,
            -foreground => $herramientas::Estilos::fg_button_color_snmp,
            -font => $herramientas::Estilos::button_font_snmp
        )->pack(-side => 'left', -padx => 5);
    };
    if ($@) {
        $logger->error("Error ejecutando el agente local: $@");
        $text_widget->insert('end', "Error ejecutando el agente local: $@\n");
        $text_widget->see('end');
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