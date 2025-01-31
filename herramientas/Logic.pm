package Logic;

use strict;
use warnings;

# Añadir la carpeta donde se encuentran los módulos
use lib $FindBin::Bin . "/herramientas";
use lib $FindBin::Bin . "./Script Generacion de Agentes SNMP/utilidades";

# Ventanas secundarias
use MIB_utils;

use Data::Dumper; # Importar el módulo Data::Dumper

use File::Path qw(make_path rmtree);
use File::Spec;
use File::Basename;

use FindBin;

use Data::Dumper;

use Toolbar;
use Estilos;
use Complementos;
use Rutas;

# Function to create the directory tree and files
sub crear_arbol_directorio {
    my ($parent, $ruta_principal, $nombre_agente) = @_;

    my $ruta_agente = File::Spec->catdir($ruta_principal, $nombre_agente);

    if (-d $ruta_agente) {
        my $response = _handle_existing_agent($parent, $nombre_agente, $ruta_agente);
        return 0 unless $response;
    }

    my @directorios = _get_directories($ruta_agente, $nombre_agente);
    _create_directories(@directorios);

    _create_files($ruta_agente, $nombre_agente);
    _create_conf_files($ruta_agente, $nombre_agente);
    _create_abr_files($ruta_agente, $nombre_agente);

    return 1;
}

# Handle existing agent directory
sub _handle_existing_agent {
    my ($parent, $nombre_agente, $ruta_agente) = @_;
    my $title = "Agente Existente";
    my $message = "El agente '$nombre_agente' ya existe.¿Desea reemplazarlo?";
    my $type = 'question';

    my $response = herramientas::Complementos::create_alert_with_picture_label_and_button($parent, $title, $message, $type);
    if ($response) {
        eval { rmtree($ruta_agente); };
        die "Error al eliminar el directorio existente en la función _handle_existing_agent: $@" if $@;
    }
    return $response;
}

# Get directories to create
sub _get_directories {
    my ($ruta_agente, $nombre_agente) = @_;
    return (
        $ruta_agente,
        File::Spec->catdir($ruta_agente, 'CONF'),
        File::Spec->catdir($ruta_agente, 'ABR'),
        File::Spec->catdir($ruta_agente, "${nombre_agente}TrapAlarm")
    );
}

# Create directories
sub _create_directories {
    my @directorios = @_;
    eval { make_path(@directorios); };
    die "Error al crear directorios en la función _create_directories: $@" if $@;
}

# Create root files for the agent
sub _create_files {
    my ($ruta_agente, $nombre_agente) = @_;
    my $archivo_agente = File::Spec->catfile($ruta_agente, "agente_$nombre_agente.pl");
    my $archivo_properties = File::Spec->catfile($ruta_agente, "AGENT.properties");

    eval {
        open my $fh, '>', $archivo_agente or die "Error al crear $archivo_agente: $!";
        close $fh;
        open $fh, '>', $archivo_properties or die "Error al crear $archivo_properties: $!";
        close $fh;
    };
    die "Error al crear archivos en la función _create_files: $@" if $@;
}

# Create files in the CONF directory
sub _create_conf_files {
    my ($ruta_agente, $nombre_agente) = @_;
    my @archivos_conf = qw(
        FB_AGENTE FB_all FC_PrependAdditionalText FC_SetEventSeverity
        FC_SetGrupos FC_SetIncidentType FC_SetIncidentType_NonCascade
        FC_SetUserText MAP_ExampleExternal MAP_HostName
    );

    foreach my $archivo (@archivos_conf) {
        my $ruta_archivo = File::Spec->catfile($ruta_agente, 'CONF', $archivo);
        eval {
            open my $fh, '>', $ruta_archivo or die "Error al crear $ruta_archivo: $!";
            close $fh;
        };
        die "Error al crear archivos en la carpeta CONF en la función _create_conf_files: $@" if $@;
    }
}

# Create files in the ABR directory
sub _create_abr_files {
    my ($ruta_agente, $nombre_agente) = @_;
    my @archivos_abr = (
        "${nombre_agente}TrapAlarm", "CONFIGURATOR.pm", "CorrectiveFilter.pm", "HashOrder.pm", "${nombre_agente}.pm",
        "FILE_HANDLER.pm", "llenaComun.pm", "MICROTIME.pm", "Parser_aux.pm",
        "SNMPAgente.pm", "TapFilter.pm"
    );

    foreach my $archivo (@archivos_abr) {
        my $ruta_archivo = File::Spec->catfile($ruta_agente, 'ABR', $archivo);
        eval {
            open my $fh, '>', $ruta_archivo or die "Error al crear $ruta_archivo: $!";
            close $fh;
        };
        die "Error al crear archivos en la carpeta ABR en la función _create_abr_files: $@" if $@;
    }
}

# Función para crear un archivo con terminaciones de línea UNIX (LF)
sub crear_archivo_unix {
    my $nombre_archivo = 'archivo_unix.txt';
    # Ejemplo de uso
    my @contenido = (
        "Esta es la primera línea.",
        "Esta es la segunda línea.",
        "Esta es la tercera línea."
    );
    # Abre el archivo en modo de escritura
    open(my $fh, '>', $nombre_archivo) or die "No se pudo abrir el archivo '$nombre_archivo' $!";

    # Escribe el contenido en el archivo con terminaciones de línea UNIX (LF)
    foreach my $linea (@contenido) {
        print $fh $linea . "\n";
    }
    # Cierra el archivo
    close($fh);
    print "Archivo '$nombre_archivo' creado con éxito.\n";
}


# Function to transform DOS file to UNIX format
sub transformar_archivos_unix {
    my ($parent, $ruta_agente, $agente, $archivo) = @_;

    my $nombre_archivo = 'archivo_unix.txt';
    # Ejemplo de uso
    my @contenido = (
        "Esta es la primera línea.",
        "Esta es la segunda línea.",
        "Esta es la tercera línea."
    );
    # Abre el archivo en modo de escritura
    open(my $fh, '>', $nombre_archivo) or die "No se pudo abrir el archivo '$nombre_archivo' $!";

    # Escribe el contenido en el archivo con terminaciones de línea UNIX (LF)
    foreach my $linea (@contenido) {
        print $fh $linea . "\n";
    }
    # Cierra el archivo
    close($fh);
    print "Archivo '$nombre_archivo' creado con éxito.\n";


    my $ruta_agente_completa = File::Spec->catfile($ruta_agente, $agente);
    # Validar si el nombre del agente se repite en la ruta completa
    if ($ruta_agente_completa =~ /$agente.*$agente/) {
        $ruta_agente_completa =~ s/\\$agente//;
    }

    # Validate that the directory and file exist
    unless ($ruta_agente_completa && -d $ruta_agente_completa) {
        herramientas::Complementos::show_alert($parent, 'Advertencia', "No se selecciono una empresa", 'warning');
        return;
    }

    my $ruta_archivo = File::Spec->catfile($ruta_agente_completa, $archivo);
    unless (-e $ruta_archivo) {
        herramientas::Complementos::show_alert($parent, 'ERROR', "El archivo no existe: $ruta_archivo", 'error');
        return;
    }

    # Transform the file to UNIX format
    eval {
        open my $in, '<', $ruta_archivo or die "Error al abrir $ruta_archivo: $!";
        my @lines = <$in>;
        close $in;

        my $original_format = 'UNIX (LF)';
        foreach my $line (@lines) {
            if ($line =~ /\r\n$/) {
                $original_format = 'Windows (CR LF)';
                last;
            } elsif ($line =~ /\r$/) {
                $original_format = 'Mac (CR)';
                last;
            }
        }

        open my $out, '>', $ruta_archivo or die "Error al abrir $ruta_archivo para escritura: $!";
        foreach my $line (@lines) {
            $line =~ s/\r\n/\n/g;  # Replace DOS line endings with UNIX line endings
            $line =~ s/\r/\n/g;    # Replace Mac line endings with UNIX line endings
            print $out $line;
        }
        close $out;

        # Verify the conversion
        open my $verify, '<', $ruta_archivo or die "Error al abrir $ruta_archivo para verificacion: $!";
        my $converted_format = 'UNIX (LF)';
        while (my $line = <$verify>) {
            if ($line =~ /\r\n$/) {
                $converted_format = 'Windows (CR LF)';
                last;
            } elsif ($line =~ /\r$/) {
                $converted_format = 'Mac (CR)';
                last;
            }
        }
        close $verify;

        if ($converted_format ne 'UNIX (LF)') {
            die "La conversion no fue exitosa. El archivo sigue en formato: $converted_format";
        }

        herramientas::Complementos::show_alert($parent, 'INFO', "El archivo estaba originalmente en formato: $original_format", 'info');
    };
    if ($@) {
        herramientas::Complementos::show_alert($parent, 'ERROR', "Error al transformar el archivo: $@", 'error');
        return;
    }

    herramientas::Complementos::show_alert($parent, 'EXITO', "Se creo correctamente el archivo $archivo", 'success');
}

# Function to create a new UNIX format file
sub crear_archivo_unix {
    my ($parent, $ruta_agente, $agente, $archivo) = @_;

    my $ruta_agente_completa = File::Spec->catfile($ruta_agente, $agente);
    # Validar si el nombre del agente se repite en la ruta completa
    if ($ruta_agente_completa =~ /$agente.*$agente/) {
        $ruta_agente_completa =~ s/\\$agente//;
    }

    # Validate that the directory exists
    unless ($ruta_agente_completa && -d $ruta_agente_completa) {
        herramientas::Complementos::show_alert($parent, 'Advertencia', "No se selecciono una empresa", 'warning');
        return;
    }

    my $ruta_archivo = File::Spec->catfile($ruta_agente_completa, $archivo);
    unless (-e $ruta_archivo) {
        herramientas::Complementos::show_alert($parent, 'ERROR', "El archivo no existe: $ruta_archivo", 'error');
        return;
    }

    # Create a new file in UNIX format
    eval {
        open my $in, '<', $ruta_archivo or die "Error al abrir $ruta_archivo: $!";
        my @lines = <$in>;
        close $in;

        my $nuevo_archivo = $ruta_archivo . "_unix";
        open my $out, '>', $nuevo_archivo or die "Error al abrir $nuevo_archivo para escritura: $!";
        foreach my $line (@lines) {
            $line =~ s/\r\n/\n/g;  # Replace DOS line endings with UNIX line endings
            $line =~ s/\r/\n/g;    # Replace Mac line endings with UNIX line endings
            print $out $line;
        }
        close $out;

        # Validate the new file format
        open my $validate, '<', $nuevo_archivo or die "Error al abrir $nuevo_archivo para validación: $!";
        my $is_unix_format = 1;
        while (my $line = <$validate>) {
            if ($line =~ /\r/ || $line =~ /\r\n/) {
                $is_unix_format = 0;
                last;
            }
        }
        close $validate;

        if ($is_unix_format) {
            herramientas::Complementos::show_alert($parent, 'EXITO', "Se creo correctamente el archivo $nuevo_archivo en formato UNIX", 'success');
        } else {
            herramientas::Complementos::show_alert($parent, 'ERROR', "El archivo $nuevo_archivo no está en formato UNIX", 'error');
        }
    };
    if ($@) {
        herramientas::Complementos::show_alert($parent, 'ERROR', "Error al crear el archivo: $@", 'error');
        return;
    }
}

# Function to destroy the last child if it contains the property -scrollbars => 'osoe'
sub destruir_ultimo_hijo_con_scrollbars {
    my ($frame_personalizacion) = @_;
    foreach my $child ($frame_personalizacion->children) {
        if ($child->isa('Tk::Frame') && defined $child->cget('-scrollbars') && $child->cget('-scrollbars') eq 'osoe') {
            $child->destroy;
        }
    }
}

# Function to update the customization frame and return the field information
sub actualizar_frame_agent_properties {
    my ($ventana_principal, $frame_personalizacion, $modo, $agente, $ruta_agente) = @_;

    destruir_ultimo_hijo_con_scrollbars($frame_personalizacion);

    my $frame_agent_properties = $frame_personalizacion->Scrolled(
        'Frame',
        -scrollbars => 'osoe',
        -bg => $herramientas::Estilos::bg_color_snmp // 'white',
        -background => $herramientas::Estilos::scroll_bg_color_snmp // 'white',
        -foreground => $herramientas::Estilos::scroll_fg_color_snmp // 'black'
    )->pack(-pady => 20, -fill => 'both', -expand => 1);

    my @fields = _get_fields($modo, $agente);
    my %field_vars = _create_field_entries($frame_agent_properties, @fields);

    my $guardo_correctamente = 0;

    my $button_siguiente = $frame_agent_properties->Button(
        -text => 'Siguiente Paso',
        -bg => $herramientas::Estilos::next_button_bg,
        -fg => $herramientas::Estilos::next_button_fg,
        -activebackground => $herramientas::Estilos::next_button_active_bg,
        -activeforeground => $herramientas::Estilos::next_button_active_fg,
        -font => $herramientas::Estilos::next_button_font,
        -state => 'disabled',  # Initially disabled
        -command => sub { 
            # Pasar a la siguiente ventana MIBS
            utilidades::MIB_utils::Inicio_MIBS($agente, $ruta_agente), $ventana_principal->destroy(); # Llamar a la subrutina crear_agente_snmp - Destruir la ventana principal
        }
    )->pack(-side => 'left', -pady => 10);

    my $button_guardar = $frame_agent_properties->Button(
        -text => 'Guardar',
        -bg => $herramientas::Estilos::modern_button_bg,
        -fg => $herramientas::Estilos::modern_button_fg,
        -activebackground => $herramientas::Estilos::modern_button_active_bg,
        -activeforeground => $herramientas::Estilos::modern_button_active_fg,
        -font => $herramientas::Estilos::modern_button_font,
        -command => sub { 
            $guardo_correctamente = guardar_informacion($ventana_principal, \%field_vars, $agente, $ruta_agente, 'agent_properties'); 
            if ($guardo_correctamente) {
                $button_siguiente->configure(-state => 'normal');  # Enable the "Next Step" button
            }
        }
    )->pack(-side => 'right', -pady => 10);

    return \%field_vars;
}

# Get fields for the customization frame
sub _get_fields {
    my ($modo, $agente) = @_;
    my @fields = (
        { label => 'host', default => '' },
        { label => 'port', default => '' },
        { label => 'MIN_REREAD_FILE', default => 10 },
        { label => 'ALARM_PRINTS', default => 1 },
        { label => 'SOM_EOM', default => 'som_eom.abr' },
        { label => 'HOST', default => 'CONF/MAP_HostName' },
        { label => 'Severity', default => 'CONF/MAP_Severity' },
        { label => 'ExternalMap', default => "CONF/MAP_${agente}External" },
        { label => 'FB_AGENTE', default => 'CONF/FB_AGENTE' },
        { label => 'FB_all', default => 'CONF/FB_all' },
        { label => 'FC_PrependAdditionalText', default => 'CONF/FC_PrependAdditionalText' },
        { label => 'FC_SetEventSeverity', default => 'CONF/FC_SetEventSeverity' },
        { label => 'FC_SetGrupos', default => 'CONF/FC_SetGrupos' },
        { label => 'FC_SetIncidentType', default => 'CONF/FC_SetIncidentType' },
        { label => 'FC_SetIncidentType_NonCascade', default => 'CONF/FC_SetIncidentType_NonCascade' },
        { label => 'FC_SetUserText', default => 'CONF/FC_SetUserText' },
    );

    if ($modo eq 'local') {
        $fields[0]->{default} = 'localhost';
        $fields[1]->{default} = 12345;
        $fields[5]->{default} = "CONF/MAP_HostName";
        $fields[6]->{default} = "CONF/MAP_Severity";
    }

    return @fields;
}

# Create field entries in the customization frame
sub _create_field_entries {
    my ($frame_agent_properties, @fields) = @_;

    my $image_edit;
    eval {
        $image_edit = $frame_agent_properties->Photo(-file => Rutas::edit_image_path());  # Cargar la imagen desde la ruta
        1;
    } or do {
        my $error = $@ || 'Unknown error';
        die "Error al cargar la imagen en _create_field_entries: $error";
    };

    my %field_vars;
    my @active_fields = qw(
        MIN_REREAD_FILE SOM_EOM ExternalMap FB_AGENTE
        FB_all FC_PrependAdditionalText FC_SetEventSeverity FC_SetGrupos
        FC_SetIncidentType FC_SetIncidentType_NonCascade FC_SetUserText
    );

    foreach my $field (@fields) {
        my $frame_field = $frame_agent_properties->Frame(
            -bg => $herramientas::Estilos::bg_color_snmp // 'white'
        )->pack(-side => 'top', -fill => 'x', -padx => 5, -pady => 5);

        my $label = $frame_field->Label(
            -text => $field->{label},
            -bg => $herramientas::Estilos::bg_color_snmp // 'white',
            -fg => $herramientas::Estilos::fg_color_snmp // 'black',
            -font => $herramientas::Estilos::label_font_snmp // 'Arial 10'
        )->pack(-side => 'left');

        my $entry_var = $field->{default};
        $field_vars{$field->{label}} = \$entry_var;

        my $state_entry = (grep { $_ eq $field->{label} } @active_fields) ? 'disabled' : 'normal';

        my $entry = $frame_field->Entry(
            -bg => $herramientas::Estilos::entry_bg_color_snmp // 'white',
            -fg => $herramientas::Estilos::entry_fg_color_snmp // 'black',
            -font => $herramientas::Estilos::entry_font_snmp // 'Arial 10',
            -textvariable => \$entry_var,
            -state => $state_entry
        )->pack(-side => 'left', -padx => 5);

        my $button = $frame_field->Button(
            -image => $image_edit,
            -command => sub {
                if ($entry->cget('-state') eq 'disabled') {
                    $entry->configure(-state => 'normal');
                } else {
                    $entry->configure(-state => 'disabled');
                }
            }
        )->pack(-side => 'left', -padx => 5);

        my $checkbutton_var = (grep { $_ eq $field->{label} } @active_fields) ? 1 : 0;

        my $checkbutton_comment = $frame_field->Checkbutton(
            -text => 'comment',
            -bg => $herramientas::Estilos::bg_color_snmp // 'white',
            -fg => $herramientas::Estilos::fg_color_snmp // 'black',
            -font => $herramientas::Estilos::label_font_snmp // 'Arial 10',
            -variable => \$checkbutton_var
        )->pack(-side => 'right', -padx => 5);

        $field_vars{"comment_$field->{label}"} = \$checkbutton_var;
    }

    return %field_vars;
}

# Function to save the field information
sub guardar_informacion {
    my ($ventana_principal, $field_vars, $agente, $ruta_agente, $tipo) = @_;
    foreach my $key (keys %$field_vars) {
        if (${$field_vars->{$key}} eq '') {
            herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "Error: El campo '$key' no puede estar vacío.", 'error');
            return;
        }
    }
    # Aviso de se guardó la información
    herramientas::Complementos::show_alert($ventana_principal, 'info', "Se guardo la informacion correctamente", 'info');
    # Actualizar el archivo AGENT.properties
    if ($tipo eq 'agent_properties') {
        actualizar_archivo_properties($ventana_principal, $ruta_agente, $agente, $field_vars);
    }
}

# Function to update the AGENT.properties file
sub actualizar_archivo_properties {
    my ($ventana_principal, $ruta_agente, $nombre_agente, $field_vars) = @_;
    my $archivo_properties = File::Spec->catfile($ruta_agente, "AGENT.properties");
    # Check if the file exists
    unless (-e $archivo_properties) {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se pudo encontrar el archivo AGENT.properties en la ruta: $archivo_properties", 'error');
        return;
    }
    # Open the file for writing
    open my $fh, '>', $archivo_properties or die "Error al abrir $archivo_properties: $!";    
    # Write the formatted output
    print $fh "#############################################################################\n";
    print $fh "# --------------------------------MANDATORY---------------------------------\n";
    print $fh "#############################################################################\n";
    print $fh "# --- AGENT NAME\n";
    print $fh "agt:=$nombre_agente\n";
    print $fh "# --- WHERE THIS AGENT WILL LISTEN FOR TRAPS OR ALARMS\n";
    print_field($fh, $field_vars, 'host');
    print_field($fh, $field_vars, 'port');
    print $fh "# --- TIME TO CHECK AND UPDATE \"CONF/\" DIRECTORY FILES\n";
    print $fh "# --- TIME IN MINUTES\n";
    print_field($fh, $field_vars, 'MIN_REREAD_FILE');
    print $fh "# --- \"1\" to activate alarm prints and \"0\" to deactivate alarm prints\n";
    print_field($fh, $field_vars, 'ALARM_PRINTS');
    print $fh "#\n";
    print $fh "#############################################################################\n";
    print $fh "# -------------------------------- SOM EOM ----------------------------------\n";
    print $fh "#############################################################################\n";
    print_field($fh, $field_vars, 'SOM_EOM');
    print $fh "#\n";
    print $fh "#############################################################################\n";
    print $fh "# ------------------------------EXTERNAL MAPS-------------------------------\n";
    print $fh "#############################################################################\n";
    print $fh "# --- Host Name Table (HostName)\n";
    print_field($fh, $field_vars, 'HOST');
    print $fh "# --- External Map ${nombre_agente}\n";
    print_field($fh, $field_vars, 'Severity');
    print_field($fh, $field_vars, 'ExternalMap');
    print $fh "#\n";
    print $fh "#############################################################################\n";
    print $fh "# -----------------------------BLOCKING FILTERS-----------------------------\n";
    print $fh "#############################################################################\n";
    print $fh "# --- Filter used just in this agent\n";
    print_field($fh, $field_vars, 'FB_AGENTE');
    print_field($fh, $field_vars, 'FB_all');
    print $fh "#############################################################################\n";
    print $fh "# ----------------------------CORRECTIVE FILTERS----------------------------\n";
    print $fh "#############################################################################\n";
    print_field($fh, $field_vars, 'FC_PrependAdditionalText');
    print_field($fh, $field_vars, 'FC_SetEventSeverity');
    print_field($fh, $field_vars, 'FC_SetGrupos');
    print_field($fh, $field_vars, 'FC_SetIncidentType');
    print_field($fh, $field_vars, 'FC_SetIncidentType_NonCascade');
    print_field($fh, $field_vars, 'FC_SetUserText');
    close $fh or die "Error al cerrar $archivo_properties: $!";
}

# Function to validate the existence of AGENT.properties file
sub validar_existencia_archivo_properties {
    my ($ventana_principal, $ruta_agente) = @_;
    my $archivo_properties = File::Spec->catfile($ruta_agente, "AGENT.properties");
    unless (-e $archivo_properties) {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se pudo encontrar el archivo AGENT.properties en la ruta: $archivo_properties", 'error');
        return 0;
    }
    return 1;
}

# Subroutine to print a field with comment validation
sub print_field {
    my ($fh, $field_vars, $key) = @_;
    my $comment_key = "comment_$key";
    if (exists $field_vars->{$comment_key} && ${$field_vars->{$comment_key}} == 1) {
        print $fh "#$key:=${$field_vars->{$key}}\n";
    } else {
        print $fh "$key:=${$field_vars->{$key}}\n";
    }
}

# Subroutine para listar todos los modulos locales disponibles MIBS
# Función principal para abrir una carpeta en el explorador de archivos
sub abrir_carpeta {
    my ($ventana_principal, $directorio) = @_;


    
    # Validar que se proporcionó un directorio
    unless ($directorio) {
        herramientas::Complementos::show_alert($ventana_principal, 'Advertencia', "No se proporcionó un directorio", 'warning');
        return;
    }

    # Validar que el directorio exista
    unless (-d $directorio) {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "El directorio no existe: $directorio", 'error');
        return;
    }

    # Intentar abrir el directorio en el explorador de archivos
    my $command = "explorer " . File::Spec->rel2abs($directorio);
    my $result = system($command);

    # Manejo de errores
    if ($result == 0 || $result == 256) {
        herramientas::Complementos::show_alert($ventana_principal, 'EXITO', "Se abrió correctamente el directorio $directorio", 'success');
    } else {
        herramientas::Complementos::show_alert($ventana_principal, 'ERROR', "No se puede abrir el directorio: $!", 'error');
    }
}


1;