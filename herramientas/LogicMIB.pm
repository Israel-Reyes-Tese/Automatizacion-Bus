package LogicMIB;

use strict;
use warnings;

use Tk;
use TK::Table;

# Añadir la carpeta donde se encuentran los modulos
use lib $FindBin::Bin . "/herramientas";
use lib $FindBin::Bin . "./Script Generacion de Agentes SNMP/utilidades";


use SNMP::MIB::Compiler;

# Ventanas secundarias
use MIB_utils;

use Data::Dumper; # Importar el modulo Data::Dumper

use File::Path qw(make_path rmtree);
use File::Temp qw(tempfile);

use File::Spec;
use File::Basename;

use Cwd 'abs_path';

use FindBin;

use Data::Dumper;
use Toolbar;
use Estilos;
use Complementos;
use Rutas;


# Funcion principal para cargar MIBs
sub cargar_mib {
    my ($ventana_principal, $result_table_pane, $mib_tree_pane, $buscar_ext_mib, $buscar_ext_txt, $buscar_sin_ext) = @_;
    my %mib_files;
    my @selected_files = "";

    # Crear una ventana de seleccion de archivos
    my $fs = $result_table_pane->FileSelect(
        -title => 'Seleccionar archivos MIB',
        -selectmode => 'multiple',
    );

    @selected_files = $fs->Show;

    # Manejo de errores
    if (!@selected_files) {
        warn "No se seleccionaron archivos en la funcion cargar_mib";
        return;
    }

    # Agregar archivos adicionales según las extensiones especificadas


    if ($buscar_ext_mib) {
        push @selected_files, buscar_archivos_por_extension(\@selected_files, 'mib');
    }
    if ($buscar_ext_txt) {
        push @selected_files, buscar_archivos_por_extension(\@selected_files, 'txt');
    }
    if ($buscar_sin_ext) {
        print "Buscar archivos sin extension\n";
        push @selected_files, buscar_archivos_por_extension(\@selected_files, '');
    }

    # Guardar los archivos seleccionados en un hash para eliminar duplicados
    foreach my $file (@selected_files) {
        $mib_files{abs_path($file)} = 1;
    }
    

    # Validar los archivos MIB
    foreach my $file (keys %mib_files) {
        unless (validar_mib($file, $ventana_principal)) {
            warn "Archivo MIB no valido: $file";
            next;
        }
        unless (validar_importaciones($file, \%mib_files, $ventana_principal)) {
            warn "Importaciones no validas en el archivo MIB: $file";
            next;
        }

    }

    # Crear ventana de selección si hay más de un archivo MIB
    if (keys %mib_files > 1) {
        my $selected_files = crear_ventana_seleccion_mib(\%mib_files, $ventana_principal);
        %mib_files = map { $_ => 1 } @$selected_files;
    }

    # Mostrar los archivos seleccionados en el panel
    foreach my $file (keys %mib_files) {
        my $relative_path = File::Spec->abs2rel($file);
        $mib_tree_pane->Label(-text => $relative_path, -bg => $herramientas::Estilos::twilight_grey)->pack(-side => 'top', -anchor => 'w');
    }
    # Extraer la información de los archivos MIB seleccionados
    # Datos OBJECT-IDENTITY
    my %object_identities;
    foreach my $file (keys %mib_files) {
        # Extraer OBJECT-IDENTITY y añadir al hash object_identities
        my $extracted_object_identities = extraer_object_identities($file);
        @object_identities{keys %$extracted_object_identities} = values %$extracted_object_identities;
    }
    #print Dumper(\%object_identities);
    
    
    # Datos OBJECT-TYPE
    my %object_types;
    foreach my $file (keys %mib_files) {
        # Extraer OBJECT-TYPE y añadir al hash object_types
        my $extracted_object_types = extraer_object_types($file);
        @object_types{keys %$extracted_object_types} = values %$extracted_object_types;

    }
    #print Dumper(\%object_types);

    # Datos OBJECT IDENTIFIER
    my %object_identifiers;
    foreach my $file (keys %mib_files) {
        # Extraer OBJECT IDENTIFIER y añadir al hash object_identifiers
        my $extracted_object_identifiers = extraer_object_identifiers($file);
        @object_identifiers{keys %$extracted_object_identifiers} = values %$extracted_object_identifiers;
    }
    #print Dumper(\%object_identifiers);

    # Datos MODULE-IDENTITY
    my %module_identities;
    foreach my $file (keys %mib_files) {
        # Extraer MODULE-IDENTITY y añadir al hash module_identities
        my $extracted_module_identities = extraer_module_identities($file);
        @module_identities{keys %$extracted_module_identities} = values %$extracted_module_identities;
    }
    print Dumper(\%module_identities);


    # Datos de las alarmas NOTIFICATION-TYPE o TRAP-TYPE
    my %alarm_traps;
    foreach my $file (keys %mib_files) {
        # Extraer OBJECT-TYPE y añadir al hash object_types
        my $extracted_alarm_traps = extraer_alarm_traps($file);
        @alarm_traps{keys %$extracted_alarm_traps} = values %$extracted_alarm_traps;
    }
    #print Dumper(\%alarm_traps);

    # Extract OID nodes
    my $oid_nodes = extraer_nodos_oid(\%mib_files);
    if ($oid_nodes->{enterprise_oid}) {
    } else {
        # Logica para crear una ventana emergente para ingresar el OID de la empresa
        $oid_nodes = mostrar_ventana_seleccion_empresa($ventana_principal);
    }
    #print "Nodos OID: ", Dumper($oid_nodes);

}

# Ventana de selección de archivos MIB Emergente
sub crear_ventana_seleccion_mib {
    my ($mib_files, $ventana_principal) = @_;
    my $mw =  $ventana_principal->Toplevel();
    $mw->title("Seleccionar Archivos MIB");
    $mw->configure(-background => $herramientas::Estilos::mib_selection_bg);

    my $frame = $mw->Frame(-background => $herramientas::Estilos::mib_selection_bg)->pack(-side => 'top', -fill => 'both', -expand => 1);
    my %selected_files = map { $_ => 1 } keys %$mib_files;

    foreach my $file (keys %$mib_files) {
        my $checkbutton = $frame->Checkbutton(
            -text => $file,
            -variable => \$selected_files{$file},
            -background => $herramientas::Estilos::mib_selection_bg,
            -foreground => $herramientas::Estilos::mib_selection_fg,
            -font => $herramientas::Estilos::mib_selection_checkbutton_font
        )->pack(-side => 'top', -anchor => 'w');
    }

    my $button_frame = $mw->Frame(-background => $herramientas::Estilos::mib_selection_bg)->pack(-side => 'bottom', -fill => 'x');
    my $user_selection;

    $button_frame->Button(
        -text => "Guardar",
        -command => sub { $user_selection = 'guardar'; $mw->destroy },
        -background => $herramientas::Estilos::mib_selection_button_bg,
        -foreground => $herramientas::Estilos::mib_selection_button_fg,
        -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
        -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
        -font => $herramientas::Estilos::mib_selection_button_font
    )->pack(-side => 'left', -padx => 10, -pady => 10);

    $button_frame->Button(
        -text => "Salir",
        -command => sub { $user_selection = 'salir'; $mw->destroy },
        -background => $herramientas::Estilos::mib_selection_button_bg,
        -foreground => $herramientas::Estilos::mib_selection_button_fg,
        -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
        -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
        -font => $herramientas::Estilos::mib_selection_button_font
    )->pack(-side => 'left', -padx => 10, -pady => 10);

    $button_frame->Button(
        -text => "Resetear",
        -command => sub { resetear_seleccion(\%selected_files) },
        -background => $herramientas::Estilos::mib_selection_button_bg,
        -foreground => $herramientas::Estilos::mib_selection_button_fg,
        -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
        -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
        -font => $herramientas::Estilos::mib_selection_button_font
    )->pack(-side => 'left', -padx => 10, -pady => 10);

    $mw->waitWindow; # Esperar a que el usuario seleccione algún botón

    return $user_selection eq 'guardar' ? [grep { $selected_files{$_} } keys %selected_files] : [];
}

# Function to save the selected MIB files
sub guardar_seleccion {
    my ($selected_files, $mw) = @_;
    my @selected = grep { $selected_files->{$_} } keys %$selected_files;
    $mw->destroy;
    return \@selected;
}

# Function to reset the selection
sub resetear_seleccion {
    my ($selected_files) = @_;
    $_ = 1 for values %$selected_files;
}

# Funcion para validar un archivo MIB
sub validar_mib {
    my ($file, $ventana_principal) = @_;
    my $is_valid = 1;
    my %oids;
    my %names;
    my @invalid_syntax;
    my @warnings;

    # Leer el archivo MIB
    open my $fh, '<', $file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return 0;
    };
    my @lines = <$fh>;
    close $fh;

    # Variables para verificar balanceo de llaves y paréntesis
    my $brace_count = 0;
    my $paren_count = 0;
    # Hashes para verificar campos SYNTAX
    my %base_syntax = map { $_ => 1 } qw(
        INTEGER INTEGER32 UNSIGNED32 Counter32 Gauge32 TimeTicks Counter64
        OCTET STRING OBJECT IDENTIFIER IpAddress Opaque
    );

    my %textual_conventions = map { $_ => 1 } qw(
        DisplayString PhysAddress MacAddress TruthValue TestAndIncr AutonomousType
        RowStatus StorageType TDomain TAddress DateAndTime InetAddress InetAddressType InetPortNumber
    );

    foreach my $line (@lines) {
        # Contar llaves y paréntesis
        $brace_count += ($line =~ tr/{//) - ($line =~ tr/}//);
        $paren_count += ($line =~ tr/(//) - ($line =~ tr/)//);

        # Verificar definiciones de objetos
        if ($line =~ /^\s*(\w+)\s+OBJECT-TYPE\s*$/) {
            my $name = $1;
            if ($name !~ /^[a-zA-Z]\w*$/) {
                push @warnings, "Nombre simbólico invalido: $name";
            }
            if (exists $names{$name}) {
                push @warnings, "Nombre simbólico duplicado: $name";
            }
            $names{$name} = 1;
        }

        # Verificar OIDs
        if ($line =~ /::=\s*\{([^\}]+)\}/) {
            my $oid = $1;
            $oid =~ s/\s+//g;
            if (exists $oids{$oid}) {
                push @warnings, "OID duplicado: $oid";
            }
            $oids{$oid} = 1;
        }

        # Verificar campos SYNTAX
        if ($line =~ /^\s*SYNTAX\s+(\w+)\s*$/) {
            my $syntax = $1;
            unless (exists $base_syntax{$syntax} || exists $textual_conventions{$syntax}) {
                push @invalid_syntax, $syntax;
            }
        }

        # Verificar campos DESCRIPTION
        if ($line =~ /^\s*DESCRIPTION\s+"([^"]*)"\s*$/) {
            my $description = $1;
            if ($description =~ /[^a-zA-Z0-9\s.,;:()'"\-]/) {
                push @warnings, "Descripción invalida: $description";
            }
        }
    }

    # Verificar balanceo de llaves y paréntesis
    if ($brace_count != 0) {
        push @warnings, "Llaves desbalanceadas en el archivo $file";
    }
    if ($paren_count != 0) {
        push @warnings, "Paréntesis desbalanceados en el archivo $file";
    }

    # Generar advertencia si hay SYNTAX inválidos
    if (@invalid_syntax) {
        my $invalid_syntax_str = join "\n", @invalid_syntax;
        push @warnings, "Los siguientes SYNTAX no son válidos:\n$invalid_syntax_str";
    }

    # Generar advertencia si hay otras advertencias
    if (@warnings) {
        my $warnings_str = join "\n", @warnings;
        my $response = herramientas::Complementos::create_alert_with_picture_label_and_button(
            $ventana_principal, 'Advertencias de Validación', 
            "Se encontraron las siguientes advertencias:\n$warnings_str\n¿Desea ignorar estas advertencias?", 'question'
        );

        if (!$response) {
            $is_valid = 0;
        }
    }

    return $is_valid;
}

# Funcion para validar las importaciones en los archivos MIB
sub validar_importaciones {
    my ($file, $mib_files, $ventana_principal) = @_;
    my $is_valid = 1;
    my @missing_imports;
    # Ruta relativa del archivo MIB
    my $relative_path = File::Spec->abs2rel($file);

    # Leer el archivo MIB
    open my $fh, '<', $file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return 0;
    };
    my @lines = <$fh>;
    close $fh;
    # Extraer las líneas desde IMPORTS hasta el proximo ;
    my $imports_section = 0;
    my @imports;
    foreach my $line (@lines) {
        if ($line =~ /IMPORTS/) {
            $imports_section = 1;
        }
        if ($imports_section) {
            if ($line =~ /FROM\s+(\S+);?/) {
                push @imports, $1;
            }
            # Fin de la seccion IMPORTS - eliminar el punto y coma
            last if $line =~ /;/; 
            # Eliminar el punto y coma de la línea actual
            $line =~ s/;//;
        }
    }
    # Eliminiar nombres repetidos, espacios en blanco y cadenas vacías y convertir a minúsculas y caracteres especiales ;
    @imports = grep { $_ } map { lc($_) } map {
            my $import = $_;
            $import =~ s/[\s;]//g; 
            $import;
        } @imports;

    # Generar la lista de modulos disponibles recortando la ruta de los archivos para obtener solo el nombre - eliminar la extension
    my @available_modules = map { (File::Spec->splitpath($_))[2] =~ s/\.[^.]+$//r } keys %$mib_files;
    # Eliminiar nombres repetidos, espacios en blanco y cadenas vacías y convertir a minúsculas
    @available_modules = grep { $_ } map { lc($_) } map {
        my $module = $_;
        $module =~ s/\s+//g;
        $module;
    } @available_modules;

    # Verificar si los modulos importados estan disponibles
    foreach my $import (@imports) {
        unless (grep { $_ eq $import } @available_modules) {
            push @missing_imports, $import;
            $is_valid = 0;
        }
    }

    # Generar una alerta si hay importaciones faltantes y preguntar si se desea buscar localmente
    if (!$is_valid) {
        my $missing_imports = join ', ', @missing_imports;
        my $response = herramientas::Complementos::create_alert_with_picture_label_and_button(
            $ventana_principal, 'Importaciones Faltantes', 
            "Los siguientes modulos no estan disponibles: $missing_imports\n¿Desea buscar los modulos localmente?", 'question'
        );

        if ($response) {
            my @local_modules = buscar_modulos_localmente();
            @available_modules = (@available_modules, @local_modules);
            # Eliminar los modulos encontrados de missing_imports
            @missing_imports = grep { my $import = $_; !grep { $_ eq $import } @available_modules } @missing_imports;

            if (@missing_imports) {
                herramientas::Complementos::show_alert(
                    $ventana_principal, 'ERROR', 
                    "Error: Los siguientes modulos no estan disponibles: " . join(', ', @missing_imports) . "\narchivo: $relative_path", 'error'
                );
            } else {
                herramientas::Complementos::show_alert(
                    $ventana_principal, 'ÉXITO', 
                    "Los modulos faltantes se han encontrado localmente", 'success'
                );
            }

        } else {
            herramientas::Complementos::show_alert(
                $ventana_principal, 'ERROR', 
                "Error: Los siguientes modulos no estan disponibles: $missing_imports\narchivo: $relative_path", 'error'
            );
        }
    }
    return $is_valid;
}

# Funcion para buscar modulos localmente en las rutas especificadas
sub buscar_modulos_localmente {
    my @local_modules;
    my @paths = (Rutas::mib_module_v1_path(), Rutas::mib_module_v2_path());

    foreach my $path (@paths) {
        opendir(my $dh, $path) or do {
            warn "No se pudo abrir el directorio $path: $!";
            next;
        };

        while (my $entry = readdir($dh)) {
            next if $entry =~ /^\./; # Ignorar archivos ocultos
            push @local_modules, lc($entry =~ s/\.[^.]+$//r);
        }
        closedir($dh);
    }

    return @local_modules;
}

# Funcion para buscar archivos por extension en el mismo directorio
sub buscar_archivos_por_extension {
    my ($selected_files, $extension) = @_;
    my @additional_files;

    foreach my $file (@$selected_files) {
        my $dir = dirname($file);
        opendir(my $dh, $dir) or do {
            warn "No se pudo abrir el directorio $dir: $!";
            next;
        };

        while (my $entry = readdir($dh)) {
            next if $entry =~ /^\./; # Ignorar archivos ocultos
            if ($extension eq '') {
                if ($entry !~ /\./) { # Archivos sin extensión
                    push @additional_files, File::Spec->catfile($dir, $entry);
                }
            } else {
                if ($entry =~ /\.$extension$/) {
                    push @additional_files, File::Spec->catfile($dir, $entry);
                }
            }
        }
        closedir($dh);
    }

    return @additional_files;
}
# Función principal para verificar y transformar archivos MIB a TXT
sub transformar_mib_a_txt {
    my ($file) = @_;

    # Verificar si el archivo tiene extensión .mib
    if ($file =~ /\.mib$/i) {
        # Crear un archivo temporal .txt
        my ($fh_temp, $filename_temp) = tempfile(SUFFIX => '.txt');

        # Copiar el contenido del archivo .mib al archivo temporal .txt
        open my $fh_mib, '<', $file or do {
            warn "Error al abrir el archivo $file en la función transformar_mib_a_txt: $!";
            return;
        };
        while (my $line = <$fh_mib>) {
            print $fh_temp $line;
        }
        close $fh_mib or warn "Error al cerrar el archivo $file en la función transformar_mib_a_txt: $!";
        close $fh_temp or warn "Error al cerrar el archivo temporal en la función transformar_mib_a_txt: $!";

        # Reemplazar el archivo original por el archivo temporal
        $file = $filename_temp;
    }

    return $file;
}

# Función para validar o crear un archivo temporal
sub validar_o_crear_archivo_temporal {
    my ($temp_file) = @_;

    # Verificar si el archivo temporal existe
    if (-e $temp_file) {
        # Limpiar el archivo si ya existe
        open my $fh_temp, '>', $temp_file or do {
            warn "No se pudo limpiar el archivo temporal $temp_file: $!";
            return;
        };
        close $fh_temp or warn "Advertencia: No se pudo cerrar el archivo temporal $temp_file: $!";
    } else {
        # Crear el archivo temporal si no existe
        open my $fh_temp, '>', $temp_file or do {
            warn "No se pudo crear el archivo temporal $temp_file: $!";
            return;
        };
        close $fh_temp or warn "Advertencia: No se pudo cerrar el archivo temporal $temp_file: $!";
    }

    return $temp_file;
}

# Función para recondicionar el archivo temporal copiando el contenido de $file
sub recondicionar_archivo_temporal {
    my ($file, $temp_file, $original_file) = @_;

    # Obtener la ruta absoluta del archivo original
    my $abs_path = abs_path($original_file);
    # Obtener el la ruta relativa del archivo original
    my $relative_path = File::Spec->abs2rel($abs_path);
    # Obtener el nombre del archivo original
    my $file_name = basename($abs_path);

    open my $fh_in, '<', $file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return;
    };

    open my $fh_out, '>', $temp_file or do {
        warn "No se pudo abrir el archivo temporal $temp_file: $!";
        close $fh_in;
        return;
    };
    # Añadir al inicio del archivo temporal la ruta del archivo original
    print $fh_out "Archivo original: $file_name\n\n";
    while (my $line = <$fh_in>) {
        $line =~ s/^\s+//;   # Eliminar espacios al inicio de la línea
        print $fh_out $line; # Imprimir la línea tal cual, conservando los saltos de línea originales
    }

    close $fh_in or warn "Advertencia: No se pudo cerrar el archivo $file: $!";
    close $fh_out or warn "Advertencia: No se pudo cerrar el archivo temporal $temp_file: $!";

    return $temp_file;
}


# Función para extraer OBJECT-IDENTITY de un archivo MIB
sub extraer_object_identities {
    my ($file) = @_;

    my $original_file = $file;

    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_path() . '/object_identities.txt';

    $file = transformar_mib_a_txt($file);
    # Validar si el archivo temporal existe, si no, crearlo
    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    # Recondicionar el archivo temporal copiando el contenido de $file
    $temp_file = recondicionar_archivo_temporal($file, $temp_file, $original_file); 

    open my $fh, '<', $temp_file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return;
    };
    my %object_identities;
    my $current_object = '';
    my $in_description = 0;
    my $description = '';
    my $nombre_archivo = '';
    my $segment = '';
    my $in_segment = 0;

    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^--/; # Saltar líneas vacías y comentarios
        # Extraer la primera línea del archivo que es el nombre del archivo original y guardarlo en el hash
        if (/Archivo original:\s+(.*)/) {
            $nombre_archivo = $1;
        }
        # Identificar el inicio del segmento
        if (/(\S+)\s+OBJECT-IDENTITY/) {
            $current_object = $1;
            $in_segment = 1;
            $segment = $_ . "\n"; # Incluir la línea actual en el segmento
            next;
        }
        # Continuar extrayendo líneas hasta encontrar "}"
        if ($in_segment) {
            $segment .= $_ . "\n";
            if (/}/) {
                my ($status) = $segment =~ /STATUS\s+(\S+)/;
                my ($description) = $segment =~ /DESCRIPTION\s+"(.*)"/s;
                my ($oid) = $segment =~ /::=\s*{([^}]+)}/;

                $object_identities{$current_object} = {
                    TYPE => 'OBJECT-IDENTITY',
                    STATUS => $status,
                    DESCRIPTION => $description,
                    ARCHIVO => $nombre_archivo,
                    OID => $oid,

                };
                $in_segment = 0;
                $segment = '';
            }
        }
    }

    close $fh or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    #print Dumper(\%object_identities);
    return \%object_identities;
}

# Función para extraer OBJECT-TYPE de un archivo MIB
sub extraer_object_types {
    my ($file) = @_;

    my $original_file = $file;

    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_path() . '/object_types.txt';

    
    $file = transformar_mib_a_txt($file);
    # Validar si el archivo temporal existe, si no, crearlo
    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    # Recondicionar el archivo temporal copiando el contenido de $file
    $temp_file = recondicionar_archivo_temporal($file, $temp_file, $original_file); 

    open my $fh, '<', $temp_file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return;
    };
    
    my %object_types;
    my $current_object = '';
    my $in_description = 0;
    my $description = '';
    my $nombre_archivo = '';
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^--/; # Saltar líneas vacías y comentarios
        # Extraer la primera línea del archivo que es el nombre del archivo original y guardarlo en el hash
        if (/Archivo original:\s+(.*)/) {
            $nombre_archivo = $1;
        }
        if (/(\w+)\s+OBJECT-TYPE/) {
            $current_object = $1;
            $object_types{$current_object} = {};
            $object_types{$current_object} -> {'ARCHIVO'} = $nombre_archivo;
        }
        elsif ($current_object) {
            if (/SYNTAX\s+(.*)/) {
                $object_types{$current_object}->{'SYNTAX'} = $1;
            } elsif (/MAX-ACCESS\s+(.*)/) {
                $object_types{$current_object}->{'MAX-ACCESS'} = $1;
            } elsif (/STATUS\s+(.*)/) {
                $object_types{$current_object}->{'STATUS'} = $1;
            } elsif (/DESCRIPTION\s+["'](.*)/) {
                $description = $1;
                $in_description = 1;
            } elsif (/DESCRIPTION\s*$/) {
                $description = $1;
                $in_description = 1;
            } elsif ($in_description) {
                if (/["]\s*::=\s*\{(.*)\}/) {
                    $description .= " $1";
                    $object_types{$current_object}->{'DESCRIPTION'} = $description;
                    $object_types{$current_object}->{'OID'} = $1; # Extraer y asignar OID
                    $in_description = 0;
                } elsif (/}/)  {
                    $description .= " $_";
                    if ($description =~ /::=\s*\{(.*)\}/) {
                        $object_types{$current_object}->{'OID'} = $1; # Extraer y asignar OID
                    }
                    $object_types{$current_object}->{'DESCRIPTION'} = $description;
                    $in_description = 0;
                } else {
                    $description .= " $_";
                }
            } 
        } 
    }
    # Eliminar ::= { contenido } de la descripción y limpiar espacios y caracteres especiales
    foreach my $object (keys %object_types) {
        foreach my $field (qw(DESCRIPTION SYNTAX MAX-ACCESS STATUS OID)) {
            if (exists $object_types{$object}->{$field}) {
                $object_types{$object}->{$field} =~ s/\s*::=\s*\{.*\}//;
                $object_types{$object}->{$field} =~ s/^\s+|\s+$//g; # Eliminar espacios al inicio y al final
                $object_types{$object}->{$field} =~ s/^["']|["']$//g; # Eliminar caracteres especiales al inicio y al final
            }
        }
    }
    close $fh or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    #print Dumper(\%object_types);
    return \%object_types;
}

# Función para extraer OBJECT IDENTIFIER de un archivo MIB
sub extraer_object_identifiers {
    my ($file) = @_;

    my $original_file = $file;

    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_path() . '/object_identifiers.txt';

    # Validar si el archivo temporal existe, si no, crearlo
    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    # Recondicionar el archivo temporal copiando el contenido de $file
    $temp_file = recondicionar_archivo_temporal($file, $temp_file, $original_file); 

    open my $fh, '<', $temp_file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return;
    };
    my %object_identifiers;
    my $nombre_archivo = '';

    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^--/; # Saltar líneas vacías y comentarios
        # Extraer la primera línea del archivo que es el nombre del archivo original y guardarlo en el hash
        if (/Archivo original:\s+(.*)/) {
            $nombre_archivo = $1;
        }
        # Identificar el OBJECT IDENTIFIER
        if (/(\S+)\s+OBJECT IDENTIFIER\s+::=\s*{([^}]+)}/) {
            my $name = $1;
            my $oid = $2;
            $object_identifiers{$name} = {
                TYPE => 'OBJECT IDENTIFIER',
                OID => $oid,
                ARCHIVO => $nombre_archivo
            };
        }
    }

    # Eliminar ::= { contenido } de la descripción y limpiar espacios y caracteres especiales
    foreach my $object (keys %object_identifiers) {
        foreach my $field (qw(OID TYPE ARCHIVO)) {
            if (exists $object_identifiers{$object}->{$field}) {
                $object_identifiers{$object}->{$field} =~ s/\s*::=\s*\{.*\}//;
                $object_identifiers{$object}->{$field} =~ s/^\s+|\s+$//g; # Eliminar espacios al inicio y al final
                $object_identifiers{$object}->{$field} =~ s/^["']|["']$//g; # Eliminar caracteres especiales al inicio y al final
            }
        }
    }

    close $fh or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    #print Dumper(\%object_identifiers);
    return \%object_identifiers;
}

# Función para extraer MODULE-IDENTITY de un archivo MIB
sub extraer_module_identities {
    my ($file) = @_;

    my $original_file = $file;

    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_path() . '/module_identities.txt';

    # Validar si el archivo temporal existe, si no, crearlo
    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    # Recondicionar el archivo temporal copiando el contenido de $file
    $temp_file = recondicionar_archivo_temporal($file, $temp_file, $original_file); 

    open my $fh, '<', $temp_file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return;
    };
    my %module_identities;
    my $current_object = '';
    my $in_segment = 0;
    my $segment = '';
    my $nombre_archivo = '';

    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^--/; # Saltar líneas vacías y comentarios
        # Extraer la primera línea del archivo que es el nombre del archivo original y guardarlo en el hash
        if (/Archivo original:\s+(.*)/) {
            $nombre_archivo = $1;
        }
        # Identificar el inicio del segmento
        if (/(\S+)\s+MODULE-IDENTITY/) {
            $current_object = $1;
            $in_segment = 1;
            $segment = $_ . "\n"; # Incluir la línea actual en el segmento
            next;
        }
        # Continuar extrayendo líneas hasta encontrar "}"
        if ($in_segment) {
            $segment .= $_ . "\n";
            if (/}/) {
                my ($last_updated) = $segment =~ /LAST-UPDATED\s+"([^"]+)"/;
                my ($organization) = $segment =~ /ORGANIZATION\s+"([^"]+)"/;
                my ($contact_info) = $segment =~ /CONTACT-INFO\s+"([^"]+)"/s;
                my @descriptions = $segment =~ /DESCRIPTION\s+"(.*?)"/sg;
                my @revisions = $segment =~ /REVISION\s+"([^"]+)"/g;
                my ($oid) = $segment =~ /::=\s*{([^}]+)}/;

                my %descriptions_hash;
                for my $i (0..$#descriptions) {
                    $descriptions_hash{"DESCRIPTION_" . ($i + 1)} = $descriptions[$i];
                }

                my %revisions_hash;
                for my $i (0..$#revisions) {
                    $revisions_hash{"REVISION_" . ($i + 1)} = $revisions[$i];
                }

                $module_identities{$current_object} = {
                    TYPE => 'MODULE-IDENTITY',
                    LAST_UPDATED => $last_updated,
                    ORGANIZATION => $organization,
                    CONTACT_INFO => $contact_info,
                    %descriptions_hash,
                    %revisions_hash,
                    OID => $oid,
                    ARCHIVO => $nombre_archivo
                };
                $in_segment = 0;
                $segment = '';
            }
        }
    }

    close $fh or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    #print Dumper(\%module_identities);
    return \%module_identities;
}


# Función para extraer la información de los traps de las alarmas
sub extraer_alarm_traps {
    my ($file) = @_;
    
    $file = transformar_mib_a_txt($file);

    open my $fh, '<', $file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return;
    };
    
    my %alarm_traps;
    my $current_alarm = '';
    my $in_description = 0;
    my $description = '';
    my $in_objects = 0;
    my @objects;
    my $objects_accumulator = '';

    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^--/; # Saltar líneas vacías y comentarios

        if (/(\w+)\s+(NOTIFICATION-TYPE|TRAP-TYPE)/) {
            $current_alarm = $1;
            $alarm_traps{$current_alarm} = {
                TYPE => $2,
                OBJECTS => '',
                STATUS => '',
                DESCRIPTION => '',
                OID => ''
            };
            $in_objects = 0;
            $in_description = 0;
            $objects_accumulator = '';
        }
        elsif ($current_alarm) {
            if (/OBJECTS\s*{\s*(.*)/) {
                $in_objects = 1;
                $objects_accumulator = $1;
            } elsif (/OBJECTS\s*$/) {
                $in_objects = 1;
                $objects_accumulator = '';
            } elsif ($in_objects) {
                if (/^\s*{\s*(.*)/) {
                    $objects_accumulator .= " $1";
                } elsif (/(.*)\s*}/) {
                    $objects_accumulator .= " $1";
                    $alarm_traps{$current_alarm}->{OBJECTS} = $objects_accumulator;
                    $in_objects = 0;
                } else {
                    $objects_accumulator .= " $_";
                }
            } elsif (/STATUS\s+(.*)/) {
                $alarm_traps{$current_alarm}->{STATUS} = $1;
            } elsif (/DESCRIPTION\s+["'](.*)/) {
                $description = $1;
                $in_description = 1;
            } elsif (/DESCRIPTION\s*$/){
                $description = $1;
                $in_description = 1;
                
            }          
            elsif ($in_description) {
                if (/["]\s*::=\s*\{(.*)\}/) {
                    $description .= " $1";
                    $alarm_traps{$current_alarm}->{DESCRIPTION} = $description;
                    $alarm_traps{$current_alarm}->{OID} = $1; # Extraer y asignar OID
                    $in_description = 0;
                } elsif (/}/)  {
                    $description .= " $_";
                    if ($description =~ /::=\s*\{(.*)\}/) {
                        $alarm_traps{$current_alarm}->{OID} = $1; # Extraer y asignar OID
                    }
                    $alarm_traps{$current_alarm}->{DESCRIPTION} = $description;
                    $in_description = 0;
                } else {
                    $description .= " $_";
                }
            }
        }
    }
    close $fh or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    # Eliminar ::= { contenido } de la descripción y limpiar espacios y caracteres especiales
    foreach my $alarm (keys %alarm_traps) {
        if (exists $alarm_traps{$alarm}->{'DESCRIPTION'}) {
            $alarm_traps{$alarm}->{'DESCRIPTION'} =~ s/\s*::=\s*\{.*\}//;
            $alarm_traps{$alarm}->{'DESCRIPTION'} =~ s/^\s+|\s+$//g; # Eliminar espacios al inicio y al final
            $alarm_traps{$alarm}->{'DESCRIPTION'} =~ s/^["']|["']$//g; # Eliminar caracteres especiales al inicio y al final
            $alarm_traps{$alarm}->{'DESCRIPTION'} =~ s/\s+/ /g; # Eliminar mas de un espacio
        }
        # Objetos de alarma
        if (exists $alarm_traps{$alarm}->{'OBJECTS'}) {
            $alarm_traps{$alarm}->{'OBJECTS'} =~ s/\s*::=\s*\{.*\}//;
            $alarm_traps{$alarm}->{'OBJECTS'} =~ s/^\s+|\s+$//g; # Eliminar espacios al inicio y al final
            $alarm_traps{$alarm}->{'OBJECTS'} =~ s/^["']|["']$//g; # Eliminar caracteres especiales al inicio y al final
            # Eliminar mas de un espacio
            $alarm_traps{$alarm}->{'OBJECTS'} =~ s/\s+/ /g;
        }
    }
    return \%alarm_traps;
}

# Function to extract and identify OID nodes
sub extraer_nodos_oid {
    my ($mib_files) = @_;
    my $root_oid = "1.3.6.1";
    my $private_enterprises_oid = "4.1";
    my $enterprise_oid;

    my $enterprise_file;
    my @filtered_enterprise_hash;

    my @enterprise_hash = extraer_datos_empresas();
    @filtered_enterprise_hash = @enterprise_hash;

    foreach my $file (keys %$mib_files) {
        open my $fh, '<', $file or do {
            warn "No se pudo abrir el archivo $file: $!";
            next;
        };
        while (my $line = <$fh>) {
            if ($line =~ /::=\s*\{\s*enterprises\s+(\d+)\s*\}/) {
                $enterprise_oid = $1;
                $enterprise_file = $file;
                last;
            }
        }
        close $fh;
        last if $enterprise_oid;
    }

    unless ($enterprise_oid) {
        warn "No se pudo encontrar el ID único de la empresa o proveedor. Ingréselo manualmente o busque en los archivos locales.";
    }

    my $enterprise_info;
    foreach my $enterprise (@filtered_enterprise_hash) {
        if (defined $enterprise_oid && $enterprise->{ID} == $enterprise_oid) {
            $enterprise_info = {
                ID => $enterprise->{ID},
                Organization => $enterprise->{Organization},
                Email => $enterprise->{Email},
                Seleccionado => $enterprise->{Seleccionado},
                Contact => $enterprise->{Contact},
            };
            last;
        }
    }

    unless ($enterprise_info) {
        warn "No se encontró el ID en la lista de empresas. Construyendo datos constantes.";
        $enterprise_info = {
            ID => $enterprise_oid,
            Organization => 'Desconocido',
            Email => '-',
            Seleccionado => '1',
            Contact => 'Desconocido',
        };
    }

    return {
        root_oid => $root_oid,
        private_enterprises_oid => $private_enterprises_oid,
        enterprise_oid => $enterprise_oid,
        enterprise_file => $enterprise_file,
        enterprise_info_ID => $enterprise_info->{ID},
        enterprise_info_Organization => $enterprise_info->{Organization},
        enterprise_info_Email => $enterprise_info->{Email},
        enterprise_info_Contact => $enterprise_info->{Contact},
        enterprise_info_Seleccionado => $enterprise_info->{Seleccionado},
    };
}

# Function to display a paginated table of enterprise IDs
sub mostrar_ventana_seleccion_empresa {
    my ($ventana_principal) = @_;
    our @enterprise_data;
    our $page_size = 50;
    our $current_page = 0;
    our $selected_row;
    our @filtered_enterprise_hash;
    our $selected_company; 
    our $return_value_company;

    my $root_oid = "1.3.6.1";
    my $private_enterprises_oid = "4.1";
    my $enterprise_oid;

    my @enterprise_hash = extraer_datos_empresas();
    @filtered_enterprise_hash = @enterprise_hash;

    # Create the main window
    our $mw = $ventana_principal->Toplevel();
    $mw->title("Seleccionar Empresa");
    $mw->configure(-background => $herramientas::Estilos::twilight_grey);
    # Maximize the window
    $mw->state('zoomed');

    # Create search entry and button
    my $search_frame = $mw->Frame(-background => $herramientas::Estilos::mib_selection_bg)->pack(-side => 'top', -fill => 'x');
    my $search_entry = $search_frame->Entry(-font => $herramientas::Estilos::input_font)->pack(-side => 'left', -fill => 'x', -expand => 1, -padx => 10, -pady => 10);
    $search_frame->Button(
        -text => "Buscar",
        -command => sub {
            my $search_term = $search_entry->get();
            @filtered_enterprise_hash = grep {
                $_->{ID} =~ /\Q$search_term\E/i ||
                $_->{Organization} =~ /\Q$search_term\E/i ||
                $_->{Email} =~ /\Q$search_term\E/i
            } @enterprise_hash;
            $current_page = 0;
            populate_table($current_page);
        },
        -background => $herramientas::Estilos::mib_selection_button_bg,
        -foreground => $herramientas::Estilos::mib_selection_button_fg,
        -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
        -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
        -font => $herramientas::Estilos::mib_selection_button_font
    )->pack(-side => 'right', -padx => 10, -pady => 10);

    # Create a frame for the table and scrollbar
    our $table_frame = $mw->Frame(-background => $herramientas::Estilos::pine_green)->pack(-side => 'top', -fill => 'both', -expand => 1);

    # Create the header panel
    my $encabezado_table_panel = $table_frame->Scrolled('Pane', -scrollbars => 'osoe', -bg => $herramientas::Estilos::twilight_grey)->pack(-side => 'top', -fill => 'x');
    # Add headers to the header panel
    my $header_frame = $encabezado_table_panel->Frame(-background => $herramientas::Estilos::twilight_grey)->pack(-side => 'top', -fill => 'x');
    foreach my $header (qw(Decimal Organization Contact Email Seleccionar)) {
        $header_frame->Label(
            -text => $header,
            -background => $herramientas::Estilos::table_header_bg,
            -foreground => $herramientas::Estilos::table_header_fg,
            -font => $herramientas::Estilos::table_header_font, 
            -relief => 'raised',
            -borderwidth => 3
        )->pack(-side => 'left', -fill => 'x');
    }
    # Create the navigation buttons panel
    our $nav_buttons_frame = $mw->Frame(-background => $herramientas::Estilos::mib_selection_bg)->pack(-side => 'top', -fill => 'x');

    update_nav_buttons();
    # Create the data panel
    our $result_table_pane = $table_frame->Scrolled('Pane', -scrollbars => 'osoe', -bg => $herramientas::Estilos::forest_shadow)->pack(-side => 'top', -fill => 'both', -expand => 1);
    # Populate the initial table
    populate_table($current_page);
    # Create the button panel
    my $button_panel = $table_frame->Frame(-background => $herramientas::Estilos::mib_selection_bg)->pack(-side => 'bottom', -fill => 'x');
    # Add buttons to the button panel
    $button_panel->Button(
        -text => "Anterior",
        -command => sub {
            if ($current_page > 0) {
                $current_page--;
                populate_table($current_page);
            }
        },
        -background => $herramientas::Estilos::mib_selection_button_bg,
        -foreground => $herramientas::Estilos::mib_selection_button_fg,
        -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
        -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
        -font => $herramientas::Estilos::mib_selection_button_font
    )->pack(-side => 'left', -padx => 10, -pady => 10);

    $button_panel->Button(
        -text => "Siguiente",
        -command => sub {
            if (($current_page + 1) * $page_size < @filtered_enterprise_hash) {
                $current_page++;
                populate_table($current_page);
            }
        },
        -background => $herramientas::Estilos::mib_selection_button_bg,
        -foreground => $herramientas::Estilos::mib_selection_button_fg,
        -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
        -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
        -font => $herramientas::Estilos::mib_selection_button_font
    )->pack(-side => 'left', -padx => 10, -pady => 10);

    $button_panel->Button(
        -text => "Refrescar",
        -command => sub {
            @filtered_enterprise_hash = @enterprise_hash;
            $current_page = 0;
            populate_table($current_page);
        },
        -background => $herramientas::Estilos::mib_selection_button_bg,
        -foreground => $herramientas::Estilos::mib_selection_button_fg,
        -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
        -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
        -font => $herramientas::Estilos::mib_selection_button_font
    )->pack(-side => 'left', -padx => 10, -pady => 10);

    $button_panel->Button(
        -text => "Guardar",
        -command => sub {
            my @selected_data = grep { $_->{Seleccionado} } @filtered_enterprise_hash;
            if (scalar @selected_data > 1) {
                herramientas::Complementos::show_alert(
                    $mw, 'Advertencia', 
                    "Solo se puede seleccionar una empresa. Se seleccionaron más de una.", 'warning'
                );
                @filtered_enterprise_hash = @enterprise_hash;


                $current_page = 0;
                populate_table($current_page);
            } elsif (scalar @selected_data == 1) {
                 $selected_company = $selected_data[0];
                # Agregar datos de la empresa seleccionada
                $return_value_company->{root_oid} = $root_oid;
                $return_value_company->{private_enterprises_oid} = $private_enterprises_oid;
                $return_value_company->{enterprise_info_ID} = $selected_company->{ID};
                $return_value_company->{enterprise_file} = "-";
                $return_value_company->{enterprise_oid} = $selected_company->{ID};
                $return_value_company->{enterprise_info_Organization} = $selected_company->{Organization};
                $return_value_company->{enterprise_info_Contact} = $selected_company->{Contact};
                $return_value_company->{enterprise_info_Email} = $selected_company->{Email};
                $return_value_company->{enterprise_info_Seleccionado} = $selected_company->{Seleccionado};
                my $message = "Empresa seleccionada:\n" .
                              "ID: $selected_company->{ID}\n" .
                              "Organizacion: $selected_company->{Organization}\n" .
                              "Contacto: $selected_company->{Contact}\n" .
                              "Email: $selected_company->{Email}";
                herramientas::Complementos::show_alert(
                    $mw, 'Éxito', 
                    $message, 'success'
                );
                $mw->destroy();
            } else {
                herramientas::Complementos::show_alert(
                    $mw, 'Advertencia', 
                    "No se seleccionó ninguna empresa.", 'warning'
                );
            }
        },
        -background => $herramientas::Estilos::next_button_bg,
        -foreground => $herramientas::Estilos::next_button_fg,
        -activebackground => $herramientas::Estilos::next_button_active_bg,
        -activeforeground => $herramientas::Estilos::next_button_active_fg,
        -font => $herramientas::Estilos::next_button_font
    )->pack(-side => 'right', -padx => 10, -pady => 10);

    $mw->waitWindow(); # Esperar a que el usuario seleccione algún botón

    # Function to update the navigation buttons
    sub update_nav_buttons {
        $nav_buttons_frame->packForget();
        $nav_buttons_frame = $mw->Frame(-background => $herramientas::Estilos::mib_selection_bg)->pack(-side => 'top', -fill => 'x');
        $nav_buttons_frame->Button(
            -text => "Inicio",
            -command => sub {
                $current_page = 0;
                populate_table($current_page);
            },
            -background => $herramientas::Estilos::mib_selection_button_bg,
            -foreground => $herramientas::Estilos::mib_selection_button_fg,
            -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
            -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
            -font => $herramientas::Estilos::mib_selection_button_font
        )->pack(-side => 'left', -padx => 5, -pady => 5);

        for my $i (-3 .. 3) {
            my $page = $current_page + $i;
            next if $page < 0 || $page * $page_size >= @filtered_enterprise_hash;
            $nav_buttons_frame->Button(
                -text => $page + 1,
                -command => sub {
                    $current_page = $page;
                    populate_table($current_page);
                },
                -background => $herramientas::Estilos::mib_selection_button_bg,
                -foreground => $herramientas::Estilos::mib_selection_button_fg,
                -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
                -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
                -font => $herramientas::Estilos::mib_selection_button_font
            )->pack(-side => 'left', -padx => 5, -pady => 5);
        }

        $nav_buttons_frame->Button(
            -text => "Final",
            -command => sub {
                $current_page = int(@filtered_enterprise_hash / $page_size);
                populate_table($current_page);
            },
            -background => $herramientas::Estilos::mib_selection_button_bg,
            -foreground => $herramientas::Estilos::mib_selection_button_fg,
            -activebackground => $herramientas::Estilos::mib_selection_button_active_bg,
            -activeforeground => $herramientas::Estilos::mib_selection_button_active_fg,
            -font => $herramientas::Estilos::mib_selection_button_font
        )->pack(-side => 'left', -padx => 5, -pady => 5);
    }


    # Function to populate the data panel with rows
    sub populate_table {
        my ($page) = @_;
        $result_table_pane->packForget();
        $result_table_pane = $table_frame->Scrolled('Pane', -scrollbars => 'osoe', -bg => $herramientas::Estilos::forest_shadow)->pack(-side => 'top', -fill => 'both', -expand => 1);
        my $start = $page * $page_size;
        my $end = $start + $page_size - 1;
        $end = $#filtered_enterprise_hash if $end > $#filtered_enterprise_hash;
        for my $i ($start .. $end) {
            my $row = $filtered_enterprise_hash[$i];
            my $row_frame = $result_table_pane->Frame(-background => $herramientas::Estilos::table_row_bg)->pack(-side => 'top', -fill => 'x');
            foreach my $key (qw(ID Organization Contact Email)) {
                $row_frame->Label(
                    -text => $row->{$key},
                    -background => $herramientas::Estilos::table_row_bg,
                    -foreground => $herramientas::Estilos::table_fg,
                    -font => $herramientas::Estilos::table_font
                )->pack(-side => 'left', -fill => 'x', -expand => 1);
            }
            my $checkbutton = $row_frame->Checkbutton(
                -variable => \$row->{Seleccionado},
                -background => $herramientas::Estilos::table_row_bg,
                -foreground => $herramientas::Estilos::table_fg,
                -font => $herramientas::Estilos::table_font,
            )->pack(-side => 'left', -fill => 'x', -expand => 1);
        }
        update_nav_buttons();
    }
    return $return_value_company;
}

# Subroutine to extract enterprise data from file
sub extraer_datos_empresas {
    my $file_path = Rutas::id_empresa_path();
    my @enterprise_data;

    # Read enterprise data from file
    open my $fh, '<', $file_path or do {
        warn "No se pudo abrir el archivo $file_path: $!";
        return;
    };
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^\s*$/ || $line =~ /^Decimal/; # Skip empty lines and header
        push @enterprise_data, $line;
    }
    close $fh;

    # Convert enterprise data to hash
    my @enterprise_hash;
    for (my $i = 0; $i < @enterprise_data; $i += 4) {
        push @enterprise_hash, {
            ID => $enterprise_data[$i],
            Organization => $enterprise_data[$i + 1],
            Contact => $enterprise_data[$i + 2],
            Email => $enterprise_data[$i + 3],
            Seleccionado => 0
        };
    }

    return @enterprise_hash;
}

1;