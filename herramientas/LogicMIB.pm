package LogicMIB;

use strict;
use warnings;

# Añadir la carpeta donde se encuentran los modulos
use lib $FindBin::Bin . "/herramientas";
use lib $FindBin::Bin . "./Script Generacion de Agentes SNMP/utilidades";


use SNMP::MIB::Compiler;

# Ventanas secundarias
use MIB_utils;

use Data::Dumper; # Importar el modulo Data::Dumper

use File::Path qw(make_path rmtree);
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
    my ($ventana_principal, $result_table_pane, $mib_tree_pane, $buscar_ext_mib, $buscar_ext_txt) = @_;
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
        my $relative_path = File::Spec->abs2rel($file);
        $mib_tree_pane->Label(-text => $relative_path, -bg => $herramientas::Estilos::twilight_grey)->pack(-side => 'top', -anchor => 'w');
    }

    # Aquí se puede agregar la logica para utilizar los archivos MIB en otro proceso
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
            # Verificar nuevamente si los modulos importados estan disponibles
            foreach my $import (@imports) {
                # Cambiar el valor de $is_valid si se encontro el modulo
                $is_valid = 1;
                unless (grep { $_ eq $import } @available_modules) {
                    $is_valid = 0;
                }
            }
            if (!$is_valid) {
                herramientas::Complementos::show_alert(
                    $ventana_principal, 'ERROR', 
                    "Error: Los siguientes modulos no estan disponibles: $missing_imports\narchivo: $relative_path", 'error'
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
            if ($entry =~ /\.$extension$/) {
                push @additional_files, File::Spec->catfile($dir, $entry);
            }
        }
        closedir($dh);
    }

    return @additional_files;
}
1;