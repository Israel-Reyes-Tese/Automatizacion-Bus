package LogicMIB;

use strict;
use warnings;
use Carp;

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
    my %mib_files_extras;

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
        #print "Buscar archivos sin extension\n";
        push @selected_files, buscar_archivos_por_extension(\@selected_files, '');
    }

    # Guardar los archivos seleccionados en un hash para eliminar duplicados
    foreach my $file (@selected_files) {
        $mib_files{abs_path($file)} = 1;
    }
    
    #print "Archivos seleccionados: ", Dumper(\%mib_files);
    # Validar los archivos MIB
    foreach my $file (keys %mib_files) {
        unless (validar_mib($file, $ventana_principal)) {
            warn "Archivo MIB no valido: $file";
            next;
        }
        my ($is_valid, $mib_files_extras_hash) = validar_importaciones($file, \%mib_files, $ventana_principal);
        %mib_files_extras = (%mib_files_extras, %$mib_files_extras_hash);
        unless ($is_valid) {
            warn "Importaciones no validas en el archivo MIB: $file";
            next;
        }
    }

    # Fusionar los archivos extras seleccionados con los archivos seleccionados
    %mib_files = (%mib_files, %mib_files_extras);
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
    my $temp_file_all_object_identities = Rutas::temp_files_logs_objects_mibs_path(). '/(Registros)_Object_Identities.logs';
    $temp_file_all_object_identities = validar_o_crear_archivo_temporal($temp_file_all_object_identities);
    foreach my $file (keys %mib_files) {
        # Extraer OBJECT-IDENTITY y añadir al hash object_identities
        my $extracted_object_identities = extraer_object_identities($file, $temp_file_all_object_identities);
        @object_identities{keys %$extracted_object_identities} = values %$extracted_object_identities;
    }
    # Escribir los datos en el archivo temporal con el tipo OBJECT_IDENTITIES
    escribir_datos_en_archivo($temp_file_all_object_identities, \%object_identities, "OBJECT_IDENTITIES", 1);
    # Datos OBJECT-TYPE
    my %object_types;
    my $temp_file_all_object_types = Rutas::temp_files_logs_objects_mibs_path(). '/(Registros)_Object_Types.logs';
    $temp_file_all_object_types = validar_o_crear_archivo_temporal($temp_file_all_object_types);
    foreach my $file (keys %mib_files) {
        # Extraer OBJECT-TYPE y añadir al hash object_types
        
        my $extracted_object_types = extraer_object_types($file, $temp_file_all_object_types);
        @object_types{keys %$extracted_object_types} = values %$extracted_object_types;
    }
    # Escribir los datos en el archivo temporal con el tipo OBJECT_TYPES
    escribir_datos_en_archivo($temp_file_all_object_types, \%object_types, "OBJECT_TYPES", 1);
    # Datos OBJECT IDENTIFIER
    my %object_identifiers;
    # Archivo temporal que almacenará todos los OBJECT IDENTIFIER encontrados
    my $temp_file_all_object_identifiers = Rutas::temp_files_logs_objects_mibs_path(). '/(Registros)_Object_Identifiers.logs';
    $temp_file_all_object_identifiers = validar_o_crear_archivo_temporal($temp_file_all_object_identifiers);
    foreach my $file (keys %mib_files) {
        # Extraer OBJECT IDENTIFIER y añadir al hash object_identifiers
        my $extracted_object_identifiers = extraer_object_identifiers($file, $temp_file_all_object_identifiers);
        @object_identifiers{keys %$extracted_object_identifiers} = values %$extracted_object_identifiers;
    }
    # Escribir los datos en el archivo temporal con el tipo OBJECT_IDENTIFIERS
    escribir_datos_en_archivo($temp_file_all_object_identifiers, \%object_identifiers, "OBJECT_IDENTIFIERS", 1);
    # Datos TEXTUAL CONVENTION
    my %textual_conventions;
    # Archivo temporal que almacenará todos los TEXTUAL CONVENTION encontrados
    my $temp_file_all_textual_conventions = Rutas::temp_files_logs_objects_mibs_path(). '/(Registros)_Textual_Conventions.logs';
    $temp_file_all_textual_conventions = validar_o_crear_archivo_temporal($temp_file_all_textual_conventions);
    foreach my $file (keys %mib_files) {
        # Extraer TEXTUAL CONVENTION y añadir al hash textual_conventions
        my $extracted_textual_conventions = extraer_textual_conventions($file, $temp_file_all_textual_conventions);
        @textual_conventions{keys %$extracted_textual_conventions} = values %$extracted_textual_conventions;
    }
    # Escribir los datos en el archivo temporal con el tipo TEXTUAL_CONVENTIONS
    escribir_datos_en_archivo($temp_file_all_textual_conventions, \%textual_conventions, "TEXTUAL_CONVENTIONS", 1);
    # Datos MODULE-IDENTITY
    my %module_identities;
    # Archivo temporal que almacenará todos los MODULE-IDENTITY encontrados
    my $temp_file_all_module_identities = Rutas::temp_files_logs_objects_mibs_path(). '/(Registros)_Module_Identities.logs';
    $temp_file_all_module_identities = validar_o_crear_archivo_temporal($temp_file_all_module_identities);
    foreach my $file (keys %mib_files) {
        # Extraer MODULE-IDENTITY y añadir al hash module_identities
        my $extracted_module_identities = extraer_module_identities($file, $temp_file_all_module_identities);
        @module_identities{keys %$extracted_module_identities} = values %$extracted_module_identities;
    }
    # Escribir los datos en el archivo temporal con el tipo MODULE_IDENTITIES
    escribir_datos_en_archivo($temp_file_all_module_identities, \%module_identities, "MODULE_IDENTITIES", 1);
    # Datos MODULE-COMPLIANCE
    my %module_compliances;
    # Archivo temporal que almacenará todos los MODULE-COMPLIANCE encontrados
    my $temp_file_all_module_compliances = Rutas::temp_files_logs_objects_mibs_path(). '/(Registros)_Module_Compliances.logs';
    $temp_file_all_module_compliances = validar_o_crear_archivo_temporal($temp_file_all_module_compliances);
    foreach my $file (keys %mib_files) {
        # Extraer MODULE-COMPLIANCE y añadir al hash module_compliances
        my $extracted_module_compliances = extraer_module_compliance($file, $temp_file_all_module_compliances);
        @module_compliances{keys %$extracted_module_compliances} = values %$extracted_module_compliances;
    }
    # Escribir los datos en el archivo temporal con el tipo MODULE_COMPLIANCES
    escribir_datos_en_archivo($temp_file_all_module_compliances, \%module_compliances, "MODULE_COMPLIANCE", 1);
    # Datos de las alarmas OBJECT-GROUP
    my %alarm_object_groups;
    # Archivo temporal que almacenará todas las alarmas OBJECT-GROUP encontradas
    my $temp_file_all_alarm_object_groups = Rutas::temp_files_logs_objects_mibs_path(). '/(Registros)_Alarmas_Object_Group.logs';
    $temp_file_all_alarm_object_groups = validar_o_crear_archivo_temporal($temp_file_all_alarm_object_groups);
    foreach my $file (keys %mib_files) {
        # Extraer OBJECT-GROUP y añadir al hash alarm_object_groups
        my $extracted_alarm_object_groups = extraer_objects_status_description($file, $temp_file_all_alarm_object_groups, "OBJECT-GROUP");
        @alarm_object_groups{keys %$extracted_alarm_object_groups} = values %$extracted_alarm_object_groups;
    }
    # Escribir los datos en el archivo temporal con el tipo OBJECT_GROUPS
    escribir_datos_en_archivo($temp_file_all_alarm_object_groups, \%alarm_object_groups, "OBJECT_GROUPS", 1);
    # Datos de las alarmas NOTIFICATION-GROUP
    my %alarm_notification_groups;
    # Archivo temporal que almacenará todas las alarmas NOTIFICATION-GROUP encontradas
    my $temp_file_all_alarm_notification_groups = Rutas::temp_files_logs_objects_mibs_path(). '/(Registros)_Alarmas_Notification_Group.logs';
    $temp_file_all_alarm_notification_groups = validar_o_crear_archivo_temporal($temp_file_all_alarm_notification_groups);
    foreach my $file (keys %mib_files) {
        # Extraer NOTIFICATION-GROUP y añadir al hash alarm_notification_groups
        my $extracted_alarm_notification_groups = extraer_objects_status_description($file, $temp_file_all_alarm_notification_groups, "NOTIFICATION-GROUP");
        @alarm_notification_groups{keys %$extracted_alarm_notification_groups} = values %$extracted_alarm_notification_groups;
    }
    # Escribir los datos en el archivo temporal con el tipo NOTIFICATION_GROUPS
    escribir_datos_en_archivo($temp_file_all_alarm_notification_groups, \%alarm_notification_groups, "NOTIFICATION_GROUPS", 1);
    # Datos de las alarmas NOTIFICATION-TYPE o TRAP-TYPE
    my %alarm_traps;
    # Archivo temporal que almacenará todas las alaramas encontras concatenadas
    my $temp_file_all_alarm_traps = Rutas::temp_files_logs_objects_mibs_path(). '/(Registros)_Alarmas.logs';
    $temp_file_all_alarm_traps = validar_o_crear_archivo_temporal($temp_file_all_alarm_traps);
    foreach my $file (keys %mib_files) {
        # Extraer OBJECT-TYPE y añadir al hash object_types
        my $extracted_alarm_traps = extraer_objects_status_description($file, $temp_file_all_alarm_traps, "ALARM");
        @alarm_traps{keys %$extracted_alarm_traps} = values %$extracted_alarm_traps;
    }
    # Escribir los datos en el archivo temporal con el tipo NOTIFICATION_TYPES_OR_TRAP_TYPES
    escribir_datos_en_archivo($temp_file_all_alarm_traps, \%alarm_traps, "NOTIFICATION_TYPES_OR_TRAP_TYPES", 1);

    #print Dumper(\%alarm_traps);
    # Extract OID nodes
    my $oid_nodes = extraer_nodos_oid(\%mib_files, $ventana_principal);
    # Validar si existe y tiene la información de la empresa
    if (!$oid_nodes || !%$oid_nodes) {
        # Logica para crear una ventana emergente para ingresar el OID de la empresa
        $oid_nodes = mostrar_ventana_seleccion_empresa($ventana_principal);
    }
    my $response = herramientas::Complementos::create_alert_with_picture_label_and_button(
        $ventana_principal, 'Advertencias', 
        "Deseas visualizar la informacion extraida?", 'question'
    );
    # Juntar todos los datos extraidos en un solo hash
    my %data = (
        OBJECT_IDENTITIES => \%object_identities,
        OBJECT_TYPES => \%object_types,
        OBJECT_IDENTIFIERS => \%object_identifiers,
        MODULE_IDENTITIES => \%module_identities,
        MODULE_COMPLIANCE => \%module_compliances,
        ALARM_TRAPS => \%alarm_traps,
        OID_NODES => $oid_nodes,
    );
    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_logs_objects_mibs_path(). '/mibs_objects.logs';
    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    escribir_datos_en_archivo($temp_file, \%data, "OBJECTS_INFO");
    # Construir el árbol de MIBs
    my ($arbol_mibs_principales, $arbol_mibs_secundarias) = construir_arbol_mibs(\%data, $oid_nodes);
    # Extraer las cabeceras dinámicamente para la tabla principal
    my %cabeceras_principales;
    foreach my $key (keys %$arbol_mibs_principales) {
        my $entry = $arbol_mibs_principales->{$key};
        @cabeceras_principales{keys %$entry} = values %$entry;
    }
    # Extraer las cabeceras dinámicamente para la tabla secundaria
    my %cabeceras_secundarias;
    foreach my $key (keys %$arbol_mibs_secundarias) {
        my $entry = $arbol_mibs_secundarias->{$key};
        @cabeceras_secundarias{keys %$entry} = values %$entry;
    }
    # Convertir las cabeceras a una lista y agregar ID y Nombre
    my @cabeceras_principales = (qw(ID Nombre), keys %cabeceras_principales);
    my @cabeceras_secundarias = (qw(ID Nombre), keys %cabeceras_secundarias);

    my @data_principal = (
         \@cabeceras_principales,
    );
    # Datos iniciales para la tabla secundaria
    my @data_secundaria = (
        \@cabeceras_secundarias,
    );
    # Transformar el árbol principal
    my $id_principal = 1;
    foreach my $key (keys %$arbol_mibs_principales) {
        my $entry = $arbol_mibs_principales->{$key};
        my @row = ($id_principal++, $key);
        foreach my $header (@cabeceras_principales[2..$#cabeceras_principales]) {
            push @row, $entry->{$header} // '';
        }
        push @data_principal, \@row;
    }

    # Transformar el árbol secundario
    my $id_secundario = 1;
    foreach my $key (keys %$arbol_mibs_secundarias) {
        my $entry = $arbol_mibs_secundarias->{$key};
        my @row = ($id_secundario++, $key);
        foreach my $header (@cabeceras_secundarias[2..$#cabeceras_secundarias]) {
            push @row, $entry->{$header} // '';
        }
        push @data_secundaria, \@row;
    }

    if ($response) {
        my @search_fields = ('enterprise_info_ID', 'enterprise_file', 'enterprise_info_Contact',
        'enterprise_info_Seleccionado', 'enterprise_oid', 'enterprise_info_Email', 'private_enterprises_oid', 'root_oid',
        'enterprise_info_Organization', 'STATUS', 'MAX-ACCESS', 'SYNTAX', 'DESCRIPTION', 'OID', 'ARCHIVO', 'TYPE'); # Campos en los que se realizará la búsqueda
        my @header_fields = ("Nodos OID", "Alarmas", "Módulos", "Objetos", "Identificadores de Objetos", "Identidades de Módulos", "Alarmas", "OID de la Empresa", "Empresa", "Contacto", "Email", "Organización", "Archivo", "Tipo", "OID", "Descripción", "Sintaxis", "Acceso Máximo", "Estado");
        my $records_per_page = 20;
        herramientas::Complementos::create_table($ventana_principal, $records_per_page, \%data, \@search_fields, \@header_fields);    
    }
        my $records_per_page = 20;

    my ($selected_data_principal, $selected_data_secundaria) = herramientas::Complementos::create_table_doble_data($ventana_principal, $records_per_page, \@data_principal, \@data_secundaria);


    return ($selected_data_principal, $selected_data_secundaria);
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
    my @mib_files_extras;
    my %mib_files_extras_hash;
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
            my @local_modules = buscar_modulos_localmente(1);
            @mib_files_extras = @missing_imports;
            @available_modules = (@available_modules, @local_modules);
            # Eliminar los modulos encontrados de missing_imports
            @missing_imports = grep { my $import = $_; !grep { $_ eq $import } @available_modules } @missing_imports;
            # Añadis los modulos encontrados a mib_files_extras
            @local_modules = buscar_modulos_localmente(0);
            # Comparar los modulos faltantes con los mib files extras y validar que eston no se en encuentren en modulos faltantes
            @mib_files_extras = grep { my $import = $_; !grep { $_ eq $import } @missing_imports } @mib_files_extras;
            # Retornar los nombres originales de los modulos mib files extras - con sus modulos locales 
            @mib_files_extras = map { my $import = $_; grep { lc($_) =~ /\\$import$/i } @local_modules } @mib_files_extras;            
            
            # Crear un hash con los modulos extras
            @mib_files_extras_hash{@mib_files_extras} = 1;

            if (@missing_imports) {
                herramientas::Complementos::show_alert(
                    $ventana_principal, 'ERROR', 
                    "Error: Los siguientes modulos no estan disponibles: " . join(',y ', @missing_imports) . "\narchivo: $relative_path", 'error'
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

    #print "Mib files extras: ", Dumper(\%mib_files_extras_hash);
    return ($is_valid, \%mib_files_extras_hash);
}

# Funcion para buscar modulos localmente en las rutas especificadas
sub buscar_modulos_localmente {
    my ($reformatear) = @_;
    my @local_modules;
    my @paths = (Rutas::mib_module_v1_path(), Rutas::mib_module_v2_path());

    foreach my $path (@paths) {
        opendir(my $dh, $path) or do {
            warn "No se pudo abrir el directorio $path: $!";
            next;
        };

        while (my $entry = readdir($dh)) {
            next if $entry =~ /^\./; # Ignorar archivos ocultos
            if ($reformatear) {
                push @local_modules, lc($entry =~ s/\.[^.]+$//r);
            } else {
                # Añadir la ruta completa del archivo
            
                push @local_modules, File::Spec->catfile($path, $entry);
            }
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

# Función principal para extraer OBJECT-TYPE y devolver el archivo sin estos segmentos
sub extraer_y_eliminar_object_archivo_temporal {
    my ($file) = @_;

    eliminar_lineas($file, "--");

    # Escribir el archivo sin los segmentos de OBJECT-TYPE
    eliminar_object_types($file);
    
    eliminar_module_compliance($file);

    eliminar_object_group($file);
    eliminar_notification_group($file);

    eliminar_textual_convention($file);

    # Eliminar lineas específicas


    return $file;
}

# Función para eliminar lineas que contengan un término específico de un archivo MIB 
sub eliminar_lineas {
    my ($file, $termino) = @_;

    open my $fh, '<', $file or croak "Error al abrir el archivo $file: $!";
    my @lines = <$fh>;
    close $fh or croak "Error al cerrar el archivo $file: $!";

    my @filtered_lines;

    foreach my $line (@lines) {
        if ($line =~ /\Q$termino\E/) {
            next;
        }
        push @filtered_lines, $line;
    }

    open my $fh_out, '>', $file or croak "Error al abrir el archivo $file para escribir: $!";
    print $fh_out @filtered_lines;
    close $fh_out or croak "Error al cerrar el archivo $file: $!";
}

# Función para eliminar los segmentos de OBJECT-TYPE del archivo original
sub eliminar_object_types {
    my ($file) = @_;

    open my $fh, '<', $file or croak "Error al abrir el archivo $file: $!";

    my @lines = <$fh>;
    close $fh or croak "Error al cerrar el archivo $file: $!";

    my @filtered_lines;
    my $in_segment = 0;

    foreach my $line (@lines) {
        if ($line =~ /(\w+)\s+OBJECT-TYPE/) {
            $in_segment = 1;
        }
        elsif ($in_segment) {
            if ($line =~ / }/) {
                $in_segment = 0;
            }
        } else {
            push @filtered_lines, $line;
        }
    }

    open my $fh_out, '>', $file or croak "Error al abrir el archivo $file para escribir: $!";
    print $fh_out @filtered_lines;
    close $fh_out or croak "Error al cerrar el archivo $file: $!";
}

# Función para eliminar los segmentos de MODULE COMPLIANCE del archivo original
sub eliminar_module_compliance {
    my ($file) = @_;

    open my $fh, '<', $file or croak "Error al abrir el archivo $file: $!";

    my @lines = <$fh>;
    close $fh or croak "Error al cerrar el archivo $file: $!";

    my @filtered_lines;
    my $in_segment = 0;

    foreach my $line (@lines) {
        if ($line =~ /(\w+)\s+MODULE-COMPLIANCE/) {
            $in_segment = 1;
        }
        elsif ($in_segment) {
            if ($line =~ /::=/) {
                $in_segment = 0;
            }
        } else {
            push @filtered_lines, $line;
        }
    }

    open my $fh_out, '>', $file or croak "Error al abrir el archivo $file para escribir: $!";
    print $fh_out @filtered_lines;
    close $fh_out or croak "Error al cerrar el archivo $file: $!";
}

# Función para extraer OBJECT-GROUP de un archivo MIB
sub eliminar_object_group {
    my ($file) = @_;

    open my $fh, '<', $file or croak "Error al abrir el archivo $file: $!";

    my @lines = <$fh>;
    close $fh or croak "Error al cerrar el archivo $file: $!";

    my @filtered_lines;
    my $in_segment = 0;

    foreach my $line (@lines) {
        if ($line =~ /(\w+)\s+OBJECT-GROUP/) {
            $in_segment = 1;
        }
        elsif ($in_segment) {
            if ($line =~ /::=/) {
                $in_segment = 0;
            }
        } else {
            push @filtered_lines, $line;
        }
    }

    open my $fh_out, '>', $file or croak "Error al abrir el archivo $file para escribir: $!";
    print $fh_out @filtered_lines;
    close $fh_out or croak "Error al cerrar el archivo $file: $!";
}

# Función para extraer NOTIFICATION-GROUP de un archivo MIB
sub eliminar_notification_group {
    my ($file) = @_;

    open my $fh, '<', $file or croak "Error al abrir el archivo $file: $!";

    my @lines = <$fh>;
    close $fh or croak "Error al cerrar el archivo $file: $!";

    my @filtered_lines;
    my $in_segment = 0;

    foreach my $line (@lines) {
        if ($line =~ /(\w+)\s+NOTIFICATION-GROUP/) {
            $in_segment = 1;
        }
        elsif ($in_segment) {
            if ($line =~ /::=/) {
                $in_segment = 0;
            }
        } else {
            push @filtered_lines, $line;
        }
    }

    open my $fh_out, '>', $file or croak "Error al abrir el archivo $file para escribir: $!";
    print $fh_out @filtered_lines;
    close $fh_out or croak "Error al cerrar el archivo $file: $!";
}

# Función para extraer TEXTUAL-CONVENTION de un archivo MIB
sub eliminar_textual_convention {
    my ($file) = @_;

    open my $fh, '<', $file or croak "Error al abrir el archivo $file: $!";

    my @lines = <$fh>;
    close $fh or croak "Error al cerrar el archivo $file: $!";

    my @filtered_lines;
    my $in_segment = 0;

    foreach my $line (@lines) {
        if ($line =~ /(\w+)\s+TEXTUAL-CONVENTION/) {
            $in_segment = 1;
        }
        elsif ($in_segment) {
            if ($line =~ / \ }/ || $line =~ /\)/) {
                $in_segment = 0;
            }
        } else {
            push @filtered_lines, $line;
        }
    }

    open my $fh_out, '>', $file or croak "Error al abrir el archivo $file para escribir: $!";
    print $fh_out @filtered_lines;
    close $fh_out or croak "Error al cerrar el archivo $file: $!";
}

# Función para extraer OBJECT-IDENTITY de un archivo MIB
sub extraer_object_identities {
    my ($file, $temp_file_all) = @_;

    my $original_file = $file;

    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_path() . '/(Reformato)_Object_Identities.txt';

    $file = transformar_mib_a_txt($file);
    # Validar si el archivo temporal existe, si no, crearlo
    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    # Recondicionar el archivo temporal copiando el contenido de $file
    $temp_file = recondicionar_archivo_temporal($file, $temp_file, $original_file); 

    open my $fh, '<', $temp_file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return;
    };

    open my $fh_all, '>>', $temp_file_all or do {
        warn "No se pudo abrir el archivo $temp_file_all: $!";
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
            print $fh_all "#----------------------------------- OBJECT IDENTITY:  $current_object  ---------------------------#\n";
            print $fh_all "Archivo: $nombre_archivo\n";
            print $fh_all "Nombre objeto: $current_object\n";
            print $fh_all "$_\n";
            print $fh_all "#----------------------------------- FIN OBJECT IDENTITY ---------------------------#\n";
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
    return \%object_identities;
}
# Función para extraer OBJECT-TYPE de un archivo MIB
sub extraer_object_types {
    my ($file, $temp_file_all) = @_;
    my $original_file = $file;
    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_path() . '/(Reformato)_Object_Types.txt';
    $file = transformar_mib_a_txt($file);
    # Validar si el archivo temporal existe, si no, crearlo
    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    # Recondicionar el archivo temporal copiando el contenido de $file
    $temp_file = recondicionar_archivo_temporal($file, $temp_file, $original_file); 

    open my $fh, '<', $temp_file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return;
    };
    
    open my $fh_all, '>>', $temp_file_all or do {
        warn "No se pudo abrir el archivo $temp_file_all: $!";
        return;
    };

    my %object_types;
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
        if (/(\S+)\s+OBJECT-TYPE/) {
            next if /OBJECT-TYPE\s*,/;
            $current_object = $1;
            $in_segment = 1;
            $segment = $_ . "\n"; # Incluir la línea actual en el segmento
            print $fh_all "#----------------------------------- OBJECT TYPE:  $current_object  ---------------------------#\n";
            print $fh_all "Archivo: $nombre_archivo\n";
            print $fh_all "Nombre objeto: $current_object\n";
            next;
        }
        # Continuar extrayendo líneas hasta encontrar "}"
        if ($in_segment) {
            $segment .= $_ . "\n";

            if (/::= { /) {
                print $fh_all "$segment\n";

                my ($syntax) = $segment =~ /SYNTAX\s+(.*)/;
                my ($max_access) = $segment =~ /MAX-ACCESS\s+(.*)/;
                my ($status) = $segment =~ /STATUS\s+(.*)/;
                my ($description) = $segment =~ /DESCRIPTION\s+"(.*?)"/s;
                my ($index) = $segment =~ /INDEX\s+\{(.*)\}/;
                my ($oid) = $segment =~ /::=\s*{([^}]+)}/;

                $object_types{$current_object} = {
                    TYPE => 'OBJECT-TYPE',
                    SYNTAX => $syntax // 'SYNTAX no encontrado',
                    MAX_ACCESS => $max_access // 'MAX-ACCESS no encontrado',
                    STATUS => $status // 'STATUS no encontrado',
                    DESCRIPTION => $description // 'DESCRIPCION no encontrada',
                    INDEX => $index // 'INDEX no encontrado',
                    OID => $oid // 'OID no encontrado',
                    ARCHIVO => $nombre_archivo // 'ARCHIVO no encontrado',
                };
                $in_segment = 0;
                $segment = '';
            }
        }
    }
    close $fh or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    close $fh_all or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    return \%object_types;
}

# Función para extraer TEXTUAL-CONVENTION de un archivo MIB
sub extraer_textual_conventions {
    my ($file, $temp_file_all) = @_;
    my $original_file = $file;
    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_path() . '/(Reformato)_Textual_Conventions.txt';
    $file = transformar_mib_a_txt($file);
    # Validar si el archivo temporal existe, si no, crearlo
    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    # Recondicionar el archivo temporal copiando el contenido de $file
    $temp_file = recondicionar_archivo_temporal($file, $temp_file, $original_file); 

    open my $fh, '<', $temp_file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return;
    };
    
    open my $fh_all, '>>', $temp_file_all or do {
        warn "No se pudo abrir el archivo $temp_file_all: $!";
        return;
    };

    my %textual_conventions;
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
        if (/(\S+)\s+::= TEXTUAL-CONVENTION/) {
            next if /TEXTUAL-CONVENTION\s*,/;
            $current_object = $1;
            $in_segment = 1;
            $segment = $_ . "\n"; # Incluir la línea actual en el segmento
            print $fh_all "#----------------------------------- TEXTUAL-CONVENTION:  $current_object  ---------------------------#\n";
            print $fh_all "Archivo: $nombre_archivo\n";
            print $fh_all "Nombre objeto: $current_object\n";
            next;
        }
        # Continuar extrayendo líneas hasta encontrar "SYNTAX"
        if ($in_segment) {
            $segment .= $_ . "\n";
            if (/SYNTAX\s+/) {
                my $syntax = $_;
                while (<$fh>) {
                    chomp;
                    $segment .= $_ . "\n";
                    $syntax .= $_;
                    last if /\ }/|| /\)/;
                }
                print $fh_all "$segment\n";

                my ($status) = $segment =~ /STATUS\s+(.*)/;
                my ($description) = $segment =~ /DESCRIPTION\s+"(.*?)"/s;
                my ($syntax_object) = $segment =~ /SYNTAX\s+(.*)/;

                $textual_conventions{$current_object} = {
                    TYPE => 'TEXTUAL-CONVENTION',
                    STATUS => $status // 'STATUS no encontrado',
                    DESCRIPTION => $description // 'DESCRIPCION no encontrada',
                    SYNTAX => $syntax_object // 'SYNTAX no encontrado',
                    ARCHIVO => $nombre_archivo // 'ARCHIVO no encontrado',
                };
                $in_segment = 0;
                $segment = '';
            }
        }
    }
    close $fh or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    close $fh_all or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    return \%textual_conventions;
}
# Función para extraer OBJECT IDENTIFIER de un archivo MIB
sub extraer_object_identifiers {
    my ($file, $temp_file_all) = @_;
    my $original_file = $file;
    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_path() . '/(Reformato)_Object_Identifiers.txt';
    # Validar si el archivo temporal existe, si no, crearlo
    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    # Recondicionar el archivo temporal copiando el contenido de $file
    $temp_file = recondicionar_archivo_temporal($file, $temp_file, $original_file); 
    $temp_file = extraer_y_eliminar_object_archivo_temporal($temp_file);

    open my $fh, '<', $temp_file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return;
    };

    open my $fh_all, '>>', $temp_file_all or do {
        warn "No se pudo abrir el archivo $temp_file_all: $!";
        return;
    };

    my %object_identifiers;
    my $current_oid = '';
    my $nombre_archivo = '';

    my $current_object = '';
    my $segment = '';
    my $in_segment = 0;

    while (<$fh>) {
        chomp;
        next if /OBJECT IDENTIFIER\s*,/;
        # Extraer la primera línea del archivo que es el nombre del archivo original y guardarlo en el hash
        if (/Archivo original:\s+(.*)/) {
            $nombre_archivo = $1;
        }
        if (/(\w+)\s+OBJECT IDENTIFIER\s*::=\s*\{[^}]+\}/ || /(\w+)\s+OBJECT IDENTIFIER\s*$/ || /(\w+)\s+OBJECT IDENTIFIER\s*::=\s*$/ || /(\S+)\s+OBJECT IDENTIFIER/) {
            my $segment = "$_";
            my $include_segment = 1;
            while (<$fh>) {
                chomp;
                $segment .= "\n$_";
                last if /::=\s*{[^}]+}\s*$/;
            }
            if ($include_segment) {
                print $fh_all "Archivo: $nombre_archivo\n";
                print $fh_all "$segment\n";
            }
        }
    }
    close $fh or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    close $fh_all or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    # 2DO Filtro
    open $fh_all, '<', $temp_file_all or do {
        warn "No se pudo abrir el archivo $temp_file_all: $!";
        return;
    };
    # Logica para eliminar datos innecesarios
    while (<$fh_all>) {
        chomp;
        # Extraer los elementos que cumplan con la condición
        if (/(\S+)\s+OBJECT\s+IDENTIFIER\s*::=\s*\{/) {
            $current_object = $1;
            $in_segment = 1;
            $segment = $_ . "\n"; # Incluir la línea actual en el segmento
            if (/}/) {
                my ($oid) = $segment =~ /::=\s*{([^}]+)}/;
                $object_identifiers{$current_object} = {
                    TYPE => 'OBJECT IDENTIFIER',
                    OID => $oid // 'OID no encontrado',
                    ARCHIVO => $nombre_archivo,
                    Nivel_Busqueda => 1,
                };
                $in_segment = 0;
                $segment = '';
            }
            next;
        } elsif (/(\S+)\s+OBJECT IDENTIFIER\s*$/){
            $current_object = $1;
            $in_segment = 1;
            $segment = $_ . "\n"; # Incluir la línea actual en el segmento
        } elsif (/(\S+)\s+OBJECT IDENTIFIER\s*::=\s*$/){
            $current_object = $1;
            $in_segment = 1;
            $segment = $_ . "\n"; # Incluir la línea actual en el segmento
        } 
        if ($in_segment) {
                $segment .= $_ . "\n";
                if (/}/) {
                    my ($oid) = $segment =~ /::=\s*{([^}]+)}/;
                    $object_identifiers{$current_object} = {
                        TYPE => 'OBJECT IDENTIFIER',
                        OID => $oid // 'OID no encontrado',
                        ARCHIVO => $nombre_archivo,
                        Nivel_Busqueda => 2,
                    };
                    $in_segment = 0;
                    $segment = '';
                }
            }
    }
    close $fh_all or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    return \%object_identifiers;
}
# Función para extraer MODULE-IDENTITY de un archivo MIB
sub extraer_module_identities {
    my ($file, $temp_file_all) = @_;

    my $original_file = $file;

    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_path() . '/(Reformato)_Module_Identities.txt';

    # Validar si el archivo temporal existe, si no, crearlo
    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    # Recondicionar el archivo temporal copiando el contenido de $file
    $temp_file = recondicionar_archivo_temporal($file, $temp_file, $original_file); 

    open my $fh, '<', $temp_file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return;
    };

    open my $fh_all, '>>', $temp_file_all or do {
        warn "No se pudo abrir el archivo $temp_file_all: $!";
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
            print $fh_all "#----------------------------------- MODULE IDENTITY  $current_object  ---------------------------#\n";
            print $fh_all "Tipo de objeto: MODULE-IDENTITY\n";
            print $fh_all "Nombre del objeto: $current_object\n";
            next;
        }
        # Continuar extrayendo líneas hasta encontrar "}"
        if ($in_segment) {
            $segment .= $_ . "\n";
            if (/}/) {
                print $fh_all "$segment\n";
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
    close $fh_all or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";

    return \%module_identities;
}
# Función para extraer MODULE-COMPLIANCE de un archivo MIB
sub extraer_module_compliance {
    my ($file, $temp_file_all) = @_;

    my $original_file = $file;

    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_path() . '/(Reformato)_Module_Compliance.txt';

    # Validar si el archivo temporal existe, si no, crearlo
    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    # Recondicionar el archivo temporal copiando el contenido de $file
    $temp_file = recondicionar_archivo_temporal($file, $temp_file, $original_file); 

    open my $fh, '<', $temp_file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return;
    };

    open my $fh_all, '>>', $temp_file_all or do {
        warn "No se pudo abrir el archivo $temp_file_all: $!";
        return;
    };

    my %module_compliance;
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
        if (/(\S+)\s+MODULE-COMPLIANCE/) {
            $current_object = $1;
            $in_segment = 1;
            $segment = $_ . "\n"; # Incluir la línea actual en el segmento
            print $fh_all "#----------------------------------- MODULE COMPLIANCE  $current_object  ---------------------------#\n";
            print $fh_all "Tipo de objeto: MODULE-COMPLIANCE\n";
            print $fh_all "Nombre del objeto: $current_object\n";
            next;
        }
        # Continuar extrayendo líneas hasta encontrar "::="
        if ($in_segment) {
            $segment .= $_ . "\n";
            if (/::=/) {
                print $fh_all "$segment\n";
                # Logica para extraer los datos de MODULE-COMPLIANCE
                my ($status) = $segment =~ /STATUS\s+(\S+)/;
                my ($description) = $segment =~ /DESCRIPTION\s+"(.*?)"/s;
                my ($oid) = $segment =~ /::=\s*{([^}]+)}/;

                my %module_data;
                $module_data{STATUS} = $status;
                $module_data{DESCRIPTION} = $description;
                $module_data{OID} = $oid;
                $module_data{ARCHIVO} = $nombre_archivo;
                $module_data{TYPE} = 'MODULE-COMPLIANCE';

                if ($segment =~ /MODULE\s*--\s*this\s*module(.*?)::=/s) {
                    my $module_segment = $1;
                    my @groups;
                    my @objects;

                    while ($module_segment =~ /GROUP\s+(\S+)\s+DESCRIPTION\s+"(.*?)"/sg) {
                        push @groups, { GROUP => $1, DESCRIPTION => $2 };
                    }

                    while ($module_segment =~ /OBJECT\s+(\S+)\s+(?:SYNTAX\s+(\S+)\s+)?MIN-ACCESS\s+(\S+)\s+DESCRIPTION\s+"(.*?)"/sg) {
                        push @objects, { OBJECT => $1, SYNTAX => $2, MIN_ACCESS => $3, DESCRIPTION => $4 };
                    }

                    $module_data{MODULE} = {
                        GROUPS => \@groups,
                        OBJECTS => \@objects,
                    };
                }

                $module_compliance{$current_object} = \%module_data;
            }
        }
    }

    close $fh or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    close $fh_all or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    return \%module_compliance;
}
# Función para extraer la información de los traps de las alarmas
sub extraer_objects_status_description {
    my ($file, $temp_file_all, $type) = @_;
    
    my $original_file = $file;

    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_path() . "/(Reformato)_${type}.txt";
    # Validar si el archivo temporal existe, si no, crearlo
    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    # Recondicionar el archivo temporal copiando el contenido de $file
    $temp_file = recondicionar_archivo_temporal($file, $temp_file, $original_file); 


    open my $fh, '<', $temp_file or do {
        warn "No se pudo abrir el archivo $file: $!";
        return;
    };

    open my $fh_all, '>>', $temp_file_all or do {
        warn "No se pudo abrir el archivo $temp_file_all: $!";
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
        if ($type eq 'ALARM') {
            if (/(\w+)\s+(NOTIFICATION-TYPE|TRAP-TYPE)/) {
                my $segment = "$_"; # Iniciar el segmento con la línea actual
                while (<$fh>) {
                    chomp;
                    $segment .= "\n$_"; # Agregar la línea actual al segmento
                    if ($2 eq 'NOTIFICATION-TYPE') {
                        last if /::=\s*\{.*\}\s*$/; # Terminar el segmento según la expresión complexa
                    } elsif ($2 eq 'TRAP-TYPE') {
                        last if /::=\s*\d+\s*$/;
                    }
                }
                print $fh_all "#----------------------------------- ALARMA ORIGINAL:  $1  ---------------------------#\n";
                print $fh_all "Tipo de alarma: $2\n";
                print $fh_all "Nombre de alarma: $1\n";
                print $fh_all "$segment\n"; # Escribir el segmento en el archivo temporal
                print $fh_all "#----------------------------------- FIN ALARMA ORIGINAL ---------------------------#\n";
            } 
        } elsif ($type eq 'OBJECT-GROUP') {
           if (/(\w+)\s+OBJECT-GROUP/) {
            my $segment = "$_"; # Iniciar el segmento con la línea actual
            while (<$fh>) {
                chomp;
                $segment .= "\n$_"; # Agregar la línea actual al segmento
                last if /::=\s*\{.*\}\s*$/; # Terminar el segmento según la expresión complexa
            }
            print $fh_all "#----------------------------------- OBJECT GROUP:  $1  ---------------------------#\n";
            print $fh_all "Nombre del grupo de objetos: $1\n";
            print $fh_all "$segment\n"; # Escribir el segmento en el archivo temporal
            print $fh_all "#----------------------------------- FIN OBJECT GROUP ---------------------------#\n";
            } 
        } elsif ($type eq 'NOTIFICATION-GROUP') {
            if (/(\w+)\s+NOTIFICATION-GROUP/) {
                my $segment = "$_"; # Iniciar el segmento con la línea actual
                while (<$fh>) {
                    chomp;
                    $segment .= "\n$_"; # Agregar la línea actual al segmento
                    last if /::=\s*\{.*\}\s*$/; # Terminar el segmento según la expresión complexa
                }
                print $fh_all "#----------------------------------- NOTIFICATION GROUP:  $1  ---------------------------#\n";
                print $fh_all "Nombre del grupo de notificaciones: $1\n";
                print $fh_all "$segment\n"; # Escribir el segmento en el archivo temporal
                print $fh_all "#----------------------------------- FIN NOTIFICATION GROUP ---------------------------#\n";
            }
        }
    }
    close $fh or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    close $fh_all or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";
    
    open $fh_all, '<', $temp_file_all or do {
        warn "No se pudo abrir el archivo $temp_file_all: $!";
        return;
    };
    my %data = (
        TYPE => 'Desconocido',
        OBJECTS => 'No se encontraron objetos',
        STATUS => 'No se encontró el estado',
        DESCRIPTION => 'No se encontró la descripción',
        OID => 'No se encontró el OID',
        VARIABLES => 'No se encontraron variables',
        ENTERPRISE => 'No se encontró la empresa',
    );

    # Logica para extraer los datos de las alarmas
  while (<$fh_all>) {
        chomp;
        if (/^#----------------------------------- (?:ALARMA ORIGINAL|OBJECT GROUP|NOTIFICATION GROUP):  (\w+)  ---------------------------#/) {
            $current_alarm = $1;
            $alarm_traps{$current_alarm} = {
                TYPE => 'Desconocido',
                OBJECTS => 'No se encontraron objetos',
                STATUS => 'No se encontró el estado',
                DESCRIPTION => 'No se encontró la descripción',
                OID => 'No se encontró el OID',
                VARIABLES => 'No se encontraron variables',
                ENTERPRISE => 'No se encontró la empresa',
            };
            if ($type eq 'OBJECT-GROUP') {
                $alarm_traps{$current_alarm}->{TYPE} = 'OBJECT-GROUP';
            } elsif ($type eq 'NOTIFICATION-GROUP') {
                $alarm_traps{$current_alarm}->{TYPE} = 'NOTIFICATION-GROUP';
            } 
        } elsif (/^Tipo de alarma: (.+)$/) {
            $alarm_traps{$current_alarm}->{TYPE} = $1;
        } 
        elsif (/^OBJECTS\s*\{\s*(.*)$/) {
            my $objects = $1;
            while ($objects !~ /\}$/) {
                $_ = <$fh_all>;
                chomp;
                $objects .= " $_";
            }
            $objects =~ s/\}$//; # Eliminar la llave de cierre
            $alarm_traps{$current_alarm}->{OBJECTS} = join(', ', split(/\s*,\s*/, $objects));
            $data{OBJECTS} = join(', ', split(/\s*,\s*/, $objects));

        } elsif (/^NOTIFICATIONS\s*\{\s*(.*)$/) {
            my $objects = $1;
            while ($objects !~ /\}$/) {
                $_ = <$fh_all>;
                chomp;
                $objects .= " $_";
            }
            $objects =~ s/\}$//; # Eliminar la llave de cierre
            $alarm_traps{$current_alarm}->{OBJECTS} = join(', ', split(/\s*,\s*/, $objects));
            $data{OBJECTS} = join(', ', split(/\s*,\s*/, $objects));

        } elsif (/^STATUS\s+(.+)$/) {
            $alarm_traps{$current_alarm}->{STATUS} = $1;
            $data{STATUS} = $1;

        } elsif (/^DESCRIPTION\s*"(.*)$/ || /^DESCRIPTION\s*$/) {
            my $description = $1 // '';
            if ($description eq '') {
                $_ = <$fh_all>;
                chomp;
                if (/^"(.*)$/) {
                    $description = $1;
                }
            }
            while ($description !~ /"\s*::=\s*\{.*\}$/) {
                $_ = <$fh_all>;
                chomp;
                $description .= " $_";
            }
            # Extraer el OID de la descripción
            if ($description =~ /"\s*::=\s*\{(.*)\}$/ || $description =~ /"\s*::=\s*(\d+)$/) {
                $alarm_traps{$current_alarm}->{OID} = $1;
                $data{OID} = $1;

            }
            $description =~ s/"\s*::=\s*\{.*\}$//; # Eliminar la parte final
            $alarm_traps{$current_alarm}->{DESCRIPTION} = $description;
            $data{DESCRIPTION} = $description;

        } 
    }
    # Eliminar ::= { contenido } de la descripción y limpiar espacios y caracteres especiales
    foreach my $object (keys %alarm_traps) {
        foreach my $field (qw(TYPE VARIABLES DESCRIPTION ENTERPRISE OID STATUS)) {
            if (exists $alarm_traps{$object}->{$field}) {
                $alarm_traps{$object}->{$field} =~ s/\s*::=\s*\{.*\}//;
                # Eliminar " ::= 
                $alarm_traps{$object}->{$field} =~ s/\s*::=\s*\d+\s*//;
                $alarm_traps{$object}->{$field} =~ s/^\s+|\s+$//g; # Eliminar espacios al inicio y al final
                $alarm_traps{$object}->{$field} =~ s/^["']|["']$//g; # Eliminar caracteres especiales al inicio y al final
            }
        }
    }
    close $fh_all or warn "Advertencia: No se pudo cerrar el archivo correctamente: $!\n";

    return \%alarm_traps;
}

# Function to extract and identify OID nodes
sub extraer_nodos_oid {
    my ($mib_files, $ventana_principal) = @_;
    my $root_oid = "1.3.6.1";
    my $private_enterprises_oid = "4.1";
    my %enterprise_oids;
    my $enterprise_file;

    my @filtered_enterprise_hash = extraer_datos_empresas();

    foreach my $file (keys %$mib_files) {
        open my $fh, '<', $file or do {
            warn "No se pudo abrir el archivo $file: $!";
            next;
        };
        while (my $line = <$fh>) {
            if ($line =~ /::=\s*\{\s*enterprises\s+(\d+)\s*\}/) {
                $enterprise_oids{$1} = $file;
            }
        }
        close $fh;
    }

    unless (%enterprise_oids) {
        warn "No se pudo encontrar el ID único de la empresa o proveedor. Ingréselo manualmente o busque en los archivos locales.";
    }

    my %enterprise_info;
    foreach my $enterprise_oid (keys %enterprise_oids) {
        foreach my $enterprise (@filtered_enterprise_hash) {
            if ($enterprise->{ID} == $enterprise_oid) {
                $enterprise_info{$enterprise_oid} = {
                    enterprise_info_ID => $enterprise->{ID},
                    enterprise_info_Organization => $enterprise->{Organization},
                    enterprise_info_Email => $enterprise->{Email},
                    enterprise_info_Contact => $enterprise->{Contact},
                    enterprise_file => $enterprise_oids{$enterprise_oid},
                    enterprise_oid =>  $enterprise->{ID},
                    root_oid => $root_oid,
                    private_enterprises_oid => $private_enterprises_oid,
                    enterprise_info_Seleccionado => 1,

                };
                last;
            }
        }
        unless ($enterprise_info{$enterprise_oid}) {
            warn "No se encontró el ID en la lista de empresas. Construyendo datos constantes.";
            $enterprise_info{$enterprise_oid} = {
                enterprise_info_ID => $enterprise_oid,
                enterprise_info_Organization => 'Desconocido',
                enterprise_info_Email => '-',
                enterprise_info_Contact => 'Desconocido',
                enterprise_file => $enterprise_oids{$enterprise_oid},
                root_oid => $root_oid,
                private_enterprises_oid => $private_enterprises_oid,
                enterprise_info_Seleccionado => 1,
            };
        }
    }

    if (keys %enterprise_oids > 1) {
        my $selected_oid = herramientas::Complementos::mostrar_ventana_seleccion_empresa_oid($ventana_principal, \%enterprise_info);
        # Comparar la informacion de la empresa seleccionada con la informacion de las empresas
        foreach my $key (keys %enterprise_info) {
            if ($enterprise_info{$key}{'enterprise_info_ID'} == $selected_oid->{'enterprise_info_ID'} || 
                $enterprise_info{$key}{'enterprise_oid'} == $selected_oid->{'enterprise_oid'}) {
                $enterprise_info{$key}{'enterprise_info_Seleccionado'} = 1;
            } else {
                $enterprise_info{$key}{'enterprise_info_Seleccionado'} = 0;
            }
        }
    }
    return \%enterprise_info;
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


    $button_panel->Button(
        -text => "Sin seleccion",
        -command => sub {
        herramientas::Complementos::show_alert(
            $mw, 'Advertencia', 
            "No se selecciono una empresa", 'warning'
        );
            $mw->destroy();
        },
        -background => $herramientas::Estilos::cancel_button_bg,
        -foreground => $herramientas::Estilos::cancel_button_fg,
        -activebackground => $herramientas::Estilos::cancel_button_active_bg,
        -activeforeground => $herramientas::Estilos::cancel_button_active_fg,
        -font => $herramientas::Estilos::cancel_button_font
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

# Función para escribir datos en el archivo temporal
sub escribir_datos_en_archivo {
    my ($temp_file, $data, $tipo, $append) = @_;
    # Validar si tiene valor el parametro append
    $append = 0 unless defined $append;
    my $mode = '>';
    if ($append) {
        $mode = '>>';
    } 
    open my $fh, $mode, $temp_file or die "No se pudo abrir el archivo temporal $temp_file: $!";
    
    if ($tipo eq 'OBJECTS_INFO') {
            escribir_seccion($fh, "OBJECT_IDENTITIES", $data->{OBJECT_IDENTITIES}, "FIN DE OBJECT_IDENTITIES");
            escribir_seccion($fh, "OBJECT_TYPES", $data->{OBJECT_TYPES}, "FIN DE OBJECT_TYPES");
            escribir_seccion($fh, "OBJECT_IDENTIFIERS", $data->{OBJECT_IDENTIFIERS}, "FIN DE OBJECT_IDENTIFIERS");
            escribir_seccion($fh, "MODULE_IDENTITIES", $data->{MODULE_IDENTITIES}, "FIN DE MODULE_IDENTITIES");
            escribir_seccion($fh, "MODULE_COMPLIANCE", $data->{MODULE_COMPLIANCE}, "FIN DE MODULE_COMPLIANCE");
            escribir_seccion($fh, "ALARM_TRAPS", $data->{ALARM_TRAPS}, "FIN DE ALARM_TRAPS");
            escribir_oid_nodes($fh, "OID_NODES", $data->{OID_NODES}, "FIN DE OID_NODES");
    } elsif ($tipo eq 'ALARM_TRAPS') {
            escribir_seccion($fh, "ALARM TRAPS", $data, "FIN DE ALARM_TRAPS");
    } elsif ($tipo eq 'NOTIFICATION_TYPES_OR_TRAP_TYPES') {
        foreach my $key (keys %$data) {
            print $fh "----------------------------------- $key ---------------------------\n";
            print $fh "$key:\n";
            foreach my $field (qw(TYPE OBJECTS STATUS DESCRIPTION OID VARIABLES ENTERPRISE)) {
                if (exists $data->{$key}->{$field}) {

                    print $fh "  $field: $data->{$key}->{$field}\n";
                }
            }
            print $fh "----------------------------------- Final de segmento -----------------------------------\n";
        }
    } elsif ($tipo eq 'OBJECT_GROUPS') {
        foreach my $key (keys %$data) {
            print $fh "----------------------------------- $key ---------------------------\n";
            print $fh "$key:\n";
            foreach my $field (qw(TYPE OBJECTS STATUS DESCRIPTION OID)) {
                if (exists $data->{$key}{$field}) {
                    print $fh "  $field: $data->{$key}{$field}\n";
                }
            }
            print $fh "----------------------------------- Final de segmento -----------------------------------\n";
        }
    }elsif ($tipo eq 'NOTIFICATION_GROUPS') {
        foreach my $key (keys %$data) {
            print $fh "----------------------------------- $key ---------------------------\n";
            print $fh "$key:\n";
            foreach my $field (qw(TYPE OBJECTS STATUS DESCRIPTION OID)) {
                if (exists $data->{$key}{$field}) {
                    print $fh "  $field: $data->{$key}{$field}\n";
                }
            }
            print $fh "----------------------------------- Final de segmento -----------------------------------\n";
        }
    }  elsif ($tipo eq 'OBJECT_IDENTIFIERS') {
        foreach my $key (keys %$data) {
            print $fh "----------------------------------- $key ---------------------------\n";
            print $fh "$key:\n";
            foreach my $field (qw(TYPE ARCHIVO OID Nivel_Busqueda)) {
                if (exists $data->{$key}{$field}) {
                    print $fh "  $field: $data->{$key}{$field}\n";
                }
            }
            print $fh "----------------------------------- Final de segmento -----------------------------------\n";
        }
    } elsif ($tipo eq 'TEXTUAL_CONVENTION') {
        foreach my $key (keys %$data) {
            print $fh "----------------------------------- $key ---------------------------\n";
            print $fh "$key:\n";
            foreach my $field (qw(TYPE STATUS DESCRIPTION SYNTAX ARCHIVO)) {
                if (exists $data->{$key}{$field}) {
                    print $fh "  $field: $data->{$key}{$field}\n";
                }
            }
            print $fh "----------------------------------- Final de segmento -----------------------------------\n";
    }
    }  elsif ($tipo eq 'MODULE_IDENTITIES') {
        foreach my $key (keys %$data) {
            print $fh "----------------------------------- $key ---------------------------\n";
            print $fh "$key:\n";
            foreach my $field (qw(TYPE LAST_UPDATED ORGANIZATION CONTACT_INFO ARCHIVO)) {
                if (exists $data->{$key}{$field}) {
                    print $fh "  $field: $data->{$key}{$field}\n";
                }
            }
            print $fh "----------------------------------- Final de segmento -----------------------------------\n";
        }
    } elsif ($tipo eq 'MODULE_COMPLIANCE') {
        foreach my $key (keys %$data) {
            print $fh "----------------------------------- $key ---------------------------\n";
            print $fh "$key:\n";
            foreach my $field (qw(ARCHIVO OID DESCRIPTION TYPE STATUS)) {
                if (exists $data->{$key}{$field}) {
                    print $fh "  $field: $data->{$key}{$field}\n";
                }
            }
            if (exists $data->{$key}{MODULE}) {
                print $fh "  MODULE:\n";
                if (exists $data->{$key}{MODULE}{GROUPS}) {
                    print $fh "    GROUPS:\n";
                    foreach my $group (@{$data->{$key}{MODULE}{GROUPS}}) {
                        print $fh "      GROUP: $group->{GROUP}\n";
                        print $fh "      DESCRIPTION: $group->{DESCRIPTION}\n";
                    }
                }
                if (exists $data->{$key}{MODULE}{OBJECTS}) {
                    print $fh "    OBJECTS:\n";
                    foreach my $object (@{$data->{$key}{MODULE}{OBJECTS}}) {
                        print $fh "      OBJECT: $object->{OBJECT}\n";
                        print $fh "      SYNTAX: " . ($object->{SYNTAX} // 'undef') . "\n";
                        print $fh "      MIN_ACCESS: $object->{MIN_ACCESS}\n";
                        print $fh "      DESCRIPTION: $object->{DESCRIPTION}\n";
                    }
                }
            }
            print $fh "----------------------------------- Final de segmento -----------------------------------\n";
        }
    }
    
    elsif ($tipo eq 'OBJECT_TYPES') {
        foreach my $key (keys %$data) {
            print $fh "----------------------------------- $key ---------------------------\n";
            print $fh "$key:\n";
            foreach my $field (qw(SYNTAX MAX-ACCESS STATUS DESCRIPTION OID INDEX ARCHIVO)) {
                if (exists $data->{$key}{$field}) {
                    print $fh "  $field: $data->{$key}{$field}\n";
                }
            }
            print $fh "----------------------------------- Final de segmento -----------------------------------\n";
        }
    } elsif ($tipo eq 'OBJECT_IDENTITIES') {
        foreach my $key (keys %$data) {
            print $fh "----------------------------------- $key ---------------------------\n";
            print $fh "$key:\n";
            foreach my $field (qw(TYPE STATUS DESCRIPTION ARCHIVO OID)) {
                if (exists $data->{$key}{$field}) {
                    print $fh "  $field: $data->{$key}{$field}\n";
                }
            }
            print $fh "----------------------------------- Final de segmento -----------------------------------\n";
        }
    } elsif ($tipo eq 'OID_NODES') {
        foreach my $key (keys %$data) {
            print $fh "----------------------------------- $key ---------------------------\n";
            print $fh "$key: $data->{$key}\n";
        }
    }



    close $fh or warn "Advertencia: No se pudo cerrar el archivo temporal $temp_file: $!";
}

# Función para escribir una sección en el archivo
sub escribir_seccion {
    my ($fh, $titulo, $seccion, $pie_pagina) = @_;
    print $fh "----------------------------------- $titulo ---------------------------\n";
    foreach my $key (keys %$seccion) {
        print $fh "$key:\n";
        foreach my $sub_key (keys %{$seccion->{$key}}) {
            print $fh "  $sub_key: $seccion->{$key}{$sub_key}\n";
        }
        print $fh "\n";
    }
    print $fh "----------------------------------- $pie_pagina -----------------------------------\n";
}

# Función para escribir OID_NODES en el archivo
sub escribir_oid_nodes {
    my ($fh, $titulo, $oid_nodes) = @_;
    
    print $fh "----------------------------------- $titulo ---------------------------\n";
    foreach my $key (keys %$oid_nodes) {
        print $fh "$key: $oid_nodes->{$key}\n";
    }
}

# Función para construir el OID completo de un objeto
sub construir_oid_completo {
    my ($nombre, $data, $oid_data) = @_;
    my @oid_parts;
    my @name_parts;
    my $current_name = $nombre;

    while ($current_name) {
        my $found = 0;
        foreach my $type (qw(ALARM_TRAPS OBJECT_IDENTITIES OBJECT_TYPES OBJECT_IDENTIFIERS MODULE_IDENTITIES MODULE_COMPLIANCE)) {
            if (exists $data->{$type}{$current_name}) {
                my $oid_part = $data->{$type}{$current_name}{OID};
                if ($oid_part =~ /^\s*(\S+)\s+(\d+)\s*$/) {
                    my $oid_search = $1;
                    my $oid_number = $2;
                    unshift @oid_parts, $oid_number;
                    unshift @name_parts, $current_name;
                    if ($oid_search =~ /^\d+(\.\d+)*$/) {
                        unshift @oid_parts, split(/\./, $oid_search);
                        unshift @name_parts, split(/\./, $oid_search);
                        $current_name = undef;
                    } else {
                        $current_name = $oid_search;
                    }
                    $found = 1;
                    last;
                } elsif ($oid_part =~ /^\s*(\d+(\.\d+)*)\s*$/) {
                    my $oid_number = $1;
                    unshift @oid_parts, split(/\./, $oid_number);
                    unshift @name_parts, split(/\./, $oid_number);
                    $current_name = undef;
                    $found = 1;
                    last;
                } elsif ($oid_part =~ /^\s*(\d+(\s+\d+)*)\s*$/) {
                    my $oid_number = $1;
                    unshift @oid_parts, split(/\s+/, $oid_number);
                    unshift @name_parts, split(/\s+/, $oid_number);
                    $current_name = undef;
                    $found = 1;
                    last;
                } else {
                    warn "OID no numerico encontrado para $current_name";
                    return;
                }
            }
        }
        last unless $found;
    }
    my $complete_oid = join('.', @oid_parts);
    my $complete_name = join(' ', @name_parts);
    #print "OID completo: $complete_oid\n";
    $complete_oid = validar_y_complementar_oid($complete_oid, $oid_data) if $oid_data;
    return ($complete_oid, $complete_name);
}

# Función para construir el árbol de MIBs
sub construir_arbol_mibs {
    my ($data, $oid_data) = @_;
    my %arbol_mibs;
    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_logs_objects_mibs_path(). '/Alarmas_principales.logs';
    #herramientas::Complementos::print($data);
    foreach my $nombre (keys %{$data->{ALARM_TRAPS}}) {
        my ($oid_completo, $complete_name) = construir_oid_completo($nombre, $data, $oid_data);
        if ($oid_completo) {
            $arbol_mibs{$nombre} = {
                DESCRIPTION => $data->{ALARM_TRAPS}{$nombre}{DESCRIPTION},
                OID => $oid_completo,
                OID_NAME => $complete_name,
                OBJECTS => $data->{ALARM_TRAPS}{$nombre}{OBJECTS},
            };
        }
    }

    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    escribir_datos_en_archivo($temp_file, \%arbol_mibs, "ALARM_TRAPS");
    # Construir el árbol de MIBs secundarios
    my $arbol_mibs_secundarios = construir_arbol_mibs_secundarios($data, $oid_data);
    return \%arbol_mibs, $arbol_mibs_secundarios;
}

# Función para construir el árbol de MIBs secundarios
sub construir_arbol_mibs_secundarios {
    my ($data, $oid_data) = @_;
    my %arbol_mibs_secundarios;
    # Archivo temporal para almacenar cómo se extraen los datos
    my $temp_file = Rutas::temp_files_logs_objects_mibs_path(). '/Objetos_principales.logs';
    foreach my $nombre (keys %{$data->{ALARM_TRAPS}}) {
        my ($oid_completo, $complete_name) = construir_oid_completo($nombre, $data, $oid_data);
        if ($oid_completo) {
            my @objects = split /,\s*/, $data->{ALARM_TRAPS}{$nombre}{OBJECTS};
            foreach my $object (@objects) {
                # Quita espacios en blanco al inicio y al final
                $object =~ s/^\s+|\s+$//g;
                my $object_name = $object . "(nombre)";
                my ($object_oid, $complete_name_oid) = construir_oid_completo($object, $data, $oid_data);
                $arbol_mibs_secundarios{$nombre}{$object} = $object_oid if $object_oid;
                $arbol_mibs_secundarios{$nombre}{$object_name} = $complete_name_oid if $complete_name_oid;
            }
        }
    }
    $temp_file = validar_o_crear_archivo_temporal($temp_file);
    escribir_datos_en_archivo($temp_file, \%arbol_mibs_secundarios, "ALARM_TRAPS");
    return \%arbol_mibs_secundarios;
}

# Function to validate and complete the OID
sub validar_y_complementar_oid {
    my ($complete_oid, $oid_data) = @_;
    return $complete_oid unless $oid_data;
    my $selected_oid_data;
    # Split the OID into parts
    my @oid_parts = split(/\./, $complete_oid);
    # Check if the OID starts with 1 (iso)
    if (@oid_parts && $oid_parts[0] != 1) {
        unshift @oid_parts, 1;
    }
    # Join the OID parts back into a complete OID
    $complete_oid = join('.', @oid_parts);
    return $complete_oid;
}

1;
