package LogicMIB;

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

use Cwd 'abs_path';


use FindBin;
use Data::Dumper;
use Toolbar;
use Estilos;
use Complementos;
use Rutas;


# Función principal para cargar MIBs
sub cargar_mib {
    my ($venta_principal, $result_table_pane, $mib_tree_pane, $buscar_ext_mib, $buscar_ext_txt) = @_;
    my %mib_files;
    my @selected_files = "";

    # Crear una ventana de selección de archivos
    my $fs = $result_table_pane->FileSelect(
        -title => 'Seleccionar archivos MIB',
        -selectmode => 'multiple',
    );

    @selected_files = $fs->Show;

    # Manejo de errores
    if (!@selected_files) {
        warn "No se seleccionaron archivos en la función cargar_mib";
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

    # Listar los archivos seleccionados en el panel $mib_tree_pane
    foreach my $file (keys %mib_files) {
        my $relative_path = File::Spec->abs2rel($file);
        $mib_tree_pane->Label(-text => $relative_path, -bg => $herramientas::Estilos::twilight_grey)->pack(-side => 'top', -anchor => 'w');
    }

    # Aquí se puede agregar la lógica para utilizar los archivos MIB en otro proceso
}


# Función para buscar archivos por extensión en el mismo directorio
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