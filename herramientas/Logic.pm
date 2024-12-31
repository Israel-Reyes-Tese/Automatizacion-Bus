package Logic;

use strict;
use warnings;
use File::Path qw(make_path rmtree);
use File::Spec;

# Añadir la carpeta donde se encuentran los módulos
use lib $FindBin::Bin . "/herramientas";
use Data::Dumper; # Importar el módulo Data::Dumper
# Importar el módulos axuliares
use Toolbar; # Importar el módulo Toolbar
use Estilos; # Importar todas las variables de Estilos
use Complementos;  # Importar el módulo Complementos
use Rutas; # Importar el módulo de rutas

# Función para crear el árbol de directorios y archivos
sub crear_arbol_directorio {
    my ($parent, $ruta_principal, $nombre_agente) = @_;

    # Ruta completa del agente
    my $ruta_agente = File::Spec->catdir($ruta_principal, $nombre_agente);

    # Verificar si el agente ya existe
    if (-d $ruta_agente) {
        my $title = "Agente Existente";
        my $message = "El agente '$nombre_agente' ya existe.¿Desea reemplazarlo?";
        my $type = 'question';

        my $response = herramientas::Complementos::create_alert_with_picture_label_and_button($parent, $title, $message, $type);
        # Si la respuesta es 'No', detener el proceso
        if (!$response) {
            return 0;
        }
        # Si la respuesta es 'Sí', eliminar el directorio existente
        eval {
            rmtree($ruta_agente);
        };
        if ($@) {
            die "Error al eliminar el directorio existente en la función crear_arbol_directorio: $@";
        }
   
    }

    # Crear directorios
    my @directorios = (
        $ruta_agente,
        File::Spec->catdir($ruta_agente, 'CONF'),
        File::Spec->catdir($ruta_agente, 'ABR'),
        File::Spec->catdir($ruta_agente, 'ExampleTrapAlarm')
    );

    eval {
        make_path(@directorios);
    };
    if ($@) {
        die "Error al crear directorios en la función crear_arbol_directorio: $@";
    }

    # Crear archivos en la raíz del agente
    my $archivo_agente = File::Spec->catfile($ruta_agente, "agente_$nombre_agente.pl");
    my $archivo_properties = File::Spec->catfile($ruta_agente, "AGENT.properties");

    eval {
        open my $fh, '>', $archivo_agente or die "Error al crear $archivo_agente: $!";
        close $fh;
        open $fh, '>', $archivo_properties or die "Error al crear $archivo_properties: $!";
        close $fh;
    };
    if ($@) {
        die "Error al crear archivos en la función crear_arbol_directorio: $@";
    }

    # Crear archivos en la carpeta CONF
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
        if ($@) {
            die "Error al crear archivos en la carpeta CONF en la función crear_arbol_directorio: $@";
        }
    }

    # Crear archivos en la carpeta ABR
    my @archivos_abr = qw(
        ExampleTrapAlarm CONFIGURATOR.pm CorrectiveFilter.pm EXAMPLE.pm
        FILE_HANDLER.pm llenaComun.pm MICROTIME.pm Parser_aux.pm
        SNMPAgente.pm TapFilter.pm
    );

    foreach my $archivo (@archivos_abr) {
        my $ruta_archivo = File::Spec->catfile($ruta_agente, 'ABR', $archivo);
        eval {
            open my $fh, '>', $ruta_archivo or die "Error al crear $ruta_archivo: $!";
            close $fh;
        };
        if ($@) {
            die "Error al crear archivos en la carpeta ABR en la función crear_arbol_directorio: $@";
        }
    }

    return 1;
}

1;