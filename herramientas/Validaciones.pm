package Validaciones;

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
use Logic;

# Función para validar los checkbuttons
sub validar_checkbuttons {
    my ($parent, $var_local, $var_produccion, $frame_personalizacion, $etapa, $agente, $ruta_agente) = @_;

    if ($$var_local && $$var_produccion) {
        herramientas::Complementos::show_alert($parent, 'ERROR', 'Error: No se pueden tener ambos botones activados.', 'error');
        die "Error: No se pueden tener ambos checkbuttons activados.";
    } elsif (!$$var_local && !$$var_produccion) {
        herramientas::Complementos::show_alert($parent, 'ERROR', 'Error: Es necesario tener al menos un boton activado.', 'error');
        die "Error: Es necesario tener al menos un checkbutton activado.";
    } else {
        if ($etapa eq 'agent_properties') {
        # Actualizar el frame de personalización
        my $modo = $$var_local ? 'local' : 'produccion';
        Logic::actualizar_frame_agent_properties($parent, $frame_personalizacion, $modo, $agente, $ruta_agente);
        } 

    }
}
1;