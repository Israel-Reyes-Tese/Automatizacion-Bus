# #!/usr/bin/perl

package utilidades::Crear_Codigo;


use strict;
use warnings;
use Tk;
use Tk::Pane;
use Tk::FileSelect;

use FindBin;
use lib $FindBin::Bin . "/../herramientas";
use lib $FindBin::Bin . "/../../herramientas";  # Añadir la carpeta donde se encuentran los modulos
use File::Spec;

use Estilos;
use Complementos;
use Rutas;
use Logic;
use LogicMIB;
use Validaciones;


sub Inicio_Crear_Codigo {
    my ($agente, $ruta_agente) = @_;
    if (!$agente) {
        $agente = 'Agente SNMP';
    }
    if (!$ruta_agente) {
        $ruta_agente = Rutas::temp_agents_path();
    }

    my $mw = herramientas::Complementos::create_main_window('Creacion de codigo', 'maximizada', 1 , 0 , 'Codigo', 'Titulo-Principal', 0);


}

1;

