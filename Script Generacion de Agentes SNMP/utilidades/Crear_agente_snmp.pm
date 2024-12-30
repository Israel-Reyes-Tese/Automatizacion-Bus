#!/usr/bin/perl
package utilidades::Crear_agente_snmp;

use strict;
use warnings;
use Tk;
use FindBin;
use lib $FindBin::Bin . "/../herramientas";
use Estilos;
use Complementos;
use Rutas;

sub crear_agente_snmp {
    my $mw = MainWindow->new();
    $mw->title('Crear Agente SNMP');
    $mw->configure(bg => $herramientas::Estilos::bg_color);

    # Aquí puedes agregar los widgets y la lógica para la creación de agentes SNMP

    MainLoop();
}

1;