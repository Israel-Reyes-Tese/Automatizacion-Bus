#!/usr/bin/perl
use strict;
use warnings;
use Test::More tests => 3;
use FindBin;
use lib $FindBin::Bin . "/../../utilidades";
use lib $FindBin::Bin . "/../../../herramientas";

use Crear_agente_snmp;
use Estilos;
use Complementos;
use Rutas;
use Logic;
use Validaciones;

# Test for crear_agente_snmp function
sub test_crear_agente_snmp {
    # ...setup code...
    eval {
        utilidades::Crear_agente_snmp::crear_agente_snmp();
    };
    ok(!$@, 'crear_agente_snmp executed without errors');
}

# Test for procesar_creacion_agente function
sub test_procesar_creacion_agente {
    # ...setup code...
    eval {
        utilidades::Crear_agente_snmp::procesar_creacion_agente($mw, $frame_principal, $entry_nombre_agente, $entry_ruta_agente);
    };
    ok(!$@, 'procesar_creacion_agente executed without errors');
}

# Test for crear_interfaz_personalizacion function
sub test_crear_interfaz_personalizacion {
    # ...setup code...
    eval {
        utilidades::Crear_agente_snmp::crear_interfaz_personalizacion($frame_principal, $ventana_principal, $agente, $ruta_agente);
    };
    ok(!$@, 'crear_interfaz_personalizacion executed without errors');
}

# Run tests
test_crear_agente_snmp();
test_procesar_creacion_agente();
test_crear_interfaz_personalizacion();
