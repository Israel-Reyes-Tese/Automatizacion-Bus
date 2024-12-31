#!/usr/bin/perl
use strict;
use warnings;
# Importar el módulo Tk
use Tk;
# Importar el módulo FindBin
use FindBin;
# Añadir la carpeta donde se encuentran los módulos
use lib $FindBin::Bin . "/../herramientas";
use lib $FindBin::Bin . "/utilidades";

use Data::Dumper; # Importar el módulo Data::Dumper
# Importar el módulos axuliares
use Toolbar; # Importar el módulo Toolbar
use Estilos; # Importar todas las variables de Estilos
use Complementos;  # Importar el módulo Complementos
# Rutas
use Rutas; # Importar el módulo de rutas
use Crear_agente_snmp; # Importar el módulo crear_agente_snmp

# Función principal para iniciar la aplicación
sub main {
    eval {
        my $mw = MainWindow->new();

        # Establecer el título de la ventana
        $mw->title('Inicio Agentes');
        
        # Maximizar la ventana
        $mw->state('zoomed');

        # Configurar el color de fondo de la ventana
        $mw->configure(bg => $herramientas::Estilos::bg_color);

        # Crear la barra de herramientas
        my $toolbar = herramientas::Toolbar->new($mw);
        # Etiqueta de bienvenida
        herramientas::Complementos::create_label($mw, 'Creacion de Agentes', 'Titulo-Principal');

        # Crear un frame para los botones de agentes
        my $frame = $mw->Frame(-bg => $herramientas::Estilos::bg_color)->pack(-pady => 20);

        # Crear botones de agentes con etiquetas - desde el módulo Complementos en el frame
        herramientas::Complementos::create_button_with_picture_and_label_main_window($mw, $mw, 'Agente SNMP', 
        Rutas::agentes_snmp_image_path(), 
        sub { 
            utilidades::Crear_agente_snmp::crear_agente_snmp(), $mw->destroy(); # Llamar a la subrutina crear_agente_snmp - Destruir la ventana principal
        });
        # Mantener la ventana abierta
        MainLoop();
    };

    # Manejo de errores
    if ($@) {
        die "Error al inicializar la aplicación: $@";
    }
}

# Ejecutar la función principal
main();
