#!/usr/bin/perl
use strict;
use warnings;

use FindBin;  # Añadir FindBin para obtener la ruta del script
use lib $FindBin::Bin . "/herramientas";  # Añadir la carpeta donde se encuentran los módulos
use Toolbar;  # Importar el módulo Toolbar
# Importar el módulo Estilos
use Estilos;  # Importar todas las variables de Estilos
use Complementos;  # Importar el módulo Complementos


use Tk;
use Data::Dumper;



# Función principal para iniciar la aplicación
sub main {
    eval {
        my $mw = MainWindow->new();

        # Establecer el título de la ventana
        $mw->title('AutoManage GUI');

        # Configurar el color de fondo de la ventana - desde el módulo Estilos
        $mw->configure(bg => $herramientas::Estilos::bg_color);

        # Maximizar la ventana
        $mw->state('zoomed');
        # Crear el toolbar usando el módulo
        my $toolbar = herramientas::Toolbar->new($mw);
        # Etiqueta de bienvenida
        herramientas::Complementos::create_label($mw, 'Bienvenido a AutoManage GUI', 'Titulo-Principal');

        # Crear la barra de menús
        my $menu_bar = $mw->Menu();

        # Añadir menú "Archivo"
        my $file_menu = $menu_bar->cascade(-label => 'Archivo');
        $file_menu->command(-label => 'Salir', -command => sub { exit });

        # Añadir menú "Ayuda"
        my $help_menu = $menu_bar->cascade(-label => 'Ayuda');
        $help_menu->command(-label => 'Acerca de', -command => sub { herramientas::Complementos::show_about($mw) });

        # Configurar la barra de menús en la ventana principal
        $mw->configure(-menu => $menu_bar);

        # Mantener la ventana abierta
        MainLoop();
    };

    # Manejo de errores
    if ($@) {
        die "Error al inicializar la aplicación: $@";
    }
}

# Función para redirigir a la página principal (simulado)
sub go_home {
    print "Redirigiendo a la página principal...\n";  
}


# Función para un botón adicional
sub additional_function {
    print "Función adicional activada.\n";  # Lógica para la función adicional
}


# Ejecutar la función principal
main();