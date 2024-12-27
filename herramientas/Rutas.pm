# rutas.pl
package Rutas;

use strict;
use warnings;
use FindBin;

# Definición de rutas constantes
use constant {
    RUTA_IMAGENES => "./static/imagenes/",  # Actualiza esta ruta
};

# Función para obtener la ruta completa a la imagen de inicio
sub home_image_path {
    return RUTA_IMAGENES . 'home.gif';  # Cambia la extensión si es necesario
}

# Función para obtener la ruta completa a la imagen de agentes inicio
sub agentes_home_image_path {
    return RUTA_IMAGENES . 'agentes_home.gif';  # Cambia la extensión si es necesario
}

# Función para obtener la ruta completa a la imagen de salida
sub exit_image_path {
    return RUTA_IMAGENES . 'exit.gif';  # Cambia la extensión si es necesario
}

1;  # Fin del módulo