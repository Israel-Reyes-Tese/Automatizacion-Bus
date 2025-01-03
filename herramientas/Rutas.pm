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

# Función para obtener la ruta completa a la imagena Agente SNMP
sub agentes_snmp_image_path {
    return RUTA_IMAGENES . 'agentes_snmp.gif';  # Cambia la extensión si es necesario
}

# Función para obtener la ruta completa a la imagen de salida
sub exit_image_path {
    return RUTA_IMAGENES . 'exit.gif';  # Cambia la extensión si es necesario
}

# Función para obtener la ruta completa a la imagen de ayuda
sub help_image_path {
    return RUTA_IMAGENES . 'help.gif';  # Cambia la extensión si es necesario
}

# Función para obtener la ruta completa a la imagen de acerca de
sub about_image_path {
    return RUTA_IMAGENES . 'info.gif';  # Cambia la extensión si es necesario
}

# Función para obtener la ruta completa a la imagen error
sub error_image_path {
    return RUTA_IMAGENES . 'error.gif';  # Cambia la extensión si es necesario
}

# Función para obtener la ruta completa a la imagen de éxito
sub success_image_path {
    return RUTA_IMAGENES . 'success.gif';  # Cambia la extensión si es necesario
}

# Función para obtener la ruta completa a la imagen de advertencia
sub warning_image_path {
    return RUTA_IMAGENES . 'warning.gif';  # Cambia la extensión si es necesario
}


# Función para obtener la ruta completa a la imagen de configuración
sub settings_image_path {
    return RUTA_IMAGENES . 'settings.gif';  # Cambia la extensión si es necesario
}

# Función para obtener la ruta completa a la imagen de pregunta
sub question_image_path {
    return RUTA_IMAGENES . 'question.gif';  # Cambia la extensión si es necesario
}

# Función para obtener la ruta completa a la imagen de editar
sub edit_image_path {
    return RUTA_IMAGENES . 'edit.gif';  # Cambia la extensión si es necesario
}

1;  # Fin del módulo