# rutas.pl
package Rutas;

use strict;
use warnings;
use FindBin;

# Definición de rutas constantes
use constant {
    RUTA_IMAGENES => "./static/imagenes/",  # Imágenes de la aplicación
    RUTA_MODULOS_MIB => "./herramientas/Modulos_MIB/",  # Módulos de MIB
    RUTA_ID_EMPRESA => "./herramientas/IDs_empresas_proveedores/",  # ID de la empresa
    RUTA_ARCHIVOS_TEMP => "./herramientas/Archivos_temporales/",  # Archivos temporales
};








#                                                       RUTAS IMAGENES                                   #

# Función para obtener la ruta completa a la imagen de inicio
sub home_image_path {
    return RUTA_IMAGENES . 'home.gif';  # Cambia la extensión si es necesario
}

# Función para obtener la ruta completa a la imagen de agentes inicio
sub agentes_home_image_path {
    return RUTA_IMAGENES . 'agentes_home.gif';  # Cambia la extensión si es necesario
}

# Función para obtener la ruta completa imagen de Inicio MIB
sub mib_home_image_path {
    return RUTA_IMAGENES . 'MIB.gif';  # Cambia la extensión si es necesario
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
#                                                       RUTAS IMAGENES                                   #


#                                                      RUTAS MODULOS MIB                                #

# Función para obtener la ruta completa a un módulo MIB v1
sub mib_module_v1_path {
    return RUTA_MODULOS_MIB . '/SMIv1';  
}

# Función para obtener la ruta completa a un módulo MIB v2
sub mib_module_v2_path {
    return RUTA_MODULOS_MIB . '/SMIv2'; 
}


#                                                      RUTAS ID EMPRESAS                                #
# Función para obtener la ruta completa de los ID de empresas
sub id_empresa_path {
    return RUTA_ID_EMPRESA . '/enterprise-numbers.txt';  
}
#                                                      RUTAS ID EMPRESAS                                #

#                                                      RUTAS ARCHIVOS TEMPORALES                        #
# Función para obtener la ruta completa de los archivos temporales
sub temp_files_path {
    return RUTA_ARCHIVOS_TEMP;  
}
#                                                      RUTAS ARCHIVOS TEMPORALES                        #


1;  # Fin del módulo