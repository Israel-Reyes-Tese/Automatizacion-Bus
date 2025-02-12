#!/bin/bash

# Navegar al directorio del proyecto
cd /ruta/del/proyecto

# Verificar si el repositorio ya está clonado
if [ ! -d ".git" ]; then
    # Clonar el repositorio si no está clonado
    git clone https://github.com/Israel-Reyes-Tese/Automatizacion-Bus.git .
else
    # Obtener las últimas actualizaciones del repositorio
    git pull origin main
fi

# Empaquetar el script Perl en un ejecutable
pp -o AutoManage.exe AutoManage.pl

echo "Actualización completada."