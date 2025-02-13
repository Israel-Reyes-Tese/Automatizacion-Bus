#!/bin/bash

# Verificar si cpanm está instalado
if ! command -v cpanm &> /dev/null
then
    echo "cpanm no está instalado. Por favor, instálalo primero."
    exit 1
fi

# Verificar si el archivo requirements.txt existe en la raíz del proyecto
if [ ! -f "requirements.txt" ]; then
    echo "El archivo requirements.txt no se encuentra en la raíz del proyecto."
    exit 1
fi

# Leer las dependencias del archivo requirements.txt
dependencies=$(cat requirements.txt)

# Verificar e instalar cada dependencia
for dep in $dependencies; do
    if ! perl -M$dep -e 1 &> /dev/null; then
        echo "Instalando $dep..."
        cpanm $dep
    else
        echo "$dep ya está instalado."
    fi
done


echo "Dependencias verificadas e instaladas correctamente."