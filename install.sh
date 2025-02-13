#!/bin/bash

# Verificar si cpanm está instalado
if ! command -v cpanm &> /dev/null
then
    read -p "cpanm no está instalado. ¿Desea instalarlo ahora? (s/n): " respuesta
    if [[ "$respuesta" == "s" || "$respuesta" == "S" ]]; then
        echo "Instalando cpanm..."
        curl -L https://cpanmin.us | perl - --sudo App::cpanminus
    else
        echo "Por favor, instale cpanm y vuelva a ejecutar el script."
        exit 1
    fi
fi

# Verificar si el archivo requirements.txt existe en la raíz del proyecto
if [ ! -f "$(pwd)/requirements.txt" ]; then
    echo "El archivo requirements.txt no se encuentra en la raíz del proyecto."
    exit 1
fi

# Leer las dependencias del archivo requirements.txt
dependencies=$(cat "$(pwd)/requirements.txt")

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
