@echo off
REM 1. Instalar módulos desde requirements.txt
powershell -Command "Get-Content requirements.txt | Where-Object { $_ -notmatch '^\s*#' -and $_ -match 'cpanm' } | ForEach-Object { $_.Split(' ')[1] } | ForEach-Object { cpanm $_ }"

REM 2. Buscar ruta de Tk/FileDialog.pm y aplicar parche
set filepath=C:/Strawberry/perl/site/lib/Tk/FileDialog.pm
set patchfile=herramientas\Archivos_temporales\Parche\Librerias\FileDialog.pm

if not exist "%filepath%" (
    echo Error: No se encontró Tk/FileDialog.pm en la ruta especificada
    exit /b 1
)

REM Reemplazar el contenido del archivo principal con el archivo de parche
copy /Y "%patchfile%" "%filepath%"

if %errorlevel% neq 0 (
    echo Error: No se pudo aplicar el parche
    exit /b 1
)

echo ¡Parche aplicado en %filepath%!