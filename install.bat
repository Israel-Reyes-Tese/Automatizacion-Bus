@echo off
:: Check for elevated privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Por favor, ejecute este script como administrador.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b 1
)

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
    echo Error: No se pudo aplicar el parche automaticamente.
    powershell -Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Favor de copiar y reemplazar el archivo FileDialog.pm de Parche librerias a la carpeta raiz de las librerias.', 'Aviso', 'OK', 'Warning')"
    start explorer "C:/Strawberry/perl/site/lib/Tk/"
    start explorer "herramientas\Archivos_temporales\Parche\Librerias\"
    exit /b 1
)

echo ¡Parche aplicado en %filepath%!