@echo off
REM 1. Instalar módulos desde requirements.txt
powershell -Command "Get-Content requirements.txt | Where-Object { $_ -notmatch '^\s*#' -and $_ -match 'cpanm' } | ForEach-Object { $_.Split(' ')[1] } | ForEach-Object { cpanm $_ }"

REM 2. Buscar ruta de Tk/FileDialog.pm y aplicar parche
perl -e "use File::Find; find(sub { print \$File::Find::name if /FileDialog\.pm$/ }, @INC)" > tmp.txt
set /p filepath=<tmp.txt
del tmp.txt

if "%filepath%"=="" (
    echo Error: No se encontró Tk/FileDialog.pm en @INC
    exit /b 1
)

REM 3. Reemplazar $ por $^W usando Perl (método robusto)
perl -i -pe "s/\x17/\$^W/g" "%filepath%"

echo ¡Parche aplicado en %filepath%!