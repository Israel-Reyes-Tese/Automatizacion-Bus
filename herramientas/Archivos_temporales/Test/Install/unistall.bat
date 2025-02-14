@echo off
REM 1. Desinstalar módulos desde requirements.txt
powershell -Command "Get-Content requirements.txt | Where-Object { $_ -notmatch '^\s*#' -and $_ -match 'cpanm' } | ForEach-Object { $_.Split(' ')[1] } | ForEach-Object { cpanm --uninstall $_ }"

echo ¡Se desinstalaron los módulos!
