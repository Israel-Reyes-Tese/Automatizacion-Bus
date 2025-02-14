@echo off
:: Check for elevated privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Por favor, ejecute este script como administrador.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b 1
)

:: Ejecutar el script Perl
perl install_depends.pl