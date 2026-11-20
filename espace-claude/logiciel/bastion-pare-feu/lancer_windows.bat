@echo off
chcp 65001 >nul
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Bastion a besoin des droits administrateur, demande en cours...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
set PYCMD=
where py >nul 2>&1 && set PYCMD=py -3
if "%PYCMD%"=="" where python >nul 2>&1 && set PYCMD=python
if "%PYCMD%"=="" (
  echo Python 3 est introuvable. Installez-le depuis https://www.python.org/downloads/ ^(cochez "Add Python to PATH"^).
  pause
  exit /b 1
)
%PYCMD% -m pip install --quiet --disable-pip-version-check psutil >nul 2>&1
%PYCMD% pare_feu.py
pause
