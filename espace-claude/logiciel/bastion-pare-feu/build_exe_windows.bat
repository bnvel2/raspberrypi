@echo off
REM Optionnel : fabrique Bastion.exe (demande les droits administrateur au lancement).
cd /d "%~dp0"
py -3 -m pip install pyinstaller psutil
py -3 -m PyInstaller --onefile --uac-admin --name Bastion --add-data "web;web" pare_feu.py
echo.
echo Terminé : dist\Bastion.exe
pause
