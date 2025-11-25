@echo off
title Skyline Style - Auto Start Web

echo ------------------------------------------
echo  INICIANDO SKYLINE STYLE WEB
echo ------------------------------------------
echo.

REM Ruta donde está tu proyecto (EDITA ESTA LINEA SI LO MUEVES)
cd /d "%USERPROFILE%\SkylineStyle"

echo Instalando dependencias...
pip install -r requirements.txt

echo.
echo Levantando la web en: http://127.0.0.1:5000
echo ------------------------------------------
python run.py

pause
