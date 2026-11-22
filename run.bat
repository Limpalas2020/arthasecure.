@echo off
:: =====================================================================
:: CIBER-ANALYZER // SCRIPT DE ARRANQUE Y AUTO-INSTALACION (WINDOWS CMD)
:: =====================================================================
:: Este script realiza las siguientes tareas de forma automatica:
:: 1. Fija el directorio de trabajo a la carpeta del proyecto.
:: 2. Detecta la instalacion de Python en el equipo (PATH, py, usuario o sistema).
:: 3. Verifica si Flask, ReportLab y Requests estan instalados.
:: 4. SI FALTAN LIBRERIAS, LAS INSTALA AUTOMATICAMENTE via pip.
:: 5. Crea las carpetas de salida si no existen (public\reports).
:: 6. Inicia el servidor Flask y abre el navegador en http://127.0.0.1:5000.
:: =====================================================================

cd /d "%~dp0"

title CIBER-ANALYZER // Plataforma de Auditoria de Redes
cls
echo =====================================================================
echo           CIBER-ANALYZER // PLATAFORMA DE AUDITORIA
echo =====================================================================
echo.
echo [*] Directorio del proyecto: %~dp0

:: ---------------------------------------------------------------------
:: 1. DETECCION AUTOMATICA DE PYTHON
:: ---------------------------------------------------------------------
set "PY_CMD="

:: Comprobar py.exe
where py >nul 2>&1
if %ERRORLEVEL% equ 0 (
    py -3 -c "import sys" >nul 2>&1
    if not errorlevel 1 (
        set "PY_CMD=py -3"
        goto :python_detected
    )
    py -c "import sys" >nul 2>&1
    if not errorlevel 1 (
        set "PY_CMD=py"
        goto :python_detected
    )
)

:: Comprobar python en PATH
where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    python -c "import sys" >nul 2>&1
    if not errorlevel 1 (
        set "PY_CMD=python"
        goto :python_detected
    )
)

:: Comprobar rutas en AppData local del usuario
if exist "%LOCALAPPDATA%\Python\bin\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Python\bin\python.exe"
    goto :python_detected
)
if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
    goto :python_detected
)
if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    goto :python_detected
)
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    goto :python_detected
)
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    goto :python_detected
)
if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    goto :python_detected
)

:: Comprobar rutas globales de Program Files y C:
if exist "%ProgramFiles%\Python314\python.exe" (
    set "PY_CMD=%ProgramFiles%\Python314\python.exe"
    goto :python_detected
)
if exist "%ProgramFiles%\Python313\python.exe" (
    set "PY_CMD=%ProgramFiles%\Python313\python.exe"
    goto :python_detected
)
if exist "%ProgramFiles%\Python312\python.exe" (
    set "PY_CMD=%ProgramFiles%\Python312\python.exe"
    goto :python_detected
)
if exist "%ProgramFiles%\Python311\python.exe" (
    set "PY_CMD=%ProgramFiles%\Python311\python.exe"
    goto :python_detected
)
if exist "%ProgramFiles%\Python310\python.exe" (
    set "PY_CMD=%ProgramFiles%\Python310\python.exe"
    goto :python_detected
)
if exist "C:\Python312\python.exe" (
    set "PY_CMD=C:\Python312\python.exe"
    goto :python_detected
)
if exist "C:\Python311\python.exe" (
    set "PY_CMD=C:\Python311\python.exe"
    goto :python_detected
)
if exist "C:\Python310\python.exe" (
    set "PY_CMD=C:\Python310\python.exe"
    goto :python_detected
)

:: Comprobar Anaconda y Miniconda
if exist "%USERPROFILE%\anaconda3\python.exe" (
    set "PY_CMD=%USERPROFILE%\anaconda3\python.exe"
    goto :python_detected
)
if exist "%USERPROFILE%\miniconda3\python.exe" (
    set "PY_CMD=%USERPROFILE%\miniconda3\python.exe"
    goto :python_detected
)

:: Si no se encontro Python en ningun lugar
echo.
echo =====================================================================
echo  [ERROR] No se encontro Python instalado en este equipo.
echo =====================================================================
echo  Para ejecutar CIBER-ANALYZER se requiere tener Python instalado:
echo.
echo  1. Descarga Python gratis desde la pagina oficial:
echo     https://www.python.org/downloads/
echo.
echo  2. IMPORTANTE DURANTE LA INSTALACION:
echo     Marca la casilla: "Add python.exe to PATH"
echo.
echo  3. Al terminar la instalacion, vuelve a abrir este archivo run.bat.
echo =====================================================================
echo.
pause
exit /b 1

:python_detected
echo [*] Interprete de Python detectado: %PY_CMD%

:: ---------------------------------------------------------------------
:: 2. VERIFICACION Y AUTO-INSTALACION DE DEPENDENCIAS
:: ---------------------------------------------------------------------
echo [*] Verificando dependencias del sistema...

%PY_CMD% -c "import flask, reportlab, requests" >nul 2>&1
if %ERRORLEVEL% equ 0 goto :deps_ok

echo.
echo =====================================================================
echo  [!] Se detecto que faltan dependencias en este equipo.
echo  [+] Instalando automaticamente Flask, ReportLab y Requests...
echo      (Esto solo tomara unos segundos la primera vez)
echo =====================================================================
echo.

%PY_CMD% -m pip install -r "%~dp0requirements.txt"
if %ERRORLEVEL% neq 0 (
    echo.
    echo [*] Reintentando instalacion con permisos de usuario local...
    %PY_CMD% -m pip install --user -r "%~dp0requirements.txt"
)

%PY_CMD% -c "import flask, reportlab, requests" >nul 2>&1
if %ERRORLEVEL% equ 0 goto :deps_installed

echo.
echo =====================================================================
echo  [ERROR] No se pudieron instalar las dependencias automaticamente.
echo =====================================================================
echo  Verifica que el equipo tenga conexion a Internet y ejecuta:
echo     pip install -r requirements.txt
echo =====================================================================
echo.
pause
exit /b 1

:deps_installed
echo.
echo [*] Dependencias instaladas y verificadas con exito.
goto :start_server

:deps_ok
echo [*] Todas las dependencias estan instaladas y listas.

:start_server
:: ---------------------------------------------------------------------
:: 3. COMPROBACION DE DIRECTORIOS DE SALIDA
:: ---------------------------------------------------------------------
if not exist "%~dp0public\reports" (
    mkdir "%~dp0public\reports" >nul 2>&1
)

:: ---------------------------------------------------------------------
:: 4. ARRANQUE DEL SERVIDOR WEB Y APERTURA DEL NAVEGADOR
:: ---------------------------------------------------------------------
echo.
echo =====================================================================
echo  [+] INICIANDO SERVIDOR WEB EN: http://127.0.0.1:5000
echo  [+] Abriendo la aplicacion automaticamente en tu navegador...
echo.
echo  [!] ATENCION: NO CIERRES ESTA VENTANA mientras uses la aplicacion.
echo  [!] Para detener el servidor, presiona Ctrl + C en esta consola.
echo =====================================================================
echo.

start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:5000"

%PY_CMD% "%~dp0app.py"

echo.
echo =====================================================================
echo  El servidor web se ha detenido.
echo =====================================================================
pause
