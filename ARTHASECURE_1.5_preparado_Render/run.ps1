# =====================================================================
# CIBER-ANALYZER // SCRIPT DE ARRANQUE Y AUTO-INSTALACIÓN (POWERSHELL)
# =====================================================================
# Este script automatiza la comprobación del entorno, instalación de
# dependencias e inicio del servidor web en cualquier equipo con Windows:
#
# 1. Fija el directorio de trabajo a la carpeta del script ($PSScriptRoot).
# 2. Detecta automáticamente el intérprete de Python instalado.
# 3. Verifica si Flask, ReportLab y Requests están instalados;
#    si faltan, los instala automáticamente mediante 'pip install'.
# 4. Inicia el servidor Flask y abre el navegador predeterminado.
# =====================================================================

# 1. Forzar ubicación al directorio del proyecto
Set-Location -LiteralPath $PSScriptRoot

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "          CIBER-ANALYZER // PLATAFORMA DE AUDITORIA" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "[*] Directorio del proyecto: $PSScriptRoot" -ForegroundColor DarkGray

# ---------------------------------------------------------------------
# 2. DETECCIÓN AUTOMÁTICA DEL INTÉRPRETE DE PYTHON
# ---------------------------------------------------------------------
$pyCmd = $null

# Opción A: Lanzador oficial py.exe
if (Get-Command py -ErrorAction SilentlyContinue) {
    try { & py -3 -c "import sys" 2>$null; $pyCmd = "py" } catch {}
}

# Opción B: Comando global python en PATH
if (-not $pyCmd -and (Get-Command python -ErrorAction SilentlyContinue)) {
    try { & python -c "import sys" 2>$null; $pyCmd = "python" } catch {}
}

# Opción C: Instalaciones locales de usuario (%LOCALAPPDATA%)
if (-not $pyCmd) {
    $userPaths = @(
        "$env:LOCALAPPDATA\Python\bin\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python314\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe"
    )
    foreach ($p in $userPaths) {
        if (Test-Path $p) {
            $pyCmd = $p
            break
        }
    }
}

# Opción D: Instalaciones globales (%ProgramFiles% y C:\)
if (-not $pyCmd) {
    $sysPaths = @(
        "$env:ProgramFiles\Python314\python.exe",
        "$env:ProgramFiles\Python313\python.exe",
        "$env:ProgramFiles\Python312\python.exe",
        "$env:ProgramFiles\Python311\python.exe",
        "$env:ProgramFiles\Python310\python.exe",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "C:\Python310\python.exe"
    )
    foreach ($p in $sysPaths) {
        if (Test-Path $p) {
            $pyCmd = $p
            break
        }
    }
}

if (-not $pyCmd) {
    Write-Host ""
    Write-Host "=====================================================================" -ForegroundColor Red
    Write-Host " [ERROR] No se detectó Python instalado en este equipo." -ForegroundColor Red
    Write-Host "=====================================================================" -ForegroundColor Red
    Write-Host " Para ejecutar CIBER-ANALYZER se requiere tener Python instalado:" -ForegroundColor Yellow
    Write-Host " 1. Descárgalo desde: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host " 2. Durante la instalación marca: 'Add python.exe to PATH'" -ForegroundColor Yellow
    Write-Host " 3. Vuelve a ejecutar este script." -ForegroundColor Yellow
    Write-Host "=====================================================================" -ForegroundColor Red
    Exit 1
}

Write-Host "[*] Intérprete de Python detectado: $pyCmd" -ForegroundColor Green

# ---------------------------------------------------------------------
# 3. VERIFICACIÓN Y AUTO-INSTALACIÓN DE DEPENDENCIAS
# ---------------------------------------------------------------------
Write-Host "[*] Verificando dependencias del sistema..." -ForegroundColor DarkGray
$depsInstalled = $false
try {
    & $pyCmd -c "import flask, reportlab, requests" 2>$null
    if ($LASTEXITCODE -eq 0) { $depsInstalled = $true }
} catch {}

if (-not $depsInstalled) {
    Write-Host ""
    Write-Host "=====================================================================" -ForegroundColor Yellow
    Write-Host " [!] Se detectó que faltan librerías en este equipo." -ForegroundColor Yellow
    Write-Host " [+] Instalando automáticamente (Flask, ReportLab, Requests)..." -ForegroundColor Yellow
    Write-Host "=====================================================================" -ForegroundColor Yellow
    Write-Host ""

    & $pyCmd -m pip install -r "$PSScriptRoot\requirements.txt"
    if ($LASTEXITCODE -ne 0) {
        & $pyCmd -m pip install --user -r "$PSScriptRoot\requirements.txt"
    }

    try {
        & $pyCmd -c "import flask, reportlab, requests" 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[ERROR] No se pudieron instalar las dependencias automáticamente." -ForegroundColor Red
            Write-Host "Verifica la conexión a Internet y ejecuta: pip install -r requirements.txt" -ForegroundColor Red
            Exit 1
        }
        Write-Host "[*] Dependencias instaladas exitosamente." -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Fallo al verificar dependencias tras instalación." -ForegroundColor Red
        Exit 1
    }
} else {
    Write-Host "[*] Todas las dependencias están instaladas y listas." -ForegroundColor Green
}

# ---------------------------------------------------------------------
# 4. COMPROBACIÓN DE DIRECTORIOS DE SALIDA
# ---------------------------------------------------------------------
$reportsDir = Join-Path $PSScriptRoot "public\reports"
if (-not (Test-Path $reportsDir)) {
    New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null
}

# ---------------------------------------------------------------------
# 5. ARRANQUE DEL SERVIDOR WEB Y APERTURA DEL NAVEGADOR
# ---------------------------------------------------------------------
Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host " [+] INICIANDO SERVIDOR WEB EN: http://127.0.0.1:5000" -ForegroundColor Green
Write-Host " [+] Abriendo la aplicación en tu navegador predeterminado..." -ForegroundColor Green
Write-Host ""
Write-Host " [!] ATENCION: NO CIERRES ESTA VENTANA mientras uses la aplicación." -ForegroundColor Yellow
Write-Host " [!] Para detener el servidor, presiona Ctrl + C en esta ventana." -ForegroundColor Yellow
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host ""

try {
    Start-Process "http://127.0.0.1:5000"
} catch {}

& $pyCmd "$PSScriptRoot\app.py"
