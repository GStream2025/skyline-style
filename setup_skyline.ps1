$ErrorActionPreference = "Stop"

function Info($m){ Write-Host ("ℹ  " + $m) -ForegroundColor Cyan }
function Ok($m){ Write-Host (" " + $m) -ForegroundColor Green }
function Warn($m){ Write-Host ("  " + $m) -ForegroundColor Yellow }
function Bad($m){ Write-Host (" " + $m) -ForegroundColor Red }

function Ensure-Dir($p){
  if (!(Test-Path $p)) { New-Item -ItemType Directory -Force -Path $p | Out-Null; Ok "Carpeta creada: $p" }
}

function Backup-File($p){
  if (Test-Path $p){
    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $bdir = Join-Path (Get-Location) ("_backup_" + $stamp)
    Ensure-Dir $bdir
    $safe = ($p -replace "[:\\\/]", "__")
    Copy-Item $p (Join-Path $bdir $safe) -Force
    Info "Backup: $p -> $bdir\$safe"
  }
}

function Write-Utf8($path, $content){
  Ensure-Dir (Split-Path $path -Parent)
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($path, $content, $utf8NoBom)
  Ok "Escrito: $path"
}

function Read-Raw($path){
  if (!(Test-Path $path)) { return "" }
  return Get-Content $path -Raw
}

function Open-Notepad($path){
  if (Test-Path $path){
    Start-Process notepad.exe $path
    Info "Abriendo Notepad: $path"
  }
}

Info "Validando estructura..."
if (!(Test-Path ".\app")) { Bad "No existe .\app. Ejecutá esto en la raíz del repo."; exit 1 }
if (!(Test-Path ".\run.py")) { Warn "No veo run.py aquí. Si tu entrypoint es otro, ajustalo." }
Ok "Root OK"

Info "Asegurando uploads..."
Ensure-Dir ".\app\static\uploads"
Ensure-Dir ".\app\static\uploads\products"
Ensure-Dir ".\app\static\uploads\img"
Ensure-Dir ".\app\static\uploads\img\hero"
if (!(Test-Path ".\app\static\uploads\.gitkeep")) { Set-Content ".\app\static\uploads\.gitkeep" "" -Encoding UTF8 }
if (!(Test-Path ".\app\static\uploads\products\.gitkeep")) { Set-Content ".\app\static\uploads\products\.gitkeep" "" -Encoding UTF8 }
Ok "Uploads OK"

Info "Chequeando .env..."
if (!(Test-Path ".\.env")){
$envText = @"
FLASK_ENV=development
DEBUG=1
SECRET_KEY=CHANGE_ME_SUPER_SECRET

ADMIN_EMAIL=admin@local
ADMIN_PASSWORD=admin1234

SQLALCHEMY_DATABASE_URI=sqlite:///skyline.db
PRINTFUL_API_KEY=CHANGE_ME_PRINTFUL_KEY
"@
  Write-Utf8 ".\.env" $envText
  Open-Notepad ".\.env"
} else {
  Info ".env ya existe"
}

Info "Chequeando venv..."
if (!(Test-Path ".\.venv")) {
  Info "Creando .venv..."
  python -m venv .venv
  Ok ".venv creado"
} else {
  Info ".venv ya existe"
}

$py  = ".\.venv\Scripts\python.exe"
$pip = ".\.venv\Scripts\pip.exe"
if (!(Test-Path $py)) { Bad "No existe $py"; exit 1 }

Info "Actualizando pip..."
& $py -m pip install --upgrade pip setuptools wheel | Out-Null
Ok "pip OK"

Info "Instalando deps..."
if (Test-Path ".\requirements.txt"){
  & $pip install -r ".\requirements.txt"
  Ok "requirements instaladas"
} else {
  Warn "No hay requirements.txt: instalo mínimos"
  & $pip install flask flask_sqlalchemy python-dotenv requests
  Ok "deps mínimas instaladas"
}

Info "Creando DB (create_all)..."
try {
  & $py -c "from run import app; from app import db; app.app_context().push(); db.create_all(); print('DB OK')"
  Ok "DB lista"
} catch {
  Warn "No pude crear DB. Revisá run.py y app/__init__.py"
  Open-Notepad ".\run.py"
  Open-Notepad ".\app\__init__.py"
}

Info "Abriendo archivos clave..."
Open-Notepad ".\app\routes\admin_routes.py"
Open-Notepad ".\app\routes\printful_routes.py"
Open-Notepad ".\app\__init__.py"

Ok "Listo para probar:"
Write-Host "  Admin:   http://127.0.0.1:5000/admin" -ForegroundColor Green
Write-Host "  Printful:http://127.0.0.1:5000/printful/productos" -ForegroundColor Green
Write-Host ""
Write-Host "Ejecutá:" -ForegroundColor Cyan
Write-Host "  .\.venv\Scripts\Activate.ps1" -ForegroundColor Green
Write-Host "  python run.py" -ForegroundColor Green
