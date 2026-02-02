# abrir_routes_en_orden.ps1
# Abre archivos uno por uno al presionar ENTER (sin abrir todos juntos)

$ErrorActionPreference = "Stop"

# Ruta: carpeta donde esta este .ps1
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

# Lista en el orden que queres
$files = @(
  "admin_auth_routes.py",
  "admin_routes.py",
  "admin_payments_routes.py",
  "auth_routes.py",
  "account_routes.py",
  "profile_routes.py",
  "address_routes.py",
  "cart_routes.py",
  "checkout_routes.py",
  "shop_routes.py",
  "affiliate_routes.py",
  "marketing_routes.py",
  "printful_routes.py",
  "webhook_routes.py",
  "api_routes.py",
  "__init__.py"
)

foreach ($f in $files) {
  if (-not (Test-Path $f)) {
    Write-Host ("SKIP (no existe): " + $f) -ForegroundColor DarkYellow
    continue
  }

  Write-Host ""
  Write-Host ("ENTER para abrir: " + $f) -ForegroundColor Yellow
  Read-Host | Out-Null

  # Abre con la app por defecto (normalmente tu editor)
  Start-Process -FilePath $f
}

Write-Host ""
Write-Host "Listo." -ForegroundColor Green
