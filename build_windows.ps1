# Build WiFi-Intrusion-Monitor-windows.exe into dist\ and the website folder (wifi-intrusion-monitor\).
# Needs Python 3.10 or newer from python.org. Run build_windows.bat, or:
#   powershell -ExecutionPolicy Bypass -File build_windows.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    py -3 -m venv .venv
}
$py = ".venv\Scripts\python.exe"
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet -r requirements.txt
& $py -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "Tests failed; not building." }

& $py -m PyInstaller --noconfirm --clean --onefile --windowed `
    --name "WiFi-Intrusion-Monitor" `
    --icon "assets\AppIcon.ico" `
    --add-data "wimon\alert.html;wimon" `
    --add-data "assets\icon-1024.png;assets" `
    --hidden-import "pystray._win32" `
    --collect-submodules "dns" `
    run_app.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }

Copy-Item "dist\WiFi-Intrusion-Monitor.exe" "wifi-intrusion-monitor\WiFi-Intrusion-Monitor-windows.exe" -Force
Get-FileHash "wifi-intrusion-monitor\WiFi-Intrusion-Monitor-windows.exe" -Algorithm SHA256 | Format-List
Write-Host "Built wifi-intrusion-monitor\WiFi-Intrusion-Monitor-windows.exe"
