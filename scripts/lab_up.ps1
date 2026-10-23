# Démarrage RESILIENCE-ALPHA : retire la pause, démarre la plateforme, puis lance le watchdog.
#
#   powershell -ExecutionPolicy Bypass -File scripts\lab_up.ps1
param([switch]$NoWatchdog)
$ErrorActionPreference = 'Stop'
$root    = Split-Path $PSScriptRoot -Parent
$flag    = Join-Path $root 'infra\.lab_paused'
$compose = Join-Path $root 'infra\docker-compose.yml'

# 1) Lever la pause du watchdog
Remove-Item -Path $flag -ErrorAction SilentlyContinue
Write-Output "Pause du watchdog levée."

# 2) Démarrer la plateforme
Write-Output "Démarrage de la plateforme…"
docker compose -f $compose up -d

# 3) Lancer le watchdog en arrière-plan (sauf -NoWatchdog)
if (-not $NoWatchdog) {
  $wd = Join-Path $PSScriptRoot 'lab_watchdog.ps1'
  Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Minimized -File `"$wd`""
  Write-Output "Watchdog lancé en arrière-plan (fenêtre minimisée)."
}
Write-Output "Prêt. Dashboard : http://127.0.0.1:8080"
