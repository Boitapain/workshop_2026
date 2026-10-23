# Takedown RESILIENCE-ALPHA : arrête volontairement toute la plateforme.
# Pose d'abord le drapeau de pause pour que le watchdog NE relance PAS, puis arrête les conteneurs.
#
#   powershell -ExecutionPolicy Bypass -File scripts\lab_down.ps1            # arrêt (conteneurs supprimés, données gardées)
#   powershell -ExecutionPolicy Bypass -File scripts\lab_down.ps1 -Stop      # pause seulement (conteneurs gardés)
#   powershell -ExecutionPolicy Bypass -File scripts\lab_down.ps1 -Purge     # arrêt + SUPPRESSION des volumes (efface tout : base, modèle ML…)
param([switch]$Stop, [switch]$Purge)
$ErrorActionPreference = 'Stop'
$root    = Split-Path $PSScriptRoot -Parent
$flag    = Join-Path $root 'infra\.lab_paused'
$compose = Join-Path $root 'infra\docker-compose.yml'

# 1) Mettre le watchdog en pause (sinon il relancerait tout de suite)
New-Item -ItemType File -Path $flag -Force | Out-Null
Write-Output "Watchdog mis en pause (drapeau posé)."

# 2) Arrêter la plateforme
if ($Stop) {
  Write-Output "Arrêt des conteneurs (gardés en l'état)…"
  docker compose -f $compose stop
} elseif ($Purge) {
  Write-Output "Arrêt + suppression des volumes (DONNÉES EFFACÉES)…"
  docker compose -f $compose --profile rag --profile llm-local down -v
} else {
  Write-Output "Arrêt et suppression des conteneurs (volumes gardés)…"
  docker compose -f $compose --profile rag --profile llm-local down
}
Write-Output "Plateforme arrêtée. Pour relancer : scripts\lab_up.ps1"
