# Watchdog RESILIENCE-ALPHA : relance TOUT conteneur du projet qui n'est pas en cours d'exécution,
# y compris après un arrêt manuel (docker stop). Le seul moyen d'arrêter pour de bon : lab_down.ps1,
# qui pose le drapeau de pause ci-dessous.
#
# Lancement :   powershell -ExecutionPolicy Bypass -File scripts\lab_watchdog.ps1
# Arrêt :        ferme la fenêtre, ou Ctrl+C
$ErrorActionPreference = 'SilentlyContinue'
$root     = Split-Path $PSScriptRoot -Parent
$flag     = Join-Path $root 'infra\.lab_paused'
$logFile  = Join-Path $root 'infra\watchdog.log'
$project  = 'resilience'
$interval = 5

function Log($msg) {
  $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $msg"
  Write-Output $line
  Add-Content -Path $logFile -Value $line -Encoding utf8
}

Log "Watchdog démarré (surveille le projet '$project' toutes les $interval s). Drapeau de pause : $flag"
while ($true) {
  if (-not (Test-Path $flag)) {
    # Conteneurs du projet qui ne tournent pas (arrêtés, créés, en pause, tués)
    $down = docker ps -a --filter "label=com.docker.compose.project=$project" `
                        --filter "status=exited" --filter "status=created" `
                        --filter "status=paused" --filter "status=dead" `
                        --format "{{.Names}}"
    foreach ($c in $down) {
      if ($c) {
        docker start $c | Out-Null
        if ($?) { Log "↻ relancé automatiquement : $c" }
      }
    }
  }
  Start-Sleep -Seconds $interval
}
