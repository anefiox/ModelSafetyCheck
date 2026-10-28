# Checks an Ollama model with modelcheck before pulling it. Refuses on high/critical findings unless -Force.
#   ./ollama-safe-pull.ps1 llama3.2:1b
#   ./ollama-safe-pull.ps1 hf.co/bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M -CheckOnly
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Model,
    [switch]$Force,
    [switch]$CheckOnly
)
& modelcheck repo "ollama:$Model" --min-severity medium
$rc = $LASTEXITCODE
if ($rc -eq 3) { Write-Error "modelcheck could not check $Model; not pulling."; exit 3 }
if ($rc -ge 2 -and -not $Force) { Write-Error "High or critical findings for $Model; not pulling. Re-run with -Force to pull anyway."; exit 2 }
if ($CheckOnly) { exit $rc }
& ollama pull $Model
exit $LASTEXITCODE
