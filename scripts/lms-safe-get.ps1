# Checks a Hugging Face repo with modelcheck before downloading it with LM Studio's CLI (`lms get`).
# Refuses on high/critical findings unless -Force.
#   ./lms-safe-get.ps1 lmstudio-community/gemma-4-12B-it-GGUF
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Repo,
    [switch]$Force,
    [switch]$CheckOnly
)
& modelcheck repo $Repo --min-severity medium
$rc = $LASTEXITCODE
if ($rc -eq 3) { Write-Error "modelcheck could not check $Repo; not downloading."; exit 3 }
if ($rc -ge 2 -and -not $Force) { Write-Error "High or critical findings for $Repo; not downloading. Re-run with -Force to download anyway."; exit 2 }
if ($CheckOnly) { exit $rc }
& lms get $Repo
exit $LASTEXITCODE
