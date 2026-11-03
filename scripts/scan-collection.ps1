# Works through a pinned scan collection (scans/<name>/manifest.json) and shares progress through git, so a scan can be
# stopped on one machine (Ctrl+C) and continued on another. Each run: pull, scan what is not done yet, export the
# dataset, commit scans/<name> and push. Completed models are never downloaded again at the same scanner commit.
#   ./scripts/scan-collection.ps1                          # scans/hf-top100
#   ./scripts/scan-collection.ps1 hf-top100 -NoPush        # commit locally only
#   ./scripts/scan-collection.ps1 -MaxTotalGb 200          # stop after ~200 GB of downloads this session
param(
    [Parameter(Position = 0)][string]$Name = "hf-top100",
    [switch]$NoPush,
    [decimal]$MaxTotalGb = 2500
)
$root = Split-Path -Parent $PSScriptRoot
$dir = "scans/$Name"
Set-Location $root
if (-not (Test-Path "$dir/manifest.json")) { Write-Error "No $dir/manifest.json; create one with: modelcheck batch ... --write-manifest $dir/manifest.json"; exit 64 }

git pull --rebase --autostash
if ($LASTEXITCODE -ne 0) { Write-Error "git pull failed; resolve it, then rerun."; exit 3 }
git submodule update --init
dotnet build src/ModelSafetyCheck.Cli -c Release -nologo -v q
if ($LASTEXITCODE -ne 0) { exit 3 }
$modelcheck = "src/ModelSafetyCheck.Cli/bin/Release/net10.0/modelcheck.dll"

# Ctrl+C reaches modelcheck, which records the interrupted model as incomplete and exits. PowerShell stops the script
# at the same time, so the commit happens in finally, after waiting for modelcheck to finish writing.
$rc = 3
$scan = $null
try {
    $scan = Start-Process dotnet -NoNewWindow -PassThru -ArgumentList @($modelcheck, "batch", "--manifest", "$dir/manifest.json",
        "--directory", $dir, "--max-total-gb", $MaxTotalGb.ToString([cultureinfo]::InvariantCulture), "--min-severity", "medium")
    $null = $scan.Handle   # without a cached handle, ExitCode can come back empty
    $scan.WaitForExit()
    $rc = $scan.ExitCode
}
finally {
    if ($scan) { $scan.WaitForExit() }
    & dotnet $modelcheck export --batch-dir $dir --out "$dir/dataset"
    git add $dir
    $completed = Get-ChildItem "$dir/results/*.json" -ErrorAction SilentlyContinue |
        Where-Object { Select-String -Path $_ -SimpleMatch '"completed": true' -Quiet } |
        ForEach-Object { (Select-String -Path $_ -Pattern '^  "id": "(.*)"' | Select-Object -First 1).Matches.Groups[1].Value } |
        Sort-Object -Unique
    $models = (Select-String -Path "$dir/manifest.json" -SimpleMatch '"id":').Count
    git diff --cached --quiet
    if ($LASTEXITCODE -eq 0) { Write-Host "Nothing new to commit." }
    else {
        git commit -q -m "scan: $Name progress ($(@($completed).Count)/$models model file sets complete)"
        Write-Host "Committed: $(@($completed).Count)/$models complete."
        if (-not $NoPush) { git push }
    }
}
exit $rc
