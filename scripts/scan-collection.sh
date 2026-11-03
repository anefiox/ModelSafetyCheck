#!/usr/bin/env bash
# Works through a pinned scan collection (scans/<name>/manifest.json) and shares progress through git, so a scan can be
# stopped on one machine (Ctrl+C) and continued on another. Each run: pull, scan what is not done yet, export the
# dataset, commit scans/<name> and push. Completed models are never downloaded again at the same scanner commit.
#   scripts/scan-collection.sh                       # scans/hf-top100
#   scripts/scan-collection.sh hf-top100 --no-push   # commit locally only
#   scripts/scan-collection.sh hf-top100 --max-total-gb 200   # stop after ~200 GB of downloads this session
set -uo pipefail
name="hf-top100"; push=1; total_gb=2500
while (( $# )); do
  case "$1" in
    --no-push) push=0 ;;
    --max-total-gb) total_gb="$2"; shift ;;
    -*) echo "usage: $0 [name] [--no-push] [--max-total-gb N]" >&2; exit 64 ;;
    *) name="$1" ;;
  esac
  shift
done
root="$(cd "$(dirname "$0")/.." && pwd)"
dir="scans/$name"
cd "$root" || exit 3
[[ -f "$dir/manifest.json" ]] || { echo "No $dir/manifest.json; create one with: modelcheck batch ... --write-manifest $dir/manifest.json" >&2; exit 64; }

git pull --rebase --autostash || { echo "git pull failed; resolve it, then rerun." >&2; exit 3; }
git submodule update --init
dotnet build src/ModelSafetyCheck.Cli -c Release -nologo -v q || exit 3
modelcheck=(dotnet src/ModelSafetyCheck.Cli/bin/Release/net10.0/modelcheck.dll)

# Ctrl+C reaches modelcheck, which records the interrupted model as incomplete and exits; the trap only keeps this
# script alive so the finished models still get committed.
trap 'echo "Stopping; saving progress..." >&2' INT
"${modelcheck[@]}" batch --manifest "$dir/manifest.json" --directory "$dir" --max-total-gb "$total_gb" --min-severity medium
rc=$?
trap - INT

"${modelcheck[@]}" export --batch-dir "$dir" --out "$dir/dataset"
git add "$dir"
done_count=$(grep -l '"completed": true' "$dir"/results/*.json 2>/dev/null | xargs -r grep -h '^  "id":' | sort -u | wc -l)
models=$(grep -c '"id":' "$dir/manifest.json")
if git diff --cached --quiet; then
  echo "Nothing new to commit."
else
  git commit -q -m "scan: $name progress ($done_count/$models model file sets complete)" && echo "Committed: $done_count/$models complete."
  (( push )) && git push
fi
exit "$rc"
