#!/usr/bin/env bash
# Checks a Hugging Face repo with modelcheck before downloading it with LM Studio's CLI (`lms get`).
# Refuses on high/critical findings unless --force.
#   lms-safe-get.sh lmstudio-community/gemma-4-12B-it-GGUF
set -uo pipefail
force=0; check_only=0; repo=""
for arg in "$@"; do
  case "$arg" in
    --force) force=1 ;;
    --check-only) check_only=1 ;;
    *) repo="$arg" ;;
  esac
done
[[ -n "$repo" ]] || { echo "usage: $0 [--force] [--check-only] <org/repo>" >&2; exit 64; }

modelcheck repo "$repo" --min-severity medium
rc=$?
if (( rc == 3 )); then echo "modelcheck could not check $repo; not downloading." >&2; exit 3; fi
if (( rc >= 2 && force == 0 )); then echo "High or critical findings for $repo; not downloading. Re-run with --force to download anyway." >&2; exit 2; fi
(( check_only )) && exit "$rc"
exec lms get "$repo"
