#!/usr/bin/env bash
# Checks an Ollama model with modelcheck before pulling it. Refuses on high/critical findings unless --force.
#   ollama-safe-pull.sh llama3.2:1b
#   ollama-safe-pull.sh hf.co/bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M
#   ollama-safe-pull.sh --check-only qwen3:8b
set -uo pipefail
force=0; check_only=0; model=""
for arg in "$@"; do
  case "$arg" in
    --force) force=1 ;;
    --check-only) check_only=1 ;;
    *) model="$arg" ;;
  esac
done
[[ -n "$model" ]] || { echo "usage: $0 [--force] [--check-only] <model>" >&2; exit 64; }

modelcheck repo "ollama:$model" --min-severity medium
rc=$?
if (( rc == 3 )); then echo "modelcheck could not check $model; not pulling." >&2; exit 3; fi
if (( rc >= 2 && force == 0 )); then echo "High or critical findings for $model; not pulling. Re-run with --force to pull anyway." >&2; exit 2; fi
(( check_only )) && exit "$rc"
exec ollama pull "$model"
