#!/usr/bin/env bash
# Fills the winget and Homebrew templates with a release's version, URLs and SHA-256 hashes.
# Usage: packaging/render.sh <tag> <dir with release archives> <owner/repo> <output dir>
set -euo pipefail
tag="$1"; dist="$2"; repo="$3"; out="$4"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
version="${tag#v}"
publisher="${repo%%/*}"
mkdir -p "$out/winget" "$out/homebrew"

args=(-e "s|{{TAG}}|$tag|g" -e "s|{{VERSION}}|$version|g" -e "s|{{REPO}}|$repo|g" -e "s|{{PUBLISHER}}|$publisher|g" -e "s|{{DATE}}|$(date -u +%Y-%m-%d)|g")
for rid in win-x64 win-arm64 linux-x64 linux-arm64 osx-arm64; do
  file=$(ls "$dist"/modelcheck-"$tag"-"$rid".* 2>/dev/null | head -n 1 || true)
  [[ -n "$file" ]] || { echo "missing archive for $rid in $dist" >&2; exit 1; }
  args+=(-e "s|{{SHA256_$rid}}|$(sha256sum "$file" | cut -d' ' -f1)|g")
done

for f in "$here"/winget/*.yaml; do
  name=$(basename "$f"); sed "${args[@]}" "$f" > "$out/winget/${publisher}.${name}"
done
sed "${args[@]}" "$here/homebrew/modelcheck.rb" > "$out/homebrew/modelcheck.rb"

if grep -rn '{{' "$out"; then echo "unfilled placeholders" >&2; exit 1; fi
echo "Rendered packaging for $tag into $out"
