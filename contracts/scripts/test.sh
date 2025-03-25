#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "$0")/.."

# Find and test all directories containing a Move.toml file
directories=$(find . -type f -name "Move.toml" -exec dirname {} \;)

for dir in $directories; do
  echo "$ aptos move test --package-dir \"${dir}\""
  aptos move test --package-dir "$dir"
done
