#!/bin/bash

core_ref="develop-plugins"

# Extract and trim the value after core_ref:, handle multiple spaces
if [[ $PR_BODY =~ core_ref:[[:space:]]*([^;[:space:]]+)[[:space:]]*$ ]]; then
  potential_ref="${BASH_REMATCH[1]}"
  
  # Only allow alphanumeric, dash, underscore, forward slash
  if [[ $potential_ref =~ ^[a-zA-Z0-9/_-]+$ ]]; then
    core_ref="$potential_ref"
  fi
fi

echo "core_ref=${core_ref}" >> "$GITHUB_ENV"
echo "core_ref=${core_ref}" >> "$GITHUB_OUTPUT"
