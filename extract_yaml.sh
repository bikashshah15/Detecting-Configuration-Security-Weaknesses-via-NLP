#!/bin/bash

set -e

SRC_DIR="repos"
OUT_DIR="all_yaml_raw"

mkdir -p "$OUT_DIR"

find "$SRC_DIR" -type f \( -name "*.yaml" -o -name "*.yml" \) | while read -r file; do
  base=$(basename "$file")
  repo=$(echo "$file" | cut -d'/' -f2)
  rel=$(echo "$file" | cut -d'/' -f3- | tr '/' '__')
  cp "$file" "$OUT_DIR/${repo}__${rel}"
done

echo "All YAML files copied to $OUT_DIR"