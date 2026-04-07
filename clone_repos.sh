#!/bin/bash

set -e

mkdir -p repos
cd repos

while read -r repo; do
  [ -z "$repo" ] && continue
  echo "Cloning $repo ..."
  git clone --depth 1 "$repo"
done < ../repos.txt

echo "All repos cloned successfully."