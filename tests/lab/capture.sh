#!/bin/sh
# Builds the lab, captures every scanner output format into tests/lab/out/, and tears the lab down.
set -eu
cd "$(dirname "$0")"
mkdir -p out
docker compose up -d --build
trap 'docker compose down' EXIT
docker compose exec -T scanner sh /lab/scan.sh
echo "captures in $(pwd)/out"
