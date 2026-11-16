#!/bin/sh
# Builds the lab, runs scan.sh and creds.sh (or only those named) into tests/lab/out/, and tears the lab down.
set -eu
cd "$(dirname "$0")"
mkdir -p out
compose="docker compose"
docker compose version > /dev/null 2>&1 || compose=docker-compose
$compose up -d --build
trap '$compose down' EXIT
for script in ${@:-scan creds}; do
    case $script in scan) $compose exec -T scanner sh /lab/scan.sh ;; creds) until $compose exec -T dc test -f /ready; do sleep 3; done
            $compose exec -T dc python3 /lab.py ntds > out/arbor.ntds
            $compose exec -T creds sh /lab/creds.sh ;;
        *) echo "unknown: $script (scan or creds)" >&2; exit 1 ;; esac
done
echo "captures in $(pwd)/out"
