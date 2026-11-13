#!/usr/bin/env bash
# Wrapper cincan/volatility — TP CDSI M1
# Usage : ./vol.sh -f /data/memdump.raw <plugin> [options]
# Le répertoire courant est monté sur /data dans le conteneur.

set -euo pipefail

IMAGE="${VOL_IMAGE:-cincan/volatility:latest}"
WORKDIR="$(pwd)"

if ! command -v docker >/dev/null 2>&1; then
  echo "[!] Docker est requis." >&2
  exit 1
fi

# Lecture seule sur le dump pour préserver l'intégrité.
# /root/.cache et /root/.local sont en tmpfs pour Volatility 3 (cache en mémoire).
exec docker run --rm \
  -v "${WORKDIR}":/data \
  -w /data \
  --read-only \
  --tmpfs /tmp:rw,size=512m \
  --tmpfs /root/.cache:rw,size=256m \
  --tmpfs /root/.local:rw,size=256m \
  "${IMAGE}" "$@"
