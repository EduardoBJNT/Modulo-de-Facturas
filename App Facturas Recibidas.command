#!/bin/bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"

PORT="${PORT:-5050}"
URL="http://127.0.0.1:${PORT}"

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "App ya está corriendo en ${URL}"
else
  echo "Iniciando App Facturas Recibidas..."
  nohup python3 server.py > /tmp/app_facturas_recibidas.log 2>&1 &
  for _ in {1..30}; do
    if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
fi

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  open "$URL"
else
  echo "No se pudo iniciar la app. Revisa /tmp/app_facturas_recibidas.log"
  exit 1
fi
