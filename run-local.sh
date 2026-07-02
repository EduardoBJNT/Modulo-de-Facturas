#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

PYTHON_BIN="/Users/eduardorivera/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3"
VENV_DIR=".venv312"
if [ ! -x "$VENV_DIR/bin/python" ]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
pip install -r requirements.txt
export FLASK_ENV=development
export PORT="${PORT:-5050}"
export DB_PATH="${DB_PATH:-./cfdi_data.db}"
python server.py
