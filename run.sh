#!/usr/bin/env bash
# Blackwall'ı tek komutla başlatır: proxy (mitmdump) + web UI (uvicorn).
# Ctrl-C ikisini de kapatır.
set -euo pipefail
cd "$(dirname "$0")"

BIN="${BIN:-.venv/bin}"
PROXY_PORT="${PROXY_PORT:-8080}"
WEB_PORT="${WEB_PORT:-8000}"

if [ ! -x "$BIN/mitmdump" ] || [ ! -x "$BIN/uvicorn" ]; then
  echo "Sanal ortam yok. Önce: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

export BLACKWALL_DB="${BLACKWALL_DB:-$PWD/blackwall.db}"

echo "Proxy  : http://127.0.0.1:${PROXY_PORT}  (tarayıcı/cihaz proxy ayarı)"
echo "Web UI : http://127.0.0.1:${WEB_PORT}"
echo "DB     : ${BLACKWALL_DB}"

cleanup() { kill "${PROXY_PID:-}" "${WEB_PID:-}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

PYTHONPATH="$PWD" "$BIN/mitmdump" -s blackwall/addon.py --listen-port "$PROXY_PORT" &
PROXY_PID=$!

"$BIN/uvicorn" blackwall.web.app:app --host 127.0.0.1 --port "$WEB_PORT" &
WEB_PID=$!

wait
