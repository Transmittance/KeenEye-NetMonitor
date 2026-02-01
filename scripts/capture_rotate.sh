#!/bin/sh
set -eu

IFACE="${1:-br0}"
OUT_DIR="${2:-/opt/keeneye/continious_capture}"
CHUNK_SEC="${3:-5}"
PID_FILE="${OUT_DIR}/capture.pid"

mkdir -p "$OUT_DIR"

if [ -f "$PID_FILE" ]; then
  OLD_PID=$(cat "$PID_FILE" || true)
  if [ -n "${OLD_PID:-}" ] && kill -0 "$OLD_PID" 2>/dev/null; then
    exit 0
  fi
fi

echo $$ > "$PID_FILE"
trap 'rm -f "$PID_FILE"; exit 0' INT TERM EXIT

while true; do
  TS=$(date +%Y%m%d_%H%M%S)
  OUT="$OUT_DIR/cap_${TS}.pcap"
  TMP="$OUT.tmp"

  tcpdump -i "$IFACE" -s 0 -n -w "$TMP" >/dev/null 2>&1 &
  PID=$!

  sleep "$CHUNK_SEC"

  kill -INT "$PID" >/dev/null 2>&1 || true
  wait "$PID" >/dev/null 2>&1 || true

  if [ -s "$TMP" ]; then
    mv "$TMP" "$OUT"
  else
    rm -f "$TMP"
  fi
done
