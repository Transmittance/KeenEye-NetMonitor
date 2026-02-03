#!/bin/sh
set -eu

OUT_DIR="$1"
PID_FILE="${OUT_DIR}/capture.pid"

if [ ! -f "$PID_FILE" ]; then
  exit 0
fi

PID=$(cat "$PID_FILE" || true)
if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
  kill -TERM "$PID" 2>/dev/null || true
fi
rm -f "$PID_FILE"