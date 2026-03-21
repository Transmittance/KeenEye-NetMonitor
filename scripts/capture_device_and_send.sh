#!/bin/sh
set -eu

PCAP_DIR="./captures"
PCAP="$PCAP_DIR/cap_device.pcap"
SERVER="${KEENEYE_SERVER_URL:-http://192.168.1.82:5001/upload_pcap}"

JOB_ID="${1:-}"
LIMIT="${2:-}"
TARGET_IP="${3:-}"

if [ -z "$JOB_ID" ] || [ -z "$LIMIT" ] || [ -z "$TARGET_IP" ]; then
  echo "usage: $0 <job_id> <limit> <target_ip>" >&2
  exit 2
fi

mkdir -p "$PCAP_DIR"

# Capture only packets related to the selected online device IP.
tcpdump -i br0 -w "$PCAP" -c "$LIMIT" -v "host $TARGET_IP"
curl -s -X POST -F "file=@$PCAP" "$SERVER?job_id=$JOB_ID" >/dev/null
