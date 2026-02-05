#!/bin/sh

PCAP_DIR="./captures"
PCAP="$PCAP_DIR/cap.pcap"
SERVER="http://192.168.1.63:5001/upload_pcap"

JOB_ID="$1"
LIMIT="$2"

mkdir -p "$PCAP_DIR"

tcpdump -i br0 -w "$PCAP" -c "$LIMIT" -v
curl -s -X POST -F "file=@$PCAP" "$SERVER?job_id=$JOB_ID" >/dev/null