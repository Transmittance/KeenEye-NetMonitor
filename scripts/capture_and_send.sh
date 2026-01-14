#!/bin/sh

PCAP_DIR="./captures"
PCAP="$PCAP_DIR/cap.pcap"
SERVER="http://192.168.1.130:5001/upload_pcap"

mkdir -p "$PCAP_DIR"

tcpdump -i br0 -w "$PCAP" -c 2500 -v
curl -X POST -F "file=@$PCAP" "$SERVER"