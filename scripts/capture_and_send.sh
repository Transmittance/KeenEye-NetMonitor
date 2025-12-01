#!/bin/sh                                                                                          
                                                                                                   
PCAP="/opt/captures/cap.pcap"                                                                      
SERVER="http://192.168.1.130:5001/upload_pcap"                                                  
                                                                                                   
tcpdump -i br0 -w "$PCAP" -c 5000                                                                  
curl -X POST -F "file=@$PCAP" "$SERVER"