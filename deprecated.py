def pcap_to_packets(path, limit=50):
    cap = pyshark.FileCapture(path, keep_packets=False)
    packets = []
    for i, pkt in enumerate(cap):
        if i >= limit:
            break

        src_ip = getattr(pkt.ip, "src", None) if hasattr(pkt, "ip") else None
        dst_ip = getattr(pkt.ip, "dst", None) if hasattr(pkt, "ip") else None
        proto  = pkt.highest_layer
        length = int(pkt.length)
        ts     = float(pkt.sniff_timestamp)

        sport = dport = None
        if hasattr(pkt, "tcp"):

            sport = int(pkt.tcp.srcport)
            dport = int(pkt.tcp.dstport)
        elif hasattr(pkt, "udp"):
            
            sport = int(pkt.udp.srcport)
            dport = int(pkt.udp.dstport)

        dns_name = None
        if hasattr(pkt, "dns"):

            if hasattr(pkt.dns, "qry_name"):
                dns_name = str(pkt.dns.qry_name)

            elif hasattr(pkt.dns, "resp_name"):
                dns_name = str(pkt.dns.resp_name)

        packets.append({
            "time": ts,
            "src": src_ip,
            "dst": dst_ip,
            "sport": sport,
            "dport": dport,
            "proto": proto,
            "len": length,
            "dns": dns_name
        })
    cap.close()
    return packets