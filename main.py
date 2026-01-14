from flask import Flask, render_template, session, request, jsonify
import os, time, pyshark
from dataclasses import dataclass, asdict
import ipaddress

app = Flask(__name__)
app.secret_key = "k8BB8IsrvPg1ERYW7bfqyptmbHw3hzyh"
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
UPLOAD_DIR = "pcaps"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def is_local(ip):
    a = ipaddress.ip_address(ip)
    return a.is_private or a.is_loopback or a.is_link_local

def _as_list(val):
    if not val:
        return []
    return [x.strip() for x in str(val).split(",") if x.strip()]

def _is_dns_response(dns_layer):
    v = getattr(dns_layer, "flags_response", None)
    return str(v).strip().lower() in ("1", "true", "yes")

def build_dns_cache(path, limit_packets=None):
    cap = pyshark.FileCapture(path, keep_packets=False, display_filter="dns")
    ip2domain = {}

    for i, pkt in enumerate(cap):
        if limit_packets is not None and i >= limit_packets:
            break

        dns = pkt.dns
        if not _is_dns_response(dns):
            continue

        qname = getattr(dns, "qry_name", None)
        if not qname:
            continue
        qname = str(qname).strip()

        ips = _as_list(getattr(dns, "a", None)) + _as_list(getattr(dns, "aaaa", None))
        for ip in ips:
            ip2domain[ip] = qname

    cap.close()
    return ip2domain

@dataclass
class FlowStats:
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    t_start: float
    t_end: float
    packets: int = 0
    bytes: int = 0
    fwd_packets: int = 0
    fwd_bytes: int = 0
    rev_packets: int = 0
    rev_bytes: int = 0

def normalize_key(src, dst, sport, dport, proto):
    a = (src, dst, sport, dport, proto)
    b = (dst, src, dport, sport, proto)
    if a <= b:
        return a, True
    return b, False

def finalize_flow(f, ip2domain=None):
    duration = max(0.0, f.t_end - f.t_start)

    out = asdict(f)
    out["duration"] = duration
    out["avg_pkt_size"] = (f.bytes / f.packets) if f.packets else 0.0
    out["pps"] = (f.packets / duration) if duration > 0 else 0.0
    out["bps"] = (f.bytes / duration) if duration > 0 else 0.0

    ext_ip = None
    domain = None

    if ip2domain:
        src_local = is_local(out["src"])
        dst_local = is_local(out["dst"])

        if src_local and not dst_local:
            ext_ip = out["dst"]
        elif dst_local and not src_local:
            ext_ip = out["src"]
        else:
            ext_ip = out["dst"]

        domain = ip2domain.get(ext_ip) or ip2domain.get(out["dst"]) or ip2domain.get(out["src"])

    out["ext_ip"] = ext_ip
    out["domain"] = domain
    return out

def pcap_to_flows(path, idle_timeout=30.0, active_timeout=300.0, limit_packets=None, ip2domain=None):
    cap = pyshark.FileCapture(path, keep_packets=False)

    flows = {}
    out = []

    def close_flow(key):
        f = flows.pop(key, None)
        if f:
            out.append(finalize_flow(f, ip2domain=ip2domain))

    for i, pkt in enumerate(cap):
        if limit_packets is not None and i >= limit_packets:
            break

        if not hasattr(pkt, "ip"):
            continue

        if hasattr(pkt, "tcp"):
            proto = "TCP"
            sport = int(pkt.tcp.srcport)
            dport = int(pkt.tcp.dstport)
        elif hasattr(pkt, "udp"):
            proto = "UDP"
            sport = int(pkt.udp.srcport)
            dport = int(pkt.udp.dstport)
        else:
            continue

        src = str(pkt.ip.src)
        dst = str(pkt.ip.dst)
        ts = float(pkt.sniff_timestamp)
        length = int(pkt.length)

        key, is_fwd = normalize_key(src, dst, sport, dport, proto)

        if key not in flows:
            flows[key] = FlowStats(
                src=key[0], dst=key[1], sport=key[2], dport=key[3], proto=key[4],
                t_start=ts, t_end=ts
            )

        f = flows[key]

        if (ts - f.t_end) > idle_timeout or (ts - f.t_start) > active_timeout:
            close_flow(key)
            flows[key] = FlowStats(
                src=key[0], dst=key[1], sport=key[2], dport=key[3], proto=key[4],
                t_start=ts, t_end=ts
            )
            f = flows[key]

        f.packets += 1
        f.bytes += length
        f.t_end = ts

        if is_fwd:
            f.fwd_packets += 1
            f.fwd_bytes += length
        else:
            f.rev_packets += 1
            f.rev_bytes += length

    cap.close()

    for key in list(flows.keys()):
        close_flow(key)

    return out

@app.get("/pcap/<name>")
def show_pcap(name):
    path = os.path.join(UPLOAD_DIR, name)

    ip2domain = build_dns_cache(path)
    flows = pcap_to_flows(path, ip2domain=ip2domain, limit_packets=5000)
    flows.sort(key=lambda f: f["bytes"], reverse=True)

    return render_template("pcap_view.html", flows=flows, name=name)

@app.route('/')
def index():
    pcaps = []
    for name in sorted(os.listdir(UPLOAD_DIR), reverse=True):
        if name.endswith(".pcap"):
            path = os.path.join(UPLOAD_DIR, name)
            pcaps.append({
                "name": name,
                "size_mb": round(os.path.getsize(path) / (1024*1024), 2),
                "mtime": time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(os.path.getmtime(path)))
            })

    return render_template("main.html", pcaps=pcaps)

@app.post("/upload_pcap")
def upload_pcap():
    f = request.files["file"]
    fname = f"cap_{int(time.time())}.pcap"
    path = os.path.join(UPLOAD_DIR, fname)
    f.save(path)
    return jsonify({"status": "ok", "file": fname})

if __name__ == '__main__':
    app.run(host="192.168.1.130", port=5001)
    app.secret_key = 'k8BB8IsrvPg1ERYW7bfqyptmbHw3hzyh'