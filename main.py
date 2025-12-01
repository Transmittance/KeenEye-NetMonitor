from flask import Flask, render_template, session, request, jsonify
import os, time, pyshark


app = Flask(__name__)
app.secret_key = "k8BB8IsrvPg1ERYW7bfqyptmbHw3hzyh"
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
UPLOAD_DIR = "pcaps"
os.makedirs(UPLOAD_DIR, exist_ok=True)

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

@app.get("/pcap/<name>")
def show_pcap(name):
    path = os.path.join(UPLOAD_DIR, name)
    packets = pcap_to_packets(path, limit=5000)
    return render_template("pcap_view.html", packets=packets, name=name)

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
    app.run(host="0.0.0.0", port=5001)
    app.secret_key = 'k8BB8IsrvPg1ERYW7bfqyptmbHw3hzyh'