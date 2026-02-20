from pathlib import Path
from flask import Response, Flask, render_template, request, jsonify
import sys, os, re, time, pyshark, uuid, threading, json, csv, signal
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import ipaddress
import paramiko
import numpy as np
import pandas as pd
from catboost import CatBoostClassifier
import subprocess

app = Flask(__name__)
app.secret_key = "k8BB8IsrvPg1ERYW7bfqyptmbHw3hzyh"
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

ROUTER_HOST = "192.168.1.1"
ROUTER_USER = "root"
ROUTER_KEY = os.path.expanduser("~/.ssh/keeneye_router")
ROUTER_SINGLE_CAPTURE_SCRIPT = "/opt/keeneye/capture_and_send.sh"

REMOTE_PCAP_DIR = "/opt/keeneye/captures/continious_capture"
REMOTE_CAPTURE_SH = "/opt/keeneye/capture_rotate.sh"
REMOTE_STOP_SH = "/opt/keeneye/capture_rotation_stop.sh"
CHUNK_SEC = 5

LOCAL_SPOOL_DIR = "spool"
os.makedirs(LOCAL_SPOOL_DIR, exist_ok=True)

MODEL_PATH = "./port_scanning/portscan_detection_cb.cbm"

ALERT_THRESHOLD = 0.8
ALERT_K = 2
ALERT_WINDOW_SEC = 60

DELETE_REMOTE_AFTER_DOWNLOAD = False
DELETE_LOCAL_AFTER_PROCESS = False

capture_ssh = None
capture_ssh_lock = threading.Lock()

with open("./port_scanning/fill_median.json") as f:
    FILLNA_MEDIAN = json.load(f)

UPLOAD_DIR = "pcaps"
os.makedirs(UPLOAD_DIR, exist_ok=True)

_jobs = {}
_jobs_lock = threading.Lock()

FEATURES = [
    'flows_total',
    'pkts_out', 'pkts_in',
    'bytes_out', 'bytes_in',
    'tcp_flows', 'udp_flows',
    'unique_dst_ports', 'unique_dst_ips',
    'mean_flow_duration', 'p95_flow_duration',
    'mean_packets_per_flow', 'p95_packets_per_flow',
    'syn_count', 'rst_count',
    'entropy_dst_port', 'entropy_dst_ip',
    'rst_per_syn'
]

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

    # TCP flags counters (0 for non-TCP)
    tcp_syn: int = 0
    tcp_rst: int = 0
    tcp_ack: int = 0
    tcp_fin: int = 0

    # Fields that help identify the initiator
    initiator: str = None
    responder: str = None
    initiator_is_key_src: bool = True

#1 ––––––––––- pcap to flows with dns ––––––––––-

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

def build_dns_cache(path):
    cap = pyshark.FileCapture(path, keep_packets=False, display_filter="dns")
    ip2domain = {}

    for _, pkt in enumerate(cap):
        if not hasattr(pkt, "dns"):
            continue

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

def normalize_key(src, dst, sport, dport, proto):
    if (src, sport) <= (dst, dport):
        return (src, dst, sport, dport, proto), True
    return (dst, src, dport, sport, proto), False

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
    out["initiator"] = f.initiator
    out["responder"] = f.responder
    out["initiator_is_key_src"] = f.initiator_is_key_src
    return out

def _flag(v):
    return str(v).strip().lower() in ("1", "true", "yes")

def pcap_to_flows(path, idle_timeout=30.0, active_timeout=300.0, ip2domain=None):
    cap = pyshark.FileCapture(path, keep_packets=False)

    flows = {}
    out = []

    def close_flow(key):
        f = flows.pop(key, None)
        if f:
            out.append(finalize_flow(f, ip2domain=ip2domain))

    for _, pkt in enumerate(cap):
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
            first_src = src
            first_dst = dst

            flows[key] = FlowStats(
                src=key[0], dst=key[1], sport=key[2], dport=key[3], proto=key[4],
                t_start=ts, t_end=ts, initiator=first_src, responder=first_dst,
                initiator_is_key_src=(first_src == key[0])
            )

        f = flows[key]
        from_initiator = (src == f.initiator)

        if (ts - f.t_end) > idle_timeout or (ts - f.t_start) > active_timeout:
            close_flow(key)
            first_src = src
            first_dst = dst

            flows[key] = FlowStats(
                src=key[0], dst=key[1], sport=key[2], dport=key[3], proto=key[4],
                t_start=ts, t_end=ts, initiator=first_src, responder=first_dst,
                initiator_is_key_src=(first_src == key[0])
            )
            f = flows[key]

        f.packets += 1
        f.bytes += length
        f.t_end = ts

        if from_initiator:
            f.fwd_packets += 1
            f.fwd_bytes += length
        else:
            f.rev_packets += 1
            f.rev_bytes += length

        if proto == "TCP":
            f.tcp_syn += _flag(pkt.tcp.flags_syn)
            f.tcp_rst += _flag(pkt.tcp.flags_reset)
            f.tcp_ack += _flag(pkt.tcp.flags_ack)
            f.tcp_fin += _flag(pkt.tcp.flags_fin)

            syn = _flag(pkt.tcp.flags_syn)
            ack = _flag(pkt.tcp.flags_ack)
            if syn and not ack:
                flows[key].initiator = str(pkt.ip.src)
                flows[key].responder = str(pkt.ip.dst)
                flows[key].initiator_is_key_src = (flows[key].initiator == flows[key].src)
                from_initiator = (src == f.initiator)

    cap.close()

    for key in list(flows.keys()):
        close_flow(key)

    return out

#2 ––––––––––- capture pcap through an SSH connection ––––––––––-

def _job_update(job_id, **fields):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return
        job.update(fields)
        job["updated_at"] = time.time()

def _job_get(job_id):
    with _jobs_lock:
        j = _jobs.get(job_id)
        return dict(j) if j else None

def _run_capture_job(job_id, limit_packets):
    _job_update(job_id, status="running", line="")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            ROUTER_HOST,
            port=222,
            username=ROUTER_USER,
            key_filename=ROUTER_KEY,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
        )

        cmd = f"sh {ROUTER_SINGLE_CAPTURE_SCRIPT} {job_id} {int(limit_packets)}"
        stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
        chan = stdout.channel

        got_line = None

        while True:
            if chan.recv_ready():
                data = chan.recv(4096).decode("utf-8", "ignore")
                for line in data.splitlines():
                    line = line.strip()
                    if line.startswith("Got "):
                        got_line = line
                        _job_update(job_id, line=got_line)

            if chan.recv_stderr_ready():
                data = chan.recv_stderr(4096).decode("utf-8", "ignore")
                for line in data.splitlines():
                    line = line.strip()
                    if line.startswith("Got "):
                        got_line = line
                        _job_update(job_id, line=got_line)

            if chan.exit_status_ready():
                break

            time.sleep(0.1)

        exit_code = chan.recv_exit_status()
        if exit_code != 0:
            _job_update(job_id, status="failed", error=f"exit_code={exit_code}")
            return

        _job_update(job_id, status="done", line=got_line or "Got 0")

    except Exception as e:
        _job_update(job_id, status="failed", error=str(e))
    finally:
        try:
            ssh.close()
        except Exception:
            pass

#3 ––––––––––- identify devices connected to the network ––––––––––-

def _ssh_exec(cmd):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        ROUTER_HOST,
        port=222,
        username=ROUTER_USER,
        key_filename=ROUTER_KEY,
        timeout=10,
        banner_timeout=10,
        auth_timeout=10,
    )
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode("utf-8", "ignore")
        err = stderr.read().decode("utf-8", "ignore")
        return out if out.strip() else err
    finally:
        ssh.close()

def _parse_ndmc_kv_blocks(text):
    blocks = []
    cur = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        if line.startswith("lease:"):
            if cur:
                blocks.append(cur)
            cur = {}
            continue

        if cur is None:
            continue

        m = re.match(r"^([a-zA-Z0-9_]+):\s*(.*)$", line)
        if not m:
            continue

        k = m.group(1).strip()
        v = m.group(2).strip()
        cur[k] = v if v != "" else None

    if cur:
        blocks.append(cur)

    return blocks

def _read_dhcp_bindings():
    raw = _ssh_exec('ndmc -c "show ip dhcp bindings"')
    leases = _parse_ndmc_kv_blocks(raw)

    out = {}
    for l in leases:
        ip = l.get("ip")
        mac = (l.get("mac") or "").lower()
        if not mac:
            continue

        expires = l.get("expires")
        out[mac] = {
            "dhcp_ip": ip,
            "hostname": l.get("hostname"),
            "dhcp_name": l.get("name"),
            "expires": int(expires) if (expires and str(expires).isdigit()) else None,
            "via": l.get("via"),
        }

    return out

def _read_hotspot_table():
    raw = _ssh_exec('ndmq -x -p "show ip hotspot"')
    lines = raw.splitlines()

    cur_mac = None
    cur_ip = None
    cur_name = None

    out = {}

    def commit():
        nonlocal cur_mac, cur_ip, cur_name
        if not cur_mac:
            return
        mac = cur_mac.lower()
        ip = (cur_ip or "").strip()
        name = (cur_name or "").strip() or None

        online = bool(ip and ip != "0.0.0.0")

        out[mac] = {
            "mac": mac,
            "ip": ip if ip else None,
            "name": name,
            "online": online,
        }

        cur_mac = None
        cur_ip = None
        cur_name = None

    for raw_line in lines:
        line = raw_line.strip()

        m = re.search(r"<mac>([^<]+)</mac>", line, re.I)
        if m:
            commit()
            cur_mac = m.group(1).strip()
            continue

        m = re.search(r"<ip>([^<]+)</ip>", line, re.I)
        if m and cur_mac:
            cur_ip = m.group(1).strip()
            continue

        m = re.search(r"<name>([^<]+)</name>", line, re.I)
        if m and cur_mac:
            if cur_name is None:
                cur_name = m.group(1).strip()
            continue

    commit()
    return out

def _mac12(mac):
    s = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()
    return s if re.compile(r"^[0-9a-f]{12}$").match(s) else None

def _load(path):
    with open(path, encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        return {row["Assignment"].lower(): row["Organization Name"].strip() for row in r}

DB = {**_load("vendors/ma-s.csv"), **_load("vendors/ma-m.csv"), **_load("vendors/ma-l.csv")}

def _is_randomized_mac(mac):
    s = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    return len(s) == 12 and (int(s[:2], 16) & 2) != 0

def _vendor_from_mac(mac):
    m = _mac12(mac)
    if not m: return None
    if not m: "Bad MAC"

    if _is_randomized_mac(mac):
        return "[Private]"
    return DB.get(m[:9]) or DB.get(m[:7]) or DB.get(m[:6])

def _guess_device_type(mac, vendor, hostname):
    v = (vendor or "").lower()
    h = (hostname or "").lower()

    # Phones or tablets
    phone_h = (
        "iphone","ipad","ios","android","samsung","galaxy","pixel","huawei","honor",
        "xiaomi","redmi","mi","oppo","vivo","oneplus","realme","motorola","moto","nokia","phone",
    )
    if any(x in h for x in phone_h) or any(x in v for x in ("apple","samsung","xiaomi","huawei","honor","oppo","vivo","oneplus","google")):
        return "Phone/Tablet"

    # PCs or laptops
    pc_h = ("macbook","imac","macmini","windows","win","pc","laptop","notebook","desktop","thinkpad","latitude","xps","spectre","envy","ideapad","legion","zenbook","vivobook")
    pc_v = ("intel","amd","dell","lenovo","hp","hewlett packard","asus","acer","msi","micro-star","fujitsu","toshiba","sony","lg electronics")
    if any(x in h for x in pc_h) or any(x in v for x in pc_v):
        return "PC/Laptop"

    # Router etc
    net_h = ("router","gateway","ap","access point","switch","bridge","keenetic","mikrotik","ubiquiti","unifi","edge","openwrt")
    net_v = ("keenetic","zyxel","mikrotik","ubiquiti","tp-link","netgear","d-link","cisco","aruba","juniper","huawei technologies")
    if any(x in h for x in net_h) or any(x in v for x in net_v):
        return "Router/Network"

    # TV etc
    tv_h = ("tv","androidtv","smarttv","bravia","tizen","webos","chromecast","shield","firetv","roku","appletv","mi box","settop","stb")
    tv_v = ("sony","samsung","lg","roku","google","amazon","nvidia","sonos","bose","yamaha","denon","pioneer")
    if any(x in h for x in tv_h) or any(x in v for x in tv_v):
        return "TV/Media"

    # Printers etc
    pr_h = ("printer","print","mfp","laserjet","deskjet","officejet","envy","epson","canon","brother","xerox","ricoh","kyocera")
    pr_v = ("hp","hewlett packard","epson","canon","brother","xerox","ricoh","kyocera","konica minolta","lexmark")
    if any(x in h for x in pr_h) or any(x in v for x in pr_v):
        return "Printer/Scanner"

    # Cameras etc
    cam_h = ("cam","camera","ipcam","door","doorbell","nvr","dvr","hik","dahua","reolink","ezviz","uniview","wyze","arlo","ring")
    cam_v = ("hikvision","dahua","reolink","ezviz","uniview","axis","ring","arlo","wyze","ubiquiti")
    if any(x in h for x in cam_h) or any(x in v for x in cam_v):
        return "Camera/Security"

    # IoT
    iot_h = ("iot","tuya","smart","plug","bulb","light","lamp","switch","socket","thermostat","sensor","gateway","zigbee","z-wave","matter","homekit","alexa","googlehome")
    iot_v = ("tuya","aqara","xiaomi","yeelight","philips","signify","ikea","shelly","sonoff","espressif","broadlink","tplink","amazon","google")
    if any(x in h for x in iot_h) or any(x in v for x in iot_v):
        return "IoT/SmartHome"

    # Gaming consoles
    game_h = ("playstation","ps4","ps5","xbox","nintendo","switch")
    game_v = ("sony","microsoft","nintendo")
    if any(x in h for x in game_h) or any(x in v for x in game_v):
        return "Game Console"

    # Servers etc
    nas_h = ("nas","synology","qnap","truenas","freenas","unraid","server","proxmox","esxi","vmware")
    nas_v = ("synology","qnap","asustor","wd","western digital","seagate","netapp","dell emc","hpe")
    if any(x in h for x in nas_h) or any(x in v for x in nas_v):
        return "NAS/Server"

    if _is_randomized_mac(mac):
        return "[Private]"

    return "Unknown (vendor-based)" if vendor else "Unknown"

def _get_devices_snapshot():
    hotspot = _read_hotspot_table()      # mac -> {mac, ip, name, online}
    dhcp = _read_dhcp_bindings()         # mac -> {dhcp_ip, hostname, dhcp_name, expires, via}

    by_mac = {}

    for mac, h in hotspot.items():
        d = dhcp.get(mac, {})
        vendor = _vendor_from_mac(mac) 

        display_name = (
            d.get("dhcp_name")
            or h.get("name")
            or d.get("hostname")
            or None
        )
        if display_name == "Home" : display_name = d.get("hostname")

        dtype = _guess_device_type(mac, vendor, display_name or d.get("hostname") or "")

        ip = h.get("ip")
        if not ip or ip == "0.0.0.0":
            ip = d.get("dhcp_ip")

        by_mac[mac] = {
            "mac": mac,
            "ip": ip,
            "name": display_name,
            "hostname": d.get("hostname"),
            "expires": d.get("expires"),
            "online": bool(h.get("online")),
            "vendor": vendor,
            "type": dtype,
            "registered": mac in dhcp,
        }

    for mac, d in dhcp.items():
        if mac in by_mac:
            continue

        vendor = _vendor_from_mac(mac)
        display_name = d.get("dhcp_name") or d.get("hostname") or None
        dtype = _guess_device_type(mac, vendor, display_name or "")

        by_mac[mac] = {
            "mac": mac,
            "ip": d.get("dhcp_ip"),
            "name": display_name,
            "hostname": d.get("hostname"),
            "expires": d.get("expires"),
            "online": False,
            "vendor": vendor,
            "type": dtype,
            "registered": True,
        }

    devices = list(by_mac.values())

    devices.sort(key=lambda x: (
        x["online"] is False,
        x["registered"] is False,
        x.get("ip") or "",
        x["mac"],
    ))

    return devices

#4 ––––––––––- packet inspection for port scanning ––––––––––-

def entropy(s):
    vc = s.value_counts()
    if vc.sum() == 0:
        return 0.0
    p = vc / vc.sum()
    return float(-(p * np.log2(p)).sum())

def p95(s):
    return float(s.quantile(0.95)) if len(s) else 0.0

def agg_src(df, pcap_name):
    df = df.copy()
    df["pcap"] = pcap_name

    g = df.groupby(["pcap", "initiator"], as_index=False)

    out = g.agg(
        flows_total=("proto", "size"),
        pkts_out=("fwd_packets", "sum"),
        pkts_in=("rev_packets", "sum"),
        bytes_out=("fwd_bytes", "sum"),
        bytes_in=("rev_bytes", "sum"),
        tcp_flows=("proto", lambda s: int((s == "TCP").sum())),
        udp_flows=("proto", lambda s: int((s == "UDP").sum())),
        unique_dst_ports=("dport", pd.Series.nunique),
        unique_dst_ips=("dst", pd.Series.nunique),
        mean_flow_duration=("duration", "mean"),
        p95_flow_duration=("duration", p95),
        mean_packets_per_flow=("packets", "mean"),
        p95_packets_per_flow=("packets", p95),
        syn_count=("tcp_syn", "sum"),
        rst_count=("tcp_rst", "sum"),
    )

    ent_port = df.groupby(["pcap", "initiator"])["dport"].apply(entropy).reset_index(name="entropy_dst_port")
    ent_ip   = df.groupby(["pcap", "initiator"])["dst"].apply(entropy).reset_index(name="entropy_dst_ip")
    out = out.merge(ent_port, on=["pcap","initiator"], how="left").merge(ent_ip, on=["pcap","initiator"], how="left")

    out["rst_per_syn"] = out["rst_count"] / (out["syn_count"] + 1.0)

    for c in FEATURES:
        if c not in out.columns:
            out[c] = 0.0

    out = out.rename(columns={"initiator": "src"})

    return out[["pcap", "src"] + FEATURES]

def agg_pair(df, pcap_name):
    df = df.copy()
    df["pcap"] = pcap_name
    g = df.groupby(["pcap", "initiator", "responder"], as_index=False)
    out = g.agg(
        flows_total=("proto", "size"),
        unique_dst_ports=("dport", pd.Series.nunique),
        syn_count=("tcp_syn", "sum"),
        rst_count=("tcp_rst", "sum"),
    )
    return out.rename(columns={"initiator": "src", "responder": "dst"})

stop_event = threading.Event()

alerts_lock = threading.Lock()
alerts = []
MAX_ALERTS = 300

seen_lock = threading.Lock()
seen_remote = set()

sus_lock = threading.Lock()
sus_times = {}

model = CatBoostClassifier()
model.load_model(MODEL_PATH)

def push(ev):
    ev.setdefault("ts", datetime.utcnow().isoformat() + "Z")
    with alerts_lock:
        alerts.append(ev)
        if len(alerts) > MAX_ALERTS:
            del alerts[:-MAX_ALERTS]

def start_capture():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        ROUTER_HOST,
        port=222,
        username=ROUTER_USER,
        key_filename=ROUTER_KEY,
        timeout=10,
        banner_timeout=10,
        auth_timeout=10,
    )
    cmd = (
        f"{REMOTE_CAPTURE_SH} br0 {REMOTE_PCAP_DIR} {CHUNK_SEC} "
        f"</dev/null >/opt/keeneye/captures/keeneye_capture.log 2>&1 & echo $!"
    )

    _, stdout, _ = ssh.exec_command(cmd)
    pid = stdout.read().decode(errors="ignore").strip()
    push({"type": "system", "message": f"capture started pid={pid}"})
    return ssh

def stop_capture(ssh):
    try:
        ssh.exec_command(f"{REMOTE_STOP_SH} {REMOTE_PCAP_DIR}")
        push({"type": "system", "message": "capture stopped"})
    except Exception as e:
        push({"type": "system", "message": f"stop failed: {e}"})

def apply_alerts(df_src, df_pair, pcap_name):
    if df_src.empty:
        return

    push({"type": "system", "message": f"new pcap: {pcap_name}"})
    X = df_src[FEATURES].replace([np.inf, -np.inf], np.nan).astype(float)
    X = X.fillna(pd.Series(FILLNA_MEDIAN))
    proba = model.predict_proba(X)[:, 1]
    df_src = df_src.copy()
    df_src["proba"] = proba

    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=ALERT_WINDOW_SEC)

    for r in df_src.itertuples(index=False):
        if r.flows_total < 3:
            continue
        if r.syn_count == 0 and r.flows_total <= 1:
            continue
        src = r.src
        p = float(r.proba)

        push({"type": "system", "message": f"src={src} proba={p:.3f}"})

        if p < ALERT_THRESHOLD:
            continue

        with sus_lock:
            lst = sus_times.get(src, [])
            lst.append(now)
            lst = [t for t in lst if t >= cutoff]
            sus_times[src] = lst

            if len(lst) >= ALERT_K:
                top = []
                if df_pair is not None and not df_pair.empty:
                    sub = df_pair[df_pair["src"] == src].sort_values("flows_total", ascending=False).head(5)
                    for rr in sub.itertuples(index=False):
                        top.append({
                            "dst": rr.dst,
                            "flows_total": int(rr.flows_total),
                            "unique_dst_ports": int(rr.unique_dst_ports),
                            "syn_count": int(rr.syn_count),
                            "rst_count": int(rr.rst_count),
                        })

                push({
                    "type": "alert",
                    "pcap": pcap_name,
                    "src": src,
                    "proba": p,
                    "message": f"Port scan suspected from {src} (p={p:.3f}, {ALERT_K} in {ALERT_WINDOW_SEC}s)",
                    "top_targets": top,
                })
                sus_times[src] = []

def rsync_pull():
    ssh_cmd = f"ssh -p 222 -i {ROUTER_KEY} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    remote = f"{ROUTER_USER}@{ROUTER_HOST}:{REMOTE_PCAP_DIR}/"
    local  = str(LOCAL_SPOOL_DIR) + "/"

    r = subprocess.run(
        [
            "rsync", "-az",
            "--ignore-existing",
            "--include=*.pcap", "--exclude=*",
            "-e", ssh_cmd,
            remote, local
        ],
        capture_output=True,
        text=True
    )
    if r.returncode != 0:
        push({"type":"system","message": f"rsync failed rc={r.returncode}: {r.stderr.strip()}"})

def list_new_local_pcaps():
    return sorted(
        Path(LOCAL_SPOOL_DIR) / f
        for f in os.listdir(LOCAL_SPOOL_DIR)
        if f.endswith(".pcap")
    )

def worker():
    global capture_ssh
    ssh = None
    try:
        ssh = start_capture()
        with capture_ssh_lock:
            capture_ssh = ssh

        while not stop_event.is_set():
            try:
                rsync_pull()

                for p in list_new_local_pcaps():
                    n = p.name
                    with seen_lock:
                        if n in seen_remote:
                            continue
                        seen_remote.add(n)

                    try:
                        ip2domain = build_dns_cache(str(p))
                        flows = pcap_to_flows(str(p), ip2domain=ip2domain)
                        df = pd.DataFrame(flows)

                        if not df.empty:
                            df_src = agg_src(df, n)
                            df_pair = agg_pair(df, n)
                            apply_alerts(df_src, df_pair, n)
                                
                        if DELETE_LOCAL_AFTER_PROCESS:
                            try:
                                p.unlink()
                            except Exception:
                                pass

                    except Exception as e:
                        push({"type": "system", "message": f"process failed {n}: {e}"})

                time.sleep(0.5)

            except Exception as e:
                push({"type": "system", "message": f"loop error: {e}"})
                time.sleep(1.0)

    finally:
        if ssh is not None:
            try:
                stop_capture(ssh)
            except Exception as e:
                push({"type": "system", "message": f"stop_capture failed: {e}"})

            try:
                cleanup_remote_spool(ssh)
            except Exception:
                pass
    
            try:
                ssh.close()
            except Exception as e:
                push({"type": "system", "message": f"ssh close failed: {e}"})

        with capture_ssh_lock:
            capture_ssh = None

def cleanup_local_spool():
    try:
        for f in os.listdir(LOCAL_SPOOL_DIR):
            if f.endswith(".pcap"):
                os.unlink(os.path.join(LOCAL_SPOOL_DIR, f))
    except Exception as e:
        push({"type": "system", "message": f"cleanup local spool failed: {e}"})

def cleanup_remote_spool(ssh):
    try:
        ssh.exec_command(f"rm -f {REMOTE_PCAP_DIR}/*.pcap")
    except Exception as e:
        push({"type": "system", "message": f"cleanup remote spool failed: {e}"})


@app.get("/api/alerts")
def api_alerts():
    with alerts_lock:
        return jsonify(alerts[-MAX_ALERTS:])

@app.get("/api/status")
def api_status():
    return jsonify({
        "running": not stop_event.is_set(),
        "router": f"{ROUTER_USER}@{ROUTER_HOST}:{222}",
        "iface": "br0",
        "remote_dir": REMOTE_PCAP_DIR,
        "chunk_sec": CHUNK_SEC,
        "threshold": ALERT_THRESHOLD,
        "K": ALERT_K,
        "window_sec": ALERT_WINDOW_SEC,
        "model": MODEL_PATH,
        "local_spool": str(LOCAL_SPOOL_DIR),
    })

_worker_thread = None

def start_worker():
    global _worker_thread
    if _worker_thread and _worker_thread.is_alive():
        return
    _worker_thread = threading.Thread(target=worker, daemon=True)
    _worker_thread.start()
    push({"type": "system", "message": "worker started"})

def shutdown_handler(signum, frame):
    global capture_ssh
    stop_event.set()

    with capture_ssh_lock:
        ssh = capture_ssh
        capture_ssh = None

    if ssh is not None:
        try:
            stop_capture(ssh)
        except Exception as e:
            push({"type":"system", "message": f"stop_capture in handler failed: {e}"})

        try:
            cleanup_remote_spool(ssh)
        except Exception:
            pass
        
        try:
            ssh.close()
        except Exception:
            pass

        cleanup_local_spool()

    sys.exit(0)


signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

start_worker()

#5 ––––––––––- flask routes ––––––––––-

@app.post("/capture/start")
def capture_start():
    limit = int(request.json.get("limit", 5000)) if request.is_json else 5000
    job_id = uuid.uuid4().hex

    with _jobs_lock:
        _jobs[job_id] = {
            "id": job_id,
            "status": "queued",
            "line": "Queued",
            "error": None,
            "pcap_name": None,
            "created_at": time.time(),
            "updated_at": time.time(),
        }

    t = threading.Thread(target=_run_capture_job, args=(job_id, limit), daemon=True)
    t.start()

    return jsonify({"job_id": job_id})

@app.get("/capture/status/<job_id>")
def capture_status(job_id):
    j = _job_get(job_id)
    if not j:
        return jsonify({"error": "not found"}), 404
    return jsonify(j)

@app.get("/capture/stream/<job_id>")
def capture_stream(job_id):
    def gen():
        last_sent = None
        while True:
            j = _job_get(job_id)
            if not j:
                yield "event: error\ndata: {}\n\n"
                return

            payload = json.dumps({
                "status": j.get("status"),
                "line": j.get("line"),
                "error": j.get("error"),
                "pcap_name": j.get("pcap_name"),
            }, ensure_ascii=False)

            if payload != last_sent:
                yield f"data: {payload}\n\n"
                last_sent = payload

            if j.get("status") in ("done", "failed"):
                return

            time.sleep(0.3)

    return Response(gen(), mimetype="text/event-stream")

@app.get("/pcap/<name>")
def show_pcap(name):
    path = os.path.join(UPLOAD_DIR, name)

    ip2domain = build_dns_cache(path)
    flows = pcap_to_flows(path, ip2domain=ip2domain)
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

    job_id = request.args.get("job_id")

    name = f"cap_{int(time.time())}.pcap"
    path = os.path.join(UPLOAD_DIR, name)
    f.save(path)

    if job_id:
        _job_update(job_id, status="done", line="Done", pcap_name=name)

    return "ok"

@app.get("/capture")
def capture_page():
    return render_template("capture.html")

@app.get("/devices")
def devices_page():
    return render_template("devices.html")

@app.get("/api/devices")
def devices_api():
    return jsonify({"ok": True, "devices": _get_devices_snapshot()})

@app.get("/debug_alerts")
def debug_page():
    return render_template("debug_alerts.html")

if __name__ == '__main__':
    app.run(host="192.168.1.63", port=5001, use_reloader=False)
    app.secret_key = 'k8BB8IsrvPg1ERYW7bfqyptmbHw3hzyh'