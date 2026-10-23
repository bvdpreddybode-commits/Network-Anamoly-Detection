"""Rule-based protocol-level detectors. Each returns a list of alert dicts."""
from collections import defaultdict
import pandas as pd

CFG = dict(
    portscan_ports=20,   portscan_win=5.0,
    sweep_hosts=10,      sweep_win=10.0,
    dns_queries=30,      dns_win=10.0,
    ftp_fail=5,          ftp_win=60.0,
    syn_rate=100,        syn_win=1.0,
)
def _alert(kind, t, src, detail, sev): return dict(type=kind, time=t, src=src, detail=detail, severity=sev)

def _sliding(events, win, thresh, key=lambda e: e):
    """events: list of (t, item) sorted by t. Return first time distinct(item) in window >= thresh."""
    from collections import deque, Counter
    dq, cnt = deque(), Counter()
    for t, it in events:
        dq.append((t, it)); cnt[it] += 1
        while dq and t - dq[0][0] > win:
            _, old = dq.popleft(); cnt[old] -= 1
            if cnt[old] == 0: del cnt[old]
        if len(cnt) >= thresh: return t, len(cnt)
    return None

def detect_portscan(df, c=CFG):
    out = []; syn = df[(df.proto.isin(["TCP","FTP","HTTP","TLS","DNS"])) & (df["flags"] == "S")]
    for (src, dst), g in syn.groupby(["src", "dst"]):
        r = _sliding(list(zip(g.t, g.dport)), c["portscan_win"], c["portscan_ports"])
        if r: out.append(_alert("Port Scan", r[0], src, f"{r[1]} distinct ports on {dst} within {c['portscan_win']}s (SYN, no handshake)", "HIGH"))
    return out

def detect_pingsweep(df, c=CFG):
    out = []; e = df[(df.proto == "ICMP") & (df.icmp_type == 8)]
    for src, g in e.groupby("src"):
        r = _sliding(list(zip(g.t, g.dst)), c["sweep_win"], c["sweep_hosts"])
        if r: out.append(_alert("Ping Sweep", r[0], src, f"ICMP echo to {r[1]} different hosts within {c['sweep_win']}s", "MEDIUM"))
    return out

def detect_arpspoof(df, c=CFG):
    out = []; bind = {}; seen = set()
    for r in df[df.proto == "ARP"].itertuples():
        if r.arp_op != 2: continue                      # replies carry bindings
        ip, mac = r.arp_psrc, r.arp_hwsrc
        if ip in bind and bind[ip] != mac and (ip, mac) not in seen:
            seen.add((ip, mac))
            out.append(_alert("ARP Spoofing", r.t, mac, f"IP {ip} changed MAC {bind[ip]} -> {mac}", "CRITICAL"))
        bind.setdefault(ip, mac)
    return out

def detect_dnsenum(df, c=CFG):
    out = []; q = df[(df.proto == "DNS") & df.dns_q.notna()]
    for src, g in q.groupby("src"):
        r = _sliding(list(zip(g.t, g.dns_q)), c["dns_win"], c["dns_queries"])
        if r: out.append(_alert("DNS Enumeration", r[0], src, f"{r[1]} unique names queried within {c['dns_win']}s", "MEDIUM"))
    for r in df[df.axfr].itertuples():
        out.append(_alert("DNS Zone Transfer", r.t, r.src, "AXFR request (QTYPE 252) over TCP/53", "HIGH"))
    return out

def detect_ftpbrute(df, c=CFG):
    out = []
    for dst, g in df[df.ftp530].groupby("dst"):        # failed-login replies go server -> attacker
        r = _sliding(list(zip(g.t, range(len(g)))), c["ftp_win"], c["ftp_fail"])
        if r: out.append(_alert("FTP Brute Force", r[0], dst, f"{r[1]} '530 Login incorrect' replies within {c['ftp_win']:.0f}s", "HIGH"))
    return out

def detect_synflood(df, c=CFG):
    out = []; syn = df[(df["flags"] == "S") & df.dport.notna()]
    for (dst, dp), g in syn.groupby(["dst", "dport"]):
        t = g.t.values; j = 0
        for i in range(len(t)):
            while t[i] - t[j] > c["syn_win"]: j += 1
            if i - j + 1 >= c["syn_rate"]:
                srcs = g.src.iloc[j:i+1].nunique()
                out.append(_alert("SYN Flood", float(t[i]), f"{srcs} sources", f"{i-j+1} SYNs/s to {dst}:{int(dp)} from {srcs} sources, handshakes not completed", "CRITICAL")); break
    return out

def detect_roguedhcp(df, c=CFG):
    off = df[(df.proto == "DHCP") & (df.dhcp == 2)]
    if off.smac.nunique() < 2: return []
    main = off.smac.value_counts().index[0]
    return [_alert("Rogue DHCP", r.t, r.smac, f"DHCP OFFER from {r.src} (legit server MAC {main})", "CRITICAL")
            for r in off[off.smac != main].drop_duplicates("smac").itertuples()]

DETECTORS = dict(portscan=detect_portscan, pingsweep=detect_pingsweep, arpspoof=detect_arpspoof,
                 dnsenum=detect_dnsenum, ftpbrute=detect_ftpbrute, synflood=detect_synflood, roguedhcp=detect_roguedhcp)
def run_all(df, c=CFG):
    al = [a for f in DETECTORS.values() for a in f(df, c)]
    return pd.DataFrame(sorted(al, key=lambda a: a["time"]))
