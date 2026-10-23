import json, random, sys, logging, warnings
warnings.filterwarnings("ignore"); logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
sys.path.insert(0, "src")
import pandas as pd, numpy as np
from scapy.all import wrpcap
import gen_pcaps as G
from parser import parse_pcap
from detectors import run_all, DETECTORS, CFG
import ml_iforest as ML

EXPECT = dict(portscan=["Port Scan"], pingsweep=["Ping Sweep"], arpspoof=["ARP Spoofing"],
              dnsenum=["DNS Enumeration", "DNS Zone Transfer"], ftpbrute=["FTP Brute Force"],
              synflood=["SYN Flood"], roguedhcp=["Rogue DHCP"])
T0 = 1700000000.0
is_att = lambda s: s in (G.ATT, G.mac(G.ATT)) or str(s).endswith("sources") or str(s).startswith("10.")

# held-out normal traffic + a slow (evasive) port scan
random.seed(99); wrpcap("pcaps/normal_test.pcap", G.normal(600))
random.seed(5)
slow = []
for i, dp in enumerate(random.sample(range(1, 10000), 80)):
    p = G.Ether(src=G.mac(G.ATT), dst=G.mac(G.SERVER))/G.IP(src=G.ATT, dst=G.SERVER)/G.TCP(sport=40001, dport=dp, flags="S"); p.time = T0 + 20 + i*1.5; slow.append(p)
wrpcap("pcaps/slowscan.pcap", sorted(G.normal(150) + slow, key=lambda p: p.time))

res = {}; alerts_all = {}
for name in ["normal", "normal_test"]:
    df = parse_pcap(f"pcaps/{name}.pcap"); al = run_all(df)
    res[name] = dict(packets=len(df), duration=round(df.t.max()-df.t.min(), 1), alerts=len(al))
for name in EXPECT:
    df = parse_pcap(f"pcaps/{name}.pcap"); al = run_all(df); alerts_all[name] = al
    exp = al[al.type.isin(EXPECT[name])] if len(al) else al
    tp = exp[exp.src.map(is_att)] if len(exp) else exp
    fp = al[~al.src.map(is_att)] if len(al) else al
    other = sorted(set(al.type) - set(EXPECT[name])) if len(al) else []
    res[name] = dict(packets=len(df), detected=bool(len(tp)) and set(EXPECT[name]) <= set(tp.type), types=sorted(tp.type.unique()) if len(tp) else [], latency=round(float(tp.time.min()-(T0+40)), 2) if len(tp) else None,
                     alerts=len(al), false_alerts=len(fp), also_fired=other)
df = parse_pcap("pcaps/slowscan.pcap"); al = run_all(df)
res["slowscan_rule"] = dict(packets=len(df), detected=bool(len(al) and al.src.map(is_att).any()))
# combined
dfc = parse_pcap("pcaps/combined.pcap"); alc = run_all(dfc); alc.to_csv("results/alerts_combined.csv", index=False)
res["combined"] = dict(packets=len(dfc), alerts=len(alc), attacker_alerts=int(alc.src.map(is_att).sum()), types=sorted(alc.type.unique()))
# ML
dfn = parse_pcap("pcaps/normal.pcap"); model = ML.train(dfn)
ml = {}
fnt = ML.predict(model, parse_pcap("pcaps/normal_test.pcap")); ml["normal_test_windows"] = len(fnt); ml["normal_test_flagged"] = int(fnt.anomaly.sum())
for name in EXPECT:
    f = ML.predict(model, parse_pcap(f"pcaps/{name}.pcap"))
    a = f[f.src.map(is_att)]; b = f[~f.src.map(is_att)]
    ml[name] = dict(att_windows=len(a), att_flagged=int(a.anomaly.sum()), benign_windows=len(b), benign_flagged=int(b.anomaly.sum()))
f = ML.predict(model, parse_pcap("pcaps/slowscan.pcap")); a = f[f.src.map(is_att)]
ml["slowscan"] = dict(att_windows=len(a), att_flagged=int(a.anomaly.sum()))
res["ml"] = ml

# threshold sensitivity (port scan): ports-per-5s threshold
sens = []
dfs = parse_pcap("pcaps/portscan.pcap"); dft = parse_pcap("pcaps/normal_test.pcap"); dfsl = parse_pcap("pcaps/slowscan.pcap")
from detectors import detect_portscan
for th in [2, 3, 5, 10, 20, 50, 100, 300]:
    c = dict(CFG, portscan_ports=th)
    sens.append(dict(threshold=th, scan_detected=bool(detect_portscan(dfs, c)), fp_on_normal=len(detect_portscan(dft, c)),
                     slow_detected=bool(detect_portscan(dfsl, c))))
res["sensitivity"] = sens
json.dump(res, open("results/results.json", "w"), indent=1, default=str)
for k, v in res.items(): print(k, v)
for n, a in alerts_all.items(): a.to_csv(f"results/alerts_{n}.csv", index=False)
