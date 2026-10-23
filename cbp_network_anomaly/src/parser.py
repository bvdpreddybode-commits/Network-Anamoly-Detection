"""PCAP -> pandas DataFrame (one row per packet)."""
import logging; logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import pandas as pd
from scapy.all import PcapReader, Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, BOOTP, DHCP, Raw

def dhcp_type(p):
    for o in p[DHCP].options:
        if isinstance(o, tuple) and o[0] == "message-type": return o[1]
    return None

def parse_pcap(path):
    rows = []
    with PcapReader(path) as rd:
        for p in rd:
            r = dict(t=float(p.time), len=len(p), proto="OTHER", src=None, dst=None, smac=None,
                     sport=None, dport=None, flags="", icmp_type=None, arp_op=None, arp_psrc=None,
                     arp_hwsrc=None, dns_q=None, dns_qtype=None, ftp530=False, axfr=False,
                     dhcp=None, dhcp_server_mac=None)
            if Ether in p: r["smac"] = p[Ether].src
            if ARP in p:
                r.update(proto="ARP", arp_op=int(p[ARP].op), arp_psrc=p[ARP].psrc, arp_hwsrc=p[ARP].hwsrc,
                         src=p[ARP].psrc, dst=p[ARP].pdst)
            elif IP in p:
                r["src"], r["dst"] = p[IP].src, p[IP].dst
                if TCP in p:
                    t = p[TCP]; r.update(proto="TCP", sport=t.sport, dport=t.dport, flags=str(t.flags))
                    if Raw in p:
                        pl = bytes(p[Raw].load)
                        if t.sport == 21 and b"530" in pl: r["ftp530"] = True
                        if 53 in (t.sport, t.dport):
                            r["proto"] = "DNS"
                            if pl.endswith(b"\x00\xfc\x00\x01"): r["axfr"] = True
                    if r["proto"] == "TCP":
                        r["proto"] = {21: "FTP", 80: "HTTP", 443: "TLS"}.get(min(t.sport, t.dport) if min(t.sport,t.dport) in (21,80,443) else t.dport, "TCP")
                elif UDP in p:
                    u = p[UDP]; r.update(proto="UDP", sport=u.sport, dport=u.dport)
                    if DNS in p and p[DNS].qd is not None and p[DNS].qr == 0:
                        r.update(proto="DNS", dns_q=p[DNS].qd.qname.decode(errors="ignore"), dns_qtype=int(p[DNS].qd.qtype))
                    elif DNS in p: r["proto"] = "DNS"
                    if DHCP in p:
                        r["proto"] = "DHCP"; r["dhcp"] = dhcp_type(p)
                        if r["dhcp"] == 2: r["dhcp_server_mac"] = p[Ether].src
                elif ICMP in p:
                    r.update(proto="ICMP", icmp_type=int(p[ICMP].type))
            rows.append(r)
    return pd.DataFrame(rows)
