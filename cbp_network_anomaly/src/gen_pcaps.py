"""Generate labelled pcap datasets (normal + 7 attacks) with Scapy.
Traffic is synthesised with realistic protocol structure (TCP handshakes,
FTP 220/331/530/230 replies, DNS, ARP, DHCP, ICMP) for a 192.168.56.0/24 lab."""
import random, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
random.seed(7)
NET="192.168.56."
SERVER=NET+"10"; GW=NET+"1"; ATT=NET+"66"
MAC={SERVER:"08:00:27:aa:00:10",GW:"08:00:27:aa:00:01",ATT:"08:00:27:ee:00:66"}
clients=[NET+str(i) for i in range(20,30)]
for c in clients: MAC[c]="08:00:27:bb:00:%02x"%int(c.split('.')[-1])
def mac(ip): return MAC.setdefault(ip,"08:00:27:cc:%02x:%02x"%tuple(random.randint(0,255) for _ in range(2)))

def tcp_session(t,src,dst,sport,dport,payload_c=b"",payload_s=b"",rtt=0.002):
    pk=[]
    def add(p,dt):
        p.time=t[0]; t[0]+=dt; pk.append(p)
    e=lambda s,d: Ether(src=mac(s),dst=mac(d))
    add(e(src,dst)/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="S",seq=100),rtt)
    add(e(dst,src)/IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags="SA",seq=500,ack=101),rtt)
    add(e(src,dst)/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="A",seq=101,ack=501),rtt)
    if payload_c: add(e(src,dst)/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="PA",seq=101,ack=501)/Raw(payload_c),rtt)
    if payload_s: add(e(dst,src)/IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags="PA",seq=501,ack=101+len(payload_c))/Raw(payload_s),rtt)
    add(e(src,dst)/IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="FA"),rtt)
    add(e(dst,src)/IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags="FA"),rtt)
    return pk

def normal(duration=120,start=1700000000.0):
    pk=[]; t=start
    while t<start+duration:
        t+=random.expovariate(6)
        c=random.choice(clients); r=random.random(); tt=[t]
        if r<0.35:
            q=random.choice(["vnrvjiet.ac.in","example.com","kali.org","github.com","python.org"])
            p=Ether(src=mac(c),dst=mac(GW))/IP(src=c,dst=GW)/UDP(sport=random.randint(40000,60000),dport=53)/DNS(rd=1,qd=DNSQR(qname=q))
            p.time=t; pk.append(p)
            a=Ether(src=mac(GW),dst=mac(c))/IP(src=GW,dst=c)/UDP(sport=53,dport=p[UDP].sport)/DNS(qr=1,qd=p[DNS].qd,an=DNSRR(rrname=q,rdata="93.184.216.34"))
            a.time=t+0.01; pk.append(a)
        elif r<0.65:
            pk+=tcp_session(tt,c,SERVER,random.randint(40000,60000),80,b"GET / HTTP/1.1\r\nHost: lab\r\n\r\n",b"HTTP/1.1 200 OK\r\n\r\n"+b"x"*random.randint(200,1200))
        elif r<0.78:
            pk+=tcp_session(tt,c,SERVER,random.randint(40000,60000),443,b"\x16\x03\x01"+b"a"*200,b"\x16\x03\x03"+b"b"*random.randint(300,1000))
        elif r<0.88:
            pk+=tcp_session(tt,c,SERVER,random.randint(40000,60000),21,b"USER student\r\nPASS ok\r\n",b"220 FTP ready\r\n331 Password required\r\n230 Login successful\r\n")
        elif r<0.93:
            p=Ether(src=mac(c),dst=mac(SERVER))/IP(src=c,dst=SERVER)/ICMP(type=8)/Raw(b"p"*32); p.time=t; pk.append(p)
            a=Ether(src=mac(SERVER),dst=mac(c))/IP(src=SERVER,dst=c)/ICMP(type=0)/Raw(b"p"*32); a.time=t+0.001; pk.append(a)
        elif r<0.97:
            p=Ether(src=mac(c),dst="ff:ff:ff:ff:ff:ff")/ARP(op=1,psrc=c,pdst=GW,hwsrc=mac(c)); p.time=t; pk.append(p)
            a=Ether(src=mac(GW),dst=mac(c))/ARP(op=2,psrc=GW,pdst=c,hwsrc=mac(GW),hwdst=mac(c)); a.time=t+0.001; pk.append(a)
        else:
            ch=bytes.fromhex(mac(c).replace(':',''))
            p=Ether(src=mac(c),dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=ch)/DHCP(options=[("message-type","discover"),"end"]); p.time=t; pk.append(p)
            a=Ether(src=mac(GW),dst=mac(c))/IP(src=GW,dst=c)/UDP(sport=67,dport=68)/BOOTP(yiaddr=c,chaddr=ch)/DHCP(options=[("message-type","offer"),"end"]); a.time=t+0.01; pk.append(a)
    return pk

def attack_portscan(start):
    pk=[]; t=start; ports=random.sample(range(1,10000),1000)
    for dp in ports:
        p=Ether(src=mac(ATT),dst=mac(SERVER))/IP(src=ATT,dst=SERVER)/TCP(sport=40001,dport=dp,flags="S"); p.time=t; pk.append(p)
        flag="SA" if dp in(21,80,443,53) else "RA"
        a=Ether(src=mac(SERVER),dst=mac(ATT))/IP(src=SERVER,dst=ATT)/TCP(sport=dp,dport=40001,flags=flag); a.time=t+0.0005; pk.append(a)
        t+=0.004
    return pk
def attack_pingsweep(start):
    pk=[]; t=start
    for i in range(1,255):
        p=Ether(src=mac(ATT),dst="ff:ff:ff:ff:ff:ff")/IP(src=ATT,dst=NET+str(i))/ICMP(type=8); p.time=t; pk.append(p); t+=0.02
    return pk
def attack_arpspoof(start):
    pk=[]; t=start
    for _ in range(40):
        for victim in clients[:3]:
            p=Ether(src=mac(ATT),dst=mac(victim))/ARP(op=2,psrc=GW,pdst=victim,hwsrc=mac(ATT),hwdst=mac(victim)); p.time=t; pk.append(p)
        t+=1.0
    return pk
def attack_dnsenum(start):
    pk=[]; t=start
    words=["www","mail","ftp","vpn","dev","admin","test","portal","db","ns1","ns2","intranet"]+["host%d"%i for i in range(1,49)]
    for w in words:
        p=Ether(src=mac(ATT),dst=mac(SERVER))/IP(src=ATT,dst=SERVER)/UDP(sport=random.randint(40000,60000),dport=53)/DNS(rd=1,qd=DNSQR(qname=w+".lab.local")); p.time=t; pk.append(p); t+=0.05
    ax=Ether(src=mac(ATT),dst=mac(SERVER))/IP(src=ATT,dst=SERVER)/TCP(sport=45000,dport=53,flags="PA")/Raw(b"\x00\x1d\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x03lab\x05local\x00\x00\xfc\x00\x01"); ax.time=t; pk.append(ax)
    return pk
def attack_ftpbrute(start):
    pk=[]; t=[start]
    for i in range(60):
        pk+=tcp_session(t,ATT,SERVER,41000+i,21,b"USER admin\r\nPASS guess%d\r\n"%i,b"220 FTP ready\r\n331 Password required\r\n530 Login incorrect.\r\n",rtt=0.003); t[0]+=0.05
    return pk
def attack_synflood(start):
    pk=[]; t=start
    for i in range(3000):
        s="10.%d.%d.%d"%(random.randint(0,255),random.randint(0,255),random.randint(1,254))
        p=Ether(src=mac(ATT),dst=mac(SERVER))/IP(src=s,dst=SERVER)/TCP(sport=random.randint(1024,65535),dport=80,flags="S"); p.time=t; pk.append(p); t+=0.001
    return pk
def attack_roguedhcp(start):
    pk=[]; t=start
    for c in clients[:5]:
        a=Ether(src=mac(ATT),dst=mac(c))/IP(src=ATT,dst=c)/UDP(sport=67,dport=68)/BOOTP(yiaddr=c,siaddr=ATT,chaddr=bytes.fromhex(mac(c).replace(':','')))/DHCP(options=[("message-type","offer"),("router",ATT),"end"]); a.time=t; pk.append(a); t+=0.5
    return pk

ATTACKS={"portscan":attack_portscan,"pingsweep":attack_pingsweep,"arpspoof":attack_arpspoof,
         "dnsenum":attack_dnsenum,"ftpbrute":attack_ftpbrute,"synflood":attack_synflood,"roguedhcp":attack_roguedhcp}
if __name__=="__main__":
    base=normal(120); wrpcap("pcaps/normal.pcap",base); print("normal",len(base))
    for name,fn in ATTACKS.items():
        atk=fn(1700000000.0+40)
        mixed=sorted(normal(120)+atk,key=lambda p:p.time)
        wrpcap(f"pcaps/{name}.pcap",mixed); print(name,len(mixed),"(attack pkts:",len(atk),")")
    allp=normal(300)
    for k,(name,fn) in enumerate(ATTACKS.items()): allp+=fn(1700000000.0+20+k*40)
    wrpcap("pcaps/combined.pcap",sorted(allp,key=lambda p:p.time)); print("combined",len(allp))
