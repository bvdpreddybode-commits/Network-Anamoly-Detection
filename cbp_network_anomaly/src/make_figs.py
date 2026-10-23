import sys, json, warnings, textwrap; warnings.filterwarnings("ignore"); sys.path.insert(0,"src")
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt, matplotlib.patches as mp
import pandas as pd, numpy as np
from parser import parse_pcap
plt.rcParams.update({"font.family":"serif","font.size":10})
R=json.load(open("results/results.json")); T0=1700000000.0
def box(ax,x,y,w,h,txt,fc,fs=9):
    ax.add_patch(mp.FancyBboxPatch((x,y),w,h,boxstyle="round,pad=0.03",fc=fc,ec="#1f3b63",lw=1.3))
    ax.text(x+w/2,y+h/2,txt,ha="center",va="center",fontsize=fs)
def arrow(ax,x1,y1,x2,y2): ax.annotate("",xy=(x2,y2),xytext=(x1,y1),arrowprops=dict(arrowstyle="->",lw=1.6,color="#1f3b63"))

# Fig architecture (two rows so text fits)
fig,ax=plt.subplots(figsize=(7.2,3.3)); ax.axis("off"); ax.set_xlim(0,10); ax.set_ylim(0,4.6)
items=[("1. Traffic capture\nWireshark / tcpdump\n→ .pcap file","#e8f0fb"),("2. Parser\nScapy → pandas\npacket table","#dbe8f7"),("3. Detection engine\n7 rule-based detectors\n+ Isolation Forest","#fde9d9")]
for i,(t,c) in enumerate(items):
    box(ax,0.2+i*3.4,2.9,2.8,1.4,t,c)
    if i<2: arrow(ax,3.05+i*3.4,3.6,3.55+i*3.4,3.6)
box(ax,0.2,0.4,2.8,1.4,"4. Alert records\nsource, type, time,\nseverity, evidence","#e2f0d9"); box(ax,3.6,0.4,2.8,1.4,"5. CLI report\nrun_detector.py\n(console + CSV)","#e2f0d9"); box(ax,7.0,0.4,2.8,1.4,"6. Dashboard\nStreamlit: protocol mix,\ntimeline, alerts table","#e2f0d9")
arrow(ax,8.6,2.9,1.6,1.85); arrow(ax,3.05,1.1,3.55,1.1); arrow(ax,6.45,1.1,6.95,1.1)
fig.savefig("figs/arch.png",dpi=200,bbox_inches="tight"); plt.close()

# Fig topology
fig,ax=plt.subplots(figsize=(7.2,3.6)); ax.axis("off"); ax.set_xlim(0,11); ax.set_ylim(0,4.8)
box(ax,0.1,3.0,3.1,1.5,"Kali Linux (attacker)\n192.168.56.66\nNmap, Hydra, hping3,\narpspoof, dig","#fde0dc",8.5)
box(ax,7.8,3.0,3.1,1.5,"Ubuntu server (victim)\n192.168.56.10\nFTP :21, HTTP :80,\nDNS :53","#e2f0d9",8.5)
box(ax,3.9,1.7,3.2,1.5,"Host-only network\n192.168.56.0/24\n(VirtualBox virtual switch)","#fff2cc",8.5)
box(ax,0.1,0.1,3.1,1.3,"Client VMs\n192.168.56.20 – .29\n(normal users)","#dbe8f7",8.5)
box(ax,7.8,0.1,3.1,1.3,"Monitor / analyser\nWireshark + Python detector\n(promiscuous mode)","#e8dcf3",8.5)
for a,b in [((3.25,3.4),(4.0,2.8)),((7.75,3.4),(7.0,2.8)),((3.25,1.0),(4.0,1.9)),((7.75,1.0),(7.0,1.9))]: arrow(ax,*a,*b)
fig.savefig("figs/topology.png",dpi=200,bbox_inches="tight"); plt.close()

# Protocol pie with legend
d=parse_pcap("pcaps/normal_test.pcap"); pc=d.proto.value_counts()
fig,ax=plt.subplots(figsize=(6.0,3.4)); cols=plt.cm.Set3.colors
w,_,_=ax.pie(pc.values,startangle=90,counterclock=False,colors=cols,autopct=lambda p: f"{p:.1f}%" if p>4 else "",pctdistance=0.72,textprops={"fontsize":8},wedgeprops=dict(edgecolor="white"))
ax.legend(w,[f"{k}: {v:,} ({v/pc.sum()*100:.1f}%)" for k,v in pc.items()],loc="center left",bbox_to_anchor=(1,0.5),fontsize=8,frameon=False)
fig.savefig("figs/proto_pie.png",dpi=200,bbox_inches="tight"); plt.close()
json.dump(dict(pps=len(d)/(d.t.max()-d.t.min()),avg=d["len"].mean(),n=len(d),dur=d.t.max()-d.t.min()),open("results/baseline.json","w"))

# Timeline with alert markers (staggered labels)
dc=parse_pcap("pcaps/combined.pcap"); al=pd.read_csv("results/alerts_combined.csv")
dc["s"]=(dc.t-T0).astype(int); tl=dc.groupby("s").size()
fig,ax=plt.subplots(figsize=(7.2,3.8)); ax.plot(tl.index,tl.values,lw=1,color="#1f3b63"); ax.set_yscale("log"); ax.set_ylim(1,6000)
ax.set_xlabel("Time (s)"); ax.set_ylabel("Packets per second (log scale)")
ys=[3000,1300,3000,1300,600,3000,1300,3000]; al_=["l","l","l","r","l","l","l","l"]
for i,r in enumerate(al.itertuples()):
    x=r.time-T0; c=plt.cm.tab10.colors[i%10]; ax.axvline(x,color=c,ls="--",lw=1)
    ax.text(x+(-3 if al_[i]=="r" else 3),ys[i],r.type,fontsize=7.5,color=c,ha="right" if al_[i]=="r" else "left",va="center",bbox=dict(fc="white",ec="none",pad=1,alpha=.85))
ax.grid(alpha=.3); fig.savefig("figs/timeline.png",dpi=200,bbox_inches="tight"); plt.close()

# Latency
names=["portscan","pingsweep","arpspoof","dnsenum","ftpbrute","synflood","roguedhcp"]; lab=["Port\nscan","Ping\nsweep","ARP\nspoof","DNS\nenum","FTP\nbrute","SYN\nflood","Rogue\nDHCP"]
lat=[R[n]["latency"] for n in names]
fig,ax=plt.subplots(figsize=(6.4,3.2)); b=ax.bar(lab,lat,color="#2e75b6")
for r,v in zip(b,lat): ax.text(r.get_x()+r.get_width()/2,v+0.03,f"{v:.2f}",ha="center",fontsize=8)
ax.set_ylabel("Detection latency (s)"); ax.grid(axis="y",alpha=.3); fig.savefig("figs/latency.png",dpi=200,bbox_inches="tight"); plt.close()

# Sensitivity
s=pd.DataFrame(R["sensitivity"]); fig,ax=plt.subplots(figsize=(6.4,3.3)); x=np.arange(len(s))
bars=ax.bar(x,s.fp_on_normal,color="#c00000",width=.55); ax.set_xticks(x); ax.set_xticklabels(s.threshold)
ax.set_xlabel("Port-scan threshold (distinct destination ports within 5 s)"); ax.set_ylabel("False alerts on 10 min of normal traffic"); ax.set_ylim(0,13)
for i,r in s.iterrows():
    ax.text(i,r.fp_on_normal+0.4,f"{int(r.fp_on_normal)}",ha="center",fontsize=8)
    ax.text(i,11.6,"slow scan\n"+("found" if r.slow_detected else "missed"),ha="center",fontsize=7,color="#2e75b6" if r.slow_detected else "#555")
ax.grid(axis="y",alpha=.3); fig.savefig("figs/sensitivity.png",dpi=200,bbox_inches="tight"); plt.close()

# Rules vs ML
ml=R["ml"]; mlr=[1 if ml[n]["att_flagged"]>0 else 0 for n in names]
fig,ax=plt.subplots(figsize=(6.4,3.4)); xx=np.arange(7)
ax.bar(xx-.18,[1]*7,.36,label="Rule-based detectors",color="#2e75b6"); ax.bar(xx+.18,mlr,.36,label="Isolation Forest",color="#ed7d31")
for i,v in enumerate(mlr):
    if not v: ax.text(i+.18,0.04,"missed",rotation=90,fontsize=7,color="#a33",ha="center",va="bottom")
ax.set_xticks(xx); ax.set_xticklabels(lab,fontsize=8); ax.set_yticks([0,1]); ax.set_yticklabels(["Not detected","Detected"]); ax.set_ylim(0,1.15)
ax.legend(fontsize=8,loc="upper center",bbox_to_anchor=(0.5,-0.2),ncol=2,frameon=False); ax.grid(axis="y",alpha=.3)
fig.savefig("figs/rules_vs_ml.png",dpi=200,bbox_inches="tight"); plt.close()

# Console images from REAL captured CLI output
def term(text,fn,w=6.2,wrap=96,fs=6.8):
    lines=[]
    for l in text.split("\n"): lines+=textwrap.wrap(l,wrap,subsequent_indent="      ",break_long_words=False) or [""]
    h=0.118*len(lines)+0.3; fig=plt.figure(figsize=(w,h)); fig.patch.set_facecolor("#0c0c0c")
    fig.text(0.015,0.975,"\n".join(lines),family="monospace",fontsize=fs,color="#33ff66",va="top",linespacing=1.3)
    fig.savefig(fn,dpi=220,facecolor=fig.get_facecolor()); plt.close()
for f in ["combined","normal_test"]: term(open(f"results/console_{f}.txt").read().strip(),f"figs/console_{f}.png")
