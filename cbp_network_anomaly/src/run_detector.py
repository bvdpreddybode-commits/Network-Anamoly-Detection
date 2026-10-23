"""CLI:  python src/run_detector.py <file.pcap> [--csv out.csv]"""
import sys, time, warnings; warnings.filterwarnings("ignore"); sys.path.insert(0, "src")
from parser import parse_pcap
from detectors import run_all, DETECTORS
def main():
    if len(sys.argv) < 2: sys.exit(__doc__)
    path = sys.argv[1]; t0 = time.time(); df = parse_pcap(path)
    print(f"[+] Parsed {len(df)} packets from {path} in {time.time()-t0:.1f} s")
    print(f"[+] Running {len(DETECTORS)} detectors"); t1 = time.time(); al = run_all(df)
    t_ref = df.t.min()
    for r in al.itertuples() if len(al) else []:
        print(f"[{r.severity:8s}] t={r.time-t_ref:7.2f}s {r.type:17s} src={str(r.src):17s} | {r.detail}")
    print(f"[+] {len(al)} alert(s) raised in {time.time()-t1:.2f} s")
    if "--csv" in sys.argv and len(al): al.to_csv(sys.argv[sys.argv.index("--csv")+1], index=False)
if __name__ == "__main__": main()
