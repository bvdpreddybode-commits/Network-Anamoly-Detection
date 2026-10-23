"""Optional ML layer: Isolation Forest on per-source 5-second window features."""
import numpy as np, pandas as pd
from sklearn.ensemble import IsolationForest
WIN = 5.0
FEATS = ["pkts", "bytes_avg", "uniq_dports", "uniq_dsts", "syn_ratio", "icmp_ratio"]
def window_features(df):
    d = df[df.src.notna() & (df.proto != "ARP")].copy()
    d["w"] = ((d.t - d.t.min()) // WIN).astype(int)
    d["is_syn"] = (d["flags"] == "S").astype(int); d["is_icmp"] = (d.proto == "ICMP").astype(int)
    g = d.groupby(["src", "w"])
    f = pd.DataFrame(dict(pkts=g.size(), bytes_avg=g["len"].mean(), uniq_dports=g.dport.nunique(),
                          uniq_dsts=g.dst.nunique(), syn_ratio=g.is_syn.mean(), icmp_ratio=g.is_icmp.mean())).reset_index()
    return f
def train(df_normal, contamination=0.01, seed=1):
    f = window_features(df_normal)
    return IsolationForest(n_estimators=200, contamination=contamination, random_state=seed).fit(f[FEATS])
def predict(model, df):
    f = window_features(df); f["anomaly"] = model.predict(f[FEATS]) == -1
    f["score"] = -model.score_samples(f[FEATS]); return f
