#!/usr/bin/env python3
"""Generate every data figure and the result table of the paper.

Reads results/*.pkl (run_experiments.py) and writes PDFs to ../paper/figures
plus results/summary.json with the numbers quoted in the text.
"""
import json
import math
import os
import pickle
import statistics as st
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from meshsentry.evaluate import (collab_events, local_events, watchdog_events,
                                 score, run_one)
from meshsentry.ids import IdsParams, SYBIL, sybil_distances
from meshsentry.sim import Simulator, SimConfig, SINK, airtime

OUT = os.path.join(os.path.dirname(__file__), "..", "paper", "figures")
os.makedirs(OUT, exist_ok=True)

# Fixed categorical order (validated reference palette), never cycled.
C = {"ours": "#2a78d6", "local": "#eb6834", "wd": "#1baf7a", "aux": "#eda100"}
INK, MUTED, GRID = "#1f1f1e", "#6b6a63", "#dcdbd5"
SCHEMES = [("ours", "MeshSentry (collaborative)", "o", ""),
           ("local", "Local-only detectors", "s", "//"),
           ("wd", "Watchdog [Marti et al.]", "^", "..")]
ATTACKS = ["selfwd", "sinkhole", "flood", "replay", "sybil"]
ALABEL = {"selfwd": "Sel. fwd.", "sinkhole": "Sinkhole", "flood": "Flooding",
          "replay": "Replay", "sybil": "Sybil", None: "No attack"}

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["STIXGeneral", "DejaVu Serif"],
    "mathtext.fontset": "stix", "font.size": 8, "axes.labelsize": 8,
    "axes.titlesize": 8, "legend.fontsize": 7, "xtick.labelsize": 7,
    "ytick.labelsize": 7, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
    "xtick.color": MUTED, "ytick.color": MUTED, "text.color": INK,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5,
    "axes.axisbelow": True, "axes.spines.top": False,
    "axes.spines.right": False, "lines.linewidth": 1.4,
    "legend.frameon": False, "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02, "pdf.fonttype": 42,
})
COL = 3.45   # IEEE column width (in)
P = IdsParams()
SUMMARY = {}


def load(name):
    with open(f"results/{name}.pkl", "rb") as fh:
        return pickle.load(fh)


def save(fig, name):
    fig.savefig(os.path.join(OUT, name + ".pdf"))
    fig.savefig(os.path.join(OUT, name + ".png"), dpi=200)
    plt.close(fig)


def scheme_events(key, r, p=P):
    if key == "ours":
        return collab_events(r, p)
    if key == "local":
        return local_events(r, p)
    return watchdog_events(r)


def wilson(k, n, z=1.96):
    if n == 0:
        return (0, 0)
    ph = k / n
    d = 1 + z * z / n
    c = (ph + z * z / (2 * n)) / d
    h = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / d
    return (ph - max(0, c - h), max(0, c + h) - ph)


# ------------------------------------------------------------ topology
def fig_topology():
    cfg = SimConfig(attack="sybil", seed=1000, duration=200, t_attack=100)
    s = Simulator(cfg).run()
    pos = s.pos
    fig, ax = plt.subplots(figsize=(COL, 2.35))
    ax.grid(False)
    n = s.n_members
    # radio links (mean RSSI above sensitivity)
    for i in range(n):
        for k in range(i + 1, n):
            if s.mean[i][k] > cfg.sens + 3:
                ax.plot([pos[i][0], pos[k][0]], [pos[i][1], pos[k][1]],
                        color=GRID, lw=0.5, zorder=1)
    for nd in s.nodes[1:n]:
        if nd.parent is not None:
            a, b = pos[nd.id], pos[nd.parent]
            ax.annotate("", xy=b, xytext=a, zorder=2,
                        arrowprops=dict(arrowstyle="-|>", color=MUTED, lw=0.9,
                                        shrinkA=4, shrinkB=5, mutation_scale=7))
    att = [i for i in s.attackers if i < n]
    hon = [i for i in range(1, n) if i not in att]
    ax.scatter([pos[i][0] for i in hon], [pos[i][1] for i in hon], s=26,
               color=C["ours"], edgecolor="white", lw=1.2, zorder=3,
               label="Sensor node / monitor")
    ax.scatter([pos[0][0]], [pos[0][1]], s=70, marker="s", color=INK,
               edgecolor="white", lw=1.2, zorder=4, label="Sink (fusion)")
    ax.scatter([pos[i][0] for i in att], [pos[i][1] for i in att], s=60,
               marker="X", color=C["local"], edgecolor="white", lw=1.0,
               zorder=4, label="Sybil attacker (+4 IDs)")
    for i in range(n):
        ax.text(pos[i][0] + 1.6, pos[i][1] + 1.6, str(i), fontsize=5.5,
                color=MUTED, zorder=5)
    ax.set_aspect("equal")
    ax.set_xlabel("x (m)")
    ax.set_ylabel("y (m)")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.2), ncol=3,
              handletextpad=0.3, columnspacing=0.9)
    save(fig, "topology")
    hops = [nd.hop for nd in s.nodes[1:n] if nd.hop < 255]
    SUMMARY["topology"] = {"nodes": n, "max_hop": max(hops),
                           "mean_hop": round(st.mean(hops), 2)}


# ------------------------------------------------------------ main bars
def fig_main(runs):
    res = {}
    lat = defaultdict(list)
    for key, *_ in SCHEMES:
        for a in [None] + ATTACKS:
            sc = [score(r, scheme_events(key, r)) for r in runs
                  if r["attack"] == a]
            det = sum(x["detected"] for x in sc)
            res[(key, a)] = dict(
                det=det / len(sc), n=len(sc), k=det,
                fpr=st.mean(x["fpr"] for x in sc),
                fpr_sd=st.pstdev(x["fpr"] for x in sc))
            if key == "ours":
                lat[a] = [x["latency"] for x in sc if x["latency"] is not None]
    SUMMARY["main"] = {f"{k}|{a}": v for (k, a), v in res.items()}
    SUMMARY["latency"] = {str(a): dict(median=st.median(v), p90=float(
        np.percentile(v, 90)), n=len(v)) for a, v in lat.items() if v}

    fig, (a1, a2) = plt.subplots(2, 1, figsize=(COL, 3.0), sharex=True)
    x = np.arange(len(ATTACKS))
    w = 0.26
    for j, (key, label, mk, hatch) in enumerate(SCHEMES):
        det = [res[(key, a)]["det"] * 100 for a in ATTACKS]
        err = np.array([wilson(res[(key, a)]["k"], res[(key, a)]["n"])
                        for a in ATTACKS]).T * 100
        a1.bar(x + (j - 1) * w, det, w - 0.03, color=C[key], label=label,
               hatch=hatch, edgecolor="white", lw=0.4, zorder=2)
        a1.errorbar(x + (j - 1) * w, det, yerr=err, fmt="none", ecolor=INK,
                    elinewidth=0.6, capsize=1.5, zorder=3)
        fpr = [res[(key, a)]["fpr"] * 100 for a in ATTACKS]
        a2.bar(x + (j - 1) * w, fpr, w - 0.03, color=C[key], hatch=hatch,
               edgecolor="white", lw=0.4, zorder=2)
    a1.set_ylabel("Detection rate (%)")
    a1.set_ylim(0, 112)
    a1.legend(loc="upper center", bbox_to_anchor=(0.5, 1.33), ncol=2,
              handlelength=1.5, columnspacing=1.0)
    a2.set_ylabel("False-positive rate (%)")
    a2.set_xticks(x, [ALABEL[a] for a in ATTACKS])
    for xi, a in enumerate(ATTACKS):
        v = res[("ours", a)]["fpr"] * 100
        a2.text(xi - w, v + 0.6, f"{v:.1f}", ha="center", fontsize=5.5,
                color=INK)
    save(fig, "detection_fpr")

    # latency CDF
    fig, ax = plt.subplots(figsize=(COL, 1.7))
    styles = ["-", "--", "-.", ":", (0, (5, 1, 1, 1))]
    cols = [C["ours"], C["local"], C["wd"], C["aux"], "#e87ba4"]
    for a, ls, col in zip(ATTACKS, styles, cols):
        v = sorted(lat[a])
        if not v:
            continue
        y = np.arange(1, len(v) + 1) / len(v)
        ax.step([0] + v, [0] + list(y), where="post", ls=ls, color=col,
                lw=1.3, label=ALABEL[a])
    ax.set_xlabel("Detection latency after attack onset (s)")
    ax.set_ylabel("CDF")
    ax.set_xlim(0, max(max(v) for v in lat.values() if v) + 10)
    ax.legend(ncol=2, loc="center right")
    save(fig, "latency_cdf")
    return res


# ------------------------------------------------------------ ROC
def fig_roc(runs):
    sel = [r for r in runs if r["attack"] in ("selfwd", None)]
    def point(key, events_fn):
        det, fpr = [], []
        for r in sel:
            sc = score(r, events_fn(r))
            if r["attack"] == "selfwd":
                det.append(sc["detected"])
            fpr.append(sc["fpr"])
        return st.mean(fpr) * 100, st.mean(det) * 100
    curves = {}
    alphas = [1e-6, 1e-5, 1e-4, 1e-3, 1e-2, 3e-2, 0.1, 0.2, 0.4]
    for key in ("ours", "local"):
        pts = []
        for al in alphas:
            p = IdsParams(fwd_alpha=al)
            if key == "ours":
                fn = lambda r, p=p: [e for e in collab_events(r, p) if e[2] != SYBIL]
            else:
                fn = lambda r, p=p: [e for e in local_events(r, p) if e[2] == "FWD"]
            pts.append(point(key, fn))
        curves[key] = pts
    pts = []
    for th in [0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
        pts.append(point("wd", lambda r, th=th: watchdog_events(r, theta=th)))
    curves["wd"] = pts
    SUMMARY["roc"] = curves
    fig, ax = plt.subplots(figsize=(COL, 2.1))
    for key, label, mk, _ in SCHEMES:
        xs, ys = zip(*curves[key])            # ordered by threshold
        ax.plot(xs, ys, marker=mk, ms=4, color=C[key], label=label,
                mec="white", mew=0.6)
    op = curves["ours"][alphas.index(1e-3)]
    ax.annotate(r"operating point $\alpha=10^{-3}$", xy=op,
                xytext=(1.5, 70), fontsize=6.5,
                arrowprops=dict(arrowstyle="-", color=MUTED, lw=0.6))
    ax.set_xscale("symlog", linthresh=1)
    ax.set_xticks([0, 0.5, 1, 2, 5, 10, 20, 40], ["0", "0.5", "1", "2", "5",
                                                  "10", "20", "40"])
    ax.set_xlabel("False-positive rate (% of honest nodes, log scale)")
    ax.set_ylabel("Detection rate (%)")
    ax.set_xlim(-0.05, 45)
    ax.set_ylim(0, 105)
    ax.legend(loc="lower right")
    save(fig, "roc_selfwd")


# ------------------------------------------------------------ drop rate
def fig_droprate(runs):
    ps = sorted({r["drop_p"] for r in runs})
    fig, ax = plt.subplots(figsize=(COL, 1.75))
    out = {}
    for key, label, mk, _ in SCHEMES:
        ys, es = [], []
        for p in ps:
            sc = [score(r, scheme_events(key, r)) for r in runs if r["drop_p"] == p]
            k = sum(x["detected"] for x in sc)
            ys.append(100 * k / len(sc))
            es.append(np.array(wilson(k, len(sc))) * 100)
            out[f"{key}|{p}"] = dict(det=k / len(sc),
                                     fpr=st.mean(x["fpr"] for x in sc))
        ax.errorbar(ps, ys, yerr=np.array(es).T, marker=mk, ms=4,
                    color=C[key], label=label, capsize=1.5, elinewidth=0.6,
                    mec="white", mew=0.6)
    SUMMARY["droprate"] = out
    ax.set_xlabel("Drop probability of the selective forwarder")
    ax.set_ylabel("Detection rate (%)")
    ax.set_ylim(0, 108)
    ax.legend(loc="lower right")
    save(fig, "droprate")


# ------------------------------------------------------------ bad-mouthing
def fig_badmouth(runs):
    fs = sorted({r["badmouth_frac"] for r in runs})
    fig, ax = plt.subplots(figsize=(COL, 1.75))
    out = {}
    variants = [(3, True, C["ours"], "o", "-", "Quorum $m=3$ + trust"),
                (3, False, INK, "o", ":", "$m=3$, no trust (identical)"),
                (2, True, C["local"], "s", "-", "Quorum $m=2$ + trust"),
                (1, True, C["wd"], "^", "-", "Quorum $m=1$ + trust")]
    for m, tr, col, mk, ls, label in variants:
        p = IdsParams(min_accusers=m, use_trust=tr)
        ys = []
        for f in fs:
            sc = [score(r, collab_events(r, p)) for r in runs
                  if r["badmouth_frac"] == f]
            ys.append(100 * st.mean(x["fpr"] for x in sc))
            out[f"m{m}|trust{tr}|{f}"] = ys[-1]
        ax.plot([100 * f for f in fs], ys, marker=mk, ms=4 if tr else 2.5,
                color=col, ls=ls, label=label, mec="white", mew=0.6,
                lw=1.4 if tr else 0.9, zorder=3 if not tr else 2)
    SUMMARY["badmouth"] = out
    ax.set_xlabel("Colluding bad-mouthing monitors (% of nodes)")
    ax.set_ylabel("False-positive rate (%)")
    ax.legend(ncol=2, loc="upper left", columnspacing=0.8)
    ax.set_ylim(0, 13)
    save(fig, "badmouth")


# ------------------------------------------------------------ PDR timeline
def fig_pdr(runs):
    fig, axes = plt.subplots(1, 2, figsize=(COL, 1.7), sharey=True)
    out = {}
    for ax, atk in zip(axes, ("sinkhole", "selfwd")):
        for mit, col, ls, label in ((False, C["local"], "--", "Detection only"),
                                    (True, C["ours"], "-", "With isolation")):
            sel = [r for r in runs if r["attack"] == atk and r["mitigation"] == mit]
            W = sel[0]["W"]
            arr = np.array([[d / g if g else np.nan for g, d in zip(r["gen"], r["dl"])]
                            for r in sel])
            m = np.nanmean(arr, axis=0) * 100
            t = (np.arange(len(m)) + 0.5) * W
            ax.plot(t[3:], m[3:], color=col, ls=ls, label=label)
            ta = int(sel[0]["t_attack"] // W)
            out[f"{atk}|{mit}"] = dict(
                pre=float(np.nanmean(arr[:, 5:ta])),
                post=float(np.nanmean(arr[:, ta + 3:])))
        ax.axvline(sel[0]["t_attack"], color=MUTED, lw=0.8, ls=":")
        ax.text(sel[0]["t_attack"] + 5, 96, "attack onset", fontsize=6,
                color=MUTED, va="top")
        ax.set_title(ALABEL[atk])
        ax.set_xlabel("Time (s)")
        ax.set_ylim(55, 100)
    axes[0].set_ylabel("PDR (%)")
    axes[1].legend(loc="lower right")
    SUMMARY["pdr"] = out
    save(fig, "pdr_mitigation")


# ------------------------------------------------------------ Sybil signature
def fig_sybil(runs):
    hon, syb, mix = [], [], []
    for r in runs:
        if r["attack"] != "sybil":
            continue
        att = r["attackers"]
        by_k = defaultdict(dict)
        for k, mon, recs in r["received"]:
            by_k[k][mon] = recs
        for k, reps in by_k.items():
            if (k + 1) * r["W"] <= r["t_attack"] + 10:
                continue
            for a, b, d in sybil_distances(reps, min_monitors=P.sybil_min_monitors):
                if a in att and b in att:
                    syb.append(d)
                elif a not in att and b not in att:
                    hon.append(d)
    fig, ax = plt.subplots(figsize=(COL, 1.7))
    bins = np.linspace(0, 20, 81)
    ax.hist(hon, bins=bins, color=C["ours"], alpha=0.85, label="Honest ID pairs",
            density=True, edgecolor="white", lw=0.3)
    ax.hist(syb, bins=bins, color=C["local"], alpha=0.85, hatch="//",
            label="Sybil ID pairs", density=True, edgecolor="white", lw=0.3)
    ax.axvline(P.sybil_delta_db, color=INK, lw=0.8, ls="--")
    ax.text(P.sybil_delta_db + 0.3, ax.get_ylim()[1] * 0.85,
            r"$\delta = %.1f$ dB" % P.sybil_delta_db, fontsize=6.5)
    ax.set_yscale("log")
    ax.set_xlabel(r"RSSI-signature distance $d_{ab}$ (dB)")
    ax.set_ylabel("Density (log)")
    ax.legend(loc="upper right")
    save(fig, "sybil_signature")
    hon, syb = np.array(hon), np.array(syb)
    SUMMARY["sybil"] = dict(n_hon=len(hon), n_syb=len(syb),
                            hon_below=float((hon < P.sybil_delta_db).mean()),
                            syb_below=float((syb < P.sybil_delta_db).mean()),
                            syb_p99=float(np.percentile(syb, 99)))


# ------------------------------------------------------------ overhead
def fig_overhead(runs):
    kinds = [("D", "Sensor data", C["aux"], ""), ("B", "Beacons", MUTED, ""),
             ("C", "Signed control", C["wd"], ".."),
             ("R", "IDS reports", C["ours"], "//")]
    grids = sorted({r["grid"] for r in runs})
    fig, ax = plt.subplots(figsize=(COL, 1.8))
    out = {}
    bottom = np.zeros(len(grids))
    for kind, label, col, hatch in kinds:
        vals = []
        for g in grids:
            sel = [r for r in runs if r["grid"] == g]
            occ = []
            for r in sel:
                b = r["bytes"].get(kind, 0)
                f = r["frames"].get(kind, 0)
                at = f * airtime(0) + b * 8e-6        # preamble+MAC, payload
                occ.append(100 * at / r["duration"])
            vals.append(st.mean(occ))
        ax.bar(range(len(grids)), vals, 0.6, bottom=bottom, color=col,
               hatch=hatch, edgecolor="white", lw=0.6, label=label, zorder=2)
        bottom += np.array(vals)
        out[kind] = dict(zip([g * g for g in grids], vals))
    ax.set_xticks(range(len(grids)), [f"{g * g}" for g in grids])
    ax.set_xlabel("Network size (nodes)")
    ax.set_ylabel("Channel airtime (%)")
    ax.legend(ncol=2, loc="upper left", columnspacing=0.8)
    ax.set_ylim(0, bottom.max() * 1.45)
    SUMMARY["overhead_airtime_pct"] = out
    save(fig, "overhead")


def fp_breakdown(runs):
    """False-positive node-events per detector type (all main runs)."""
    out = {}
    for key in ("ours", "local"):
        cnt = defaultdict(set)
        for r in runs:
            for t, j, typ in scheme_events(key, r):
                if typ == "REPLAY":       # names the impersonated node only
                    if r["attack"] != "replay":
                        cnt["REPLAY_spurious"].add((r["seed"], r["attack"], j))
                elif j in r["honest"]:
                    cnt[typ].add((r["seed"], r["attack"], j))
        out[key] = {k: len(v) for k, v in cnt.items()}
    naive = [score(r, local_events(r, P, single_monitor_sybil=True))["fpr"]
             for r in runs if r["attack"] == "sybil"]
    out["local_naive_sybil_fpr"] = st.mean(naive)
    out["n_runs"] = len(runs)
    SUMMARY["fp_breakdown"] = out


def main():
    main_runs = load("main")
    fp_breakdown(main_runs)
    fig_topology()
    fig_main(main_runs)
    fig_roc(main_runs)
    fig_sybil(main_runs)
    del main_runs
    fig_droprate(load("droprate"))
    fig_badmouth(load("badmouth"))
    fig_pdr(load("mitigation"))
    fig_overhead(load("scale"))
    with open("results/summary.json", "w") as fh:
        json.dump(SUMMARY, fh, indent=1, default=str)
    print("figures written to", os.path.abspath(OUT))


if __name__ == "__main__":
    main()
