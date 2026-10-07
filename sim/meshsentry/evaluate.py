"""Run simulations and score detection schemes on the recorded traces.

Detection is evaluated offline on the traces so that thresholds can be swept
without re-simulating: runs with mitigation disabled are not affected by
detection decisions, so re-scoring is exact.
"""
from collections import defaultdict
from dataclasses import replace

from .ids import (Fusion, IdsParams, local_verdicts, BLACKLIST_TYPES, REPLAY,
                  SYBIL, FWD)
from .sim import Simulator, SimConfig, SINK


def run_one(cfg: SimConfig):
    s = Simulator(cfg).run()
    W = cfg.params.window_s
    nb = int(cfg.duration // W)
    gen = [0] * nb
    dl = [0] * nb
    for t, o in s.gen_log:
        if int(t // W) < nb:
            gen[int(t // W)] += 1
    for tg, td, o in s.del_log:
        if int(tg // W) < nb:
            dl[int(tg // W)] += 1
    by_kind = defaultdict(int)
    for (phy, kind), b in s.tx_bytes.items():
        by_kind[kind] += b
    frames_kind = defaultdict(int)
    for (phy, kind), n in s.tx_frames.items():
        frames_kind[kind] += n
    return dict(
        attack=cfg.attack, seed=cfg.seed, drop_p=cfg.drop_p,
        badmouth_frac=cfg.badmouth_frac, mitigation=cfg.mitigation,
        grid=cfg.grid, t_attack=cfg.t_attack, duration=cfg.duration, W=W,
        attackers=set(s.attackers), badmouthers=set(s.badmouthers),
        honest=set(s.honest), n_members=s.n_members,
        received=s.received_reports, generated=s.generated,
        decisions=s.decisions, gen=gen, dl=dl, bytes=dict(by_kind),
        frames=dict(frames_kind),
        pos=s.pos if cfg.seed < 3 else None,
        parents={n.id: n.parent for n in s.nodes[:s.n_members]}
        if cfg.seed < 3 else None)


# ------------------------------------------------------------------ schemes
def collab_events(run, p: IdsParams):
    f = Fusion(p)
    W = run["W"]
    by_k = defaultdict(list)
    for k, mon, recs in run["received"]:
        by_k[k].append((mon, recs))
    out = []
    for k in sorted(by_k):
        for mon, recs in by_k[k]:
            f.add_report(mon, k, recs)
        t = (k + 1) * W + 6.0
        f.decide(k, t)
        for j, typ in f.positive:
            out.append((t, j, typ))
    return out


def local_events(run, p: IdsParams, single_monitor_sybil=False):
    """Local-only MeshSentry: each node acts on its own detectors.

    single_monitor_sybil enables a naive one-monitor RSSI-similarity Sybil
    check; it is reported in the text only (it flags almost every node)."""
    W = run["W"]
    honest_mon = run["honest"] | {SINK}
    out = []
    by_k = defaultdict(list)
    for k, mon, recs in run["generated"]:
        if mon in honest_mon:
            by_k[k].append((mon, recs))
    close = defaultdict(int)
    for k in sorted(by_k):
        t = (k + 1) * W
        for mon, recs in by_k[k]:
            for r in recs:
                for typ in local_verdicts(r, p):
                    out.append((t, r.nbr, typ))
            # single-monitor RSSI similarity (no collaboration)
            if not single_monitor_sybil:
                continue
            rs = [(r.nbr, r.rssi) for r in recs if r.rssi_n >= p.sybil_min_rssi_n]
            seen = set()
            for a in range(len(rs)):
                for b in range(a + 1, len(rs)):
                    key = (mon, min(rs[a][0], rs[b][0]), max(rs[a][0], rs[b][0]))
                    seen.add(key)
                    if abs(rs[a][1] - rs[b][1]) < p.local_sybil_delta_db:
                        close[key] += 1
                        if close[key] >= 2:
                            out.append((t, rs[a][0], SYBIL))
                            out.append((t, rs[b][0], SYBIL))
                    else:
                        close[key] = 0
    return out


def watchdog_events(run, theta=0.5, min_handed=6):
    """Marti et al. watchdog: a node judges only the next hop it uses."""
    W = run["W"]
    honest_mon = run["honest"] | {SINK}
    out = []
    for k, mon, recs in run["generated"]:
        if mon not in honest_mon:
            continue
        for r in recs:
            if r.hand_own >= min_handed and r.over_own / r.hand_own < theta:
                out.append(((k + 1) * W, r.nbr, FWD))
    return out


# ------------------------------------------------------------------ metrics
def score(run, events):
    ta = run["t_attack"]
    att = run["attackers"]
    honest = run["honest"]
    det_t = None
    fp = set()
    for t, j, typ in events:
        if run["attack"] == "replay":
            if typ == REPLAY and t >= ta and det_t is None:
                det_t = t
        elif j in att and t >= ta and typ in BLACKLIST_TYPES and det_t is None:
            det_t = t
        if typ in BLACKLIST_TYPES and j in honest:
            fp.add(j)
    return dict(detected=det_t is not None,
                latency=(det_t - ta) if det_t is not None else None,
                fp_nodes=len(fp), fpr=len(fp) / max(1, len(honest)))


def pdr_series(run):
    return [d / g if g else float("nan") for g, d in zip(run["gen"], run["dl"])]
