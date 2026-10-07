"""MeshSentry detection logic (reference implementation).

This module mirrors the C implementation in
firmware/components/ids/ (ids_detect.c, ids_fusion.c). Keep both in sync:
the thresholds below are the defaults of the Kconfig options in
firmware/main/Kconfig.projbuild.
"""
from collections import defaultdict, deque
from dataclasses import dataclass, field
import math

# Alert types
FWD = "FWD"        # selective forwarding / blackhole (watchdog)
FLOOD = "FLOOD"    # frame-rate anomaly (flooding / DoS)
ROUTE = "ROUTE"    # forged route advertisement (sinkhole)
REPLAY = "REPLAY"  # stale per-hop sequence numbers (replay)
SYBIL = "SYBIL"    # several identities sharing one RSSI signature

BLACKLIST_TYPES = (FWD, FLOOD, ROUTE, SYBIL)


@dataclass
class IdsParams:
    window_s: float = 10.0
    # selective-forwarding detector (one-sided binomial test)
    fwd_alpha: float = 0.001      # significance level
    fwd_q: float = 0.9            # assumed upstream delivery prob. (sender->suspect)
    min_handed: int = 6           # minimum expected forwards before judging
    # flooding detector
    rate_k: float = 4.0           # deviations above EWMA baseline
    rate_min_fps: float = 5.0     # absolute floor (frames/s)
    rate_warm: int = 3            # windows before the baseline is trusted
    # route-claim detector
    route_min_claims: int = 2
    # replay detector
    replay_min: int = 2
    # fusion
    vote_tau: float = 0.5         # trust-weighted alert fraction
    mass_min: float = 0.9         # minimum trust mass of accusing monitors
    min_accusers: int = 3         # distinct accusing monitors
    use_trust: bool = True
    trust_hi: float = 0.75
    trust_lo: float = 0.25
    # Sybil (RSSI-signature) detector
    sybil_delta_db: float = 1.5
    sybil_min_monitors: int = 6
    sybil_min_rssi_n: int = 3
    sybil_persist: int = 2        # close in >= this many of the last 3 windows
    sybil_min_trust: float = 0.4
    # local-only baselines
    local_sybil_delta_db: float = 0.5
    watchdog_theta: float = 0.5


@dataclass(slots=True)
class NbrRecord:
    """Per-neighbour feature record a monitor reports for one window."""
    nbr: int
    handed: int          # forwards expected of nbr (sliding 3 windows)
    overheard: int       # forwards of nbr actually overheard
    prr: float           # EWMA beacon reception ratio nbr -> monitor
    rssi: float          # mean RSSI of fresh frames in this window (dBm)
    rssi_n: int
    rate: float          # frames/s claimed by nbr in this window
    rate_base: float     # EWMA baseline (before this window)
    rate_dev: float      # EWMA mean absolute deviation
    warm: int            # windows of history
    replays: int         # stale frames carrying nbr as transmitter
    beacons: int
    bad_claims: int      # hop-1 claims absent from the signed sink list
    asnl_known: bool
    hand_own: int = 0    # (baseline only) frames the monitor itself handed
    over_own: int = 0


def nfr(r: NbrRecord) -> float:
    """Normalised forwarding ratio: overheard / (expected * link PRR)."""
    return r.overheard / (r.handed * max(r.prr, 0.2))


def binom_cdf(k: int, n: int, q: float) -> float:
    """P[X <= k] for X ~ Binomial(n, q)."""
    q = min(max(q, 1e-6), 1 - 1e-6)
    return sum(math.comb(n, i) * q ** i * (1 - q) ** (n - i)
               for i in range(0, k + 1))


def fwd_pvalue(r: NbrRecord, p: IdsParams) -> float:
    """Probability that an honest forwarder yields <= overheard forwards."""
    return binom_cdf(r.overheard, r.handed, p.fwd_q * r.prr)


def eligible_types(r: NbrRecord, p: IdsParams):
    t = []
    if r.handed >= p.min_handed:
        t.append(FWD)
    if r.warm >= p.rate_warm:
        t.append(FLOOD)
    if r.asnl_known and r.beacons > 0:
        t.append(ROUTE)
    if r.rssi_n > 0 or r.replays > 0:
        t.append(REPLAY)
    return t


def local_verdicts(r: NbrRecord, p: IdsParams):
    v = set()
    if r.handed >= p.min_handed and fwd_pvalue(r, p) < p.fwd_alpha:
        v.add(FWD)
    if r.warm >= p.rate_warm and r.rate > max(
            p.rate_min_fps, r.rate_base + p.rate_k * max(r.rate_dev, 0.5)):
        v.add(FLOOD)
    if r.asnl_known and r.bad_claims >= p.route_min_claims:
        v.add(ROUTE)
    if r.replays >= p.replay_min:
        v.add(REPLAY)
    return v


class Fusion:
    """Sink-side trust-weighted consensus + RSSI-signature Sybil detector."""

    def __init__(self, p: IdsParams):
        self.p = p
        self.alpha = defaultdict(float)
        self.beta = defaultdict(float)
        self.reports = defaultdict(dict)          # window -> {monitor: [rec]}
        self.close_hist = defaultdict(lambda: deque(maxlen=3))
        self.declared = {}                        # (id, type) -> first time
        self.blacklist = set()

    def trust(self, i):
        if not self.p.use_trust:
            return 1.0
        return (self.alpha[i] + 1.0) / (self.alpha[i] + self.beta[i] + 2.0)

    def add_report(self, mon, k, records):
        self.reports[k][mon] = records

    def decide(self, k, t):
        """Fuse all reports for window k; return newly declared (id, type)."""
        p = self.p
        reps = self.reports.pop(k, {})
        votes = defaultdict(lambda: [0.0, 0.0, []])
        for i, recs in reps.items():
            ti = self.trust(i)
            for r in recs:
                v = local_verdicts(r, p)
                for typ in eligible_types(r, p):
                    a = typ in v
                    e = votes[(r.nbr, typ)]
                    e[1] += ti
                    if a:
                        e[0] += ti
                    e[2].append((i, a))
        new = []
        self.positive = []            # every (id, type) positive in window k
        for (j, typ), (m_a, m_t, lst) in votes.items():
            s = m_a / m_t if m_t > 0 else 0.0
            # replays carry cryptographic evidence (valid tag, stale seq):
            # a trusted quorum suffices, the fraction of observers does not.
            thr = 0.0 if typ == REPLAY else p.vote_tau
            n_acc = sum(1 for _, a in lst if a)
            if m_a >= p.mass_min and s >= thr and n_acc >= p.min_accusers:
                self.positive.append((j, typ))
                if (j, typ) not in self.declared:
                    self.declared[(j, typ)] = t
                    new.append((j, typ))
                if typ in BLACKLIST_TYPES:
                    self.blacklist.add(j)
            if p.use_trust and typ in (FWD, FLOOD, ROUTE):
                if s >= p.trust_hi:
                    for i, a in lst:
                        if a:
                            self.alpha[i] += 1
                        else:
                            self.beta[i] += 1
                elif s <= p.trust_lo:
                    for i, a in lst:
                        if a:
                            self.beta[i] += 1
                        else:
                            self.alpha[i] += 1
        for j in self._sybil(reps):
            self.positive.append((j, SYBIL))
            if (j, SYBIL) not in self.declared:
                self.declared[(j, SYBIL)] = t
                new.append((j, SYBIL))
            self.blacklist.add(j)
        return new

    def _sybil(self, reps):
        p = self.p
        table = defaultdict(dict)                 # id -> {monitor: rssi}
        for i, recs in reps.items():
            if self.trust(i) < p.sybil_min_trust:
                continue
            for r in recs:
                if r.rssi_n >= p.sybil_min_rssi_n:
                    table[r.nbr][i] = r.rssi
        ids = sorted(table)
        seen_pairs = set()
        for a_i in range(len(ids)):
            for b_i in range(a_i + 1, len(ids)):
                a, b = ids[a_i], ids[b_i]
                common = table[a].keys() & table[b].keys()
                if len(common) < p.sybil_min_monitors:
                    continue
                d = math.sqrt(sum((table[a][m] - table[b][m]) ** 2
                                  for m in common) / len(common))
                self.close_hist[(a, b)].append(d < p.sybil_delta_db)
                seen_pairs.add((a, b))
        for pair, h in self.close_hist.items():
            if pair not in seen_pairs:
                h.append(False)
        # union of all persistently close pairs
        flagged = set()
        for (a, b), h in self.close_hist.items():
            if sum(h) >= p.sybil_persist:
                flagged.update((a, b))
        return flagged


def sybil_distances(reps, min_monitors=3, min_n=3):
    """Pairwise RSSI-signature distances (for plotting)."""
    table = defaultdict(dict)
    for i, recs in reps.items():
        for r in recs:
            if r.rssi_n >= min_n:
                table[r.nbr][i] = r.rssi
    out = []
    ids = sorted(table)
    for x in range(len(ids)):
        for y in range(x + 1, len(ids)):
            a, b = ids[x], ids[y]
            common = table[a].keys() & table[b].keys()
            if len(common) >= min_monitors:
                d = math.sqrt(sum((table[a][m] - table[b][m]) ** 2
                                  for m in common) / len(common))
                out.append((a, b, d))
    return out
