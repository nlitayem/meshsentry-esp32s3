"""Discrete-event simulator of an ESP-NOW broadcast mesh running MeshSentry.

Models: log-distance path loss with static (per-link) shadowing and per-frame
fading, sigmoid reception curve, CSMA with carrier sensing, collisions with a
capture threshold, half-duplex radios, ETX-based gradient routing towards a
sink, signed control floods (sink neighbour list + blacklist), and the five
attacks studied in the paper.
"""
import heapq
import math
import random
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .ids import (IdsParams, NbrRecord, Fusion, local_verdicts, FWD,
                  BLACKLIST_TYPES)

SINK = 0
BCAST = -1
INF = float("inf")

# 802.11 MAC header + ESP-NOW vendor action-frame wrapper + FCS (bytes)
ESPNOW_OVERHEAD = 43
PREAMBLE_US = 192.0
RATE_MBPS = 1.0
HDR = 24          # MeshSentry mesh header incl. 8-byte truncated HMAC
REC_BYTES = 10    # one per-neighbour record in a report
MAX_RECS = 16


def airtime(size):
    return (PREAMBLE_US + (size + ESPNOW_OVERHEAD) * 8.0 / RATE_MBPS) * 1e-6


@dataclass
class SimConfig:
    grid: int = 5
    spacing: float = 15.0
    jitter: float = 3.0
    duration: float = 400.0
    t_attack: float = 150.0
    attack: str = None          # selfwd|sinkhole|flood|replay|sybil|None
    drop_p: float = 0.6         # selective-forwarding drop probability
    n_sybil: int = 4
    flood_fps: float = 300.0
    replay_fps: float = 4.0
    badmouth_frac: float = 0.0
    mitigation: bool = False
    seed: int = 1
    ptx: float = 0.0
    pl0: float = 40.0
    ple: float = 3.3
    sigma_s: float = 4.0
    sigma_f: float = 1.5
    sens: float = -88.0
    cs_thresh: float = -92.0
    capture_db: float = 4.0
    t_beacon: float = 2.0
    t_data: float = 5.0
    params: IdsParams = field(default_factory=IdsParams)


class Frame:
    __slots__ = ("kind", "phy", "tx", "txseq", "orig", "seq", "nxt", "hop",
                 "cost", "parent", "size", "tgen", "payload")

    def __init__(self, kind, phy, tx, txseq, orig, seq, nxt, hop, cost,
                 parent, size, tgen, payload=None):
        self.kind, self.phy, self.tx, self.txseq = kind, phy, tx, txseq
        self.orig, self.seq, self.nxt, self.hop = orig, seq, nxt, hop
        self.cost, self.parent, self.size = cost, parent, size
        self.tgen, self.payload = tgen, payload

    def copy(self):
        return Frame(self.kind, self.phy, self.tx, self.txseq, self.orig,
                     self.seq, self.nxt, self.hop, self.cost, self.parent,
                     self.size, self.tgen, self.payload)


class Nbr:
    __slots__ = ("beacons", "frames", "rssi_sum", "rssi_n", "replays",
                 "hand", "over", "hand_own", "over_own", "prr", "mu", "dev",
                 "warm", "cost", "hop", "parent", "last", "max_seq",
                 "recent", "bad_claims")

    def __init__(self):
        self.beacons = self.frames = self.rssi_n = self.replays = 0
        self.rssi_sum = 0.0
        self.hand = deque([0], maxlen=3)
        self.over = deque([0], maxlen=3)
        self.hand_own = deque([0], maxlen=3)
        self.over_own = deque([0], maxlen=3)
        self.prr = None
        self.mu = self.dev = 0.0
        self.warm = 0
        self.cost, self.hop, self.parent = INF, 255, None
        self.last = -INF
        self.max_seq = -1
        self.recent = set()
        self.bad_claims = 0


class Node:
    def __init__(self, sim, nid, phy, role="honest"):
        self.sim, self.id, self.phy, self.role = sim, nid, phy, role
        self.txq = deque()
        self.busy = False
        self.txseq = 0
        self.dataseq = 0
        self.repseq = 0
        self.is_sink = nid == SINK
        self.cost = 0.0 if self.is_sink else INF
        self.hop = 0 if self.is_sink else 255
        self.parent = None
        self.nbrs = {}
        self.fwd_seen = {}
        self.pending = {}
        self.asnl = frozenset()
        self.asnl_last = frozenset()
        self.asnl_known = False
        self.ctl_seen = -1
        self.blacklist = set()
        self.local_suspects = set()
        self.badmouth_target = None
        self.joined = False

    # ---------------------------------------------------------------- tx
    def send(self, f):
        f.txseq = self.txseq
        self.txseq += 1
        self.txq.append(f)
        if not self.busy:
            self.busy = True
            self.sim.at(self.sim.t + 1e-5, self.sim.try_tx, self)

    def expect(self, nxt, f, own):
        """Register a watchdog expectation that nxt forwards frame f."""
        if nxt == SINK or nxt == BCAST or nxt == self.id:
            return
        nb = self.nbrs.get(nxt)
        # third-party monitors need a good link to overhear the forward;
        # a neighbour advertising no route is not expected to forward
        if nb is None or (nb.prr or 0) < (0.3 if own else 0.7) \
                or nb.cost == INF:
            return
        key = (nxt, f.kind, f.orig, f.seq)
        if key in self.pending:
            return
        self.pending[key] = (self.sim.t + 0.4, own)
        nb.hand[-1] += 1
        if own:
            nb.hand_own[-1] += 1

    def originate(self, kind, size, payload=None):
        if self.parent is None:
            return False
        if kind == "D":
            seq = self.dataseq
            self.dataseq += 1
        else:
            seq = self.repseq
            self.repseq += 1
        f = Frame(kind, self.phy, self.id, 0, self.id, seq, self.parent,
                  1, 0, None, size, self.sim.t, payload)
        self.fwd_seen[(kind, self.id, seq)] = self.sim.t
        self.expect(self.parent, f, True)
        self.send(f)
        return True

    # ---------------------------------------------------------------- rx
    def on_rx(self, f, rssi):
        sim = self.sim
        t = sim.t
        j = f.tx
        if j == self.id:
            return
        nb = self.nbrs.get(j)
        if nb is None:
            nb = self.nbrs[j] = Nbr()
        nb.frames += 1
        # per-hop freshness window (64 entries) -- authenticated seq
        s = f.txseq
        if s <= nb.max_seq - 64 or s in nb.recent:
            nb.replays += 1
            return
        nb.recent.add(s)
        if s > nb.max_seq:
            nb.max_seq = s
            if len(nb.recent) > 128:
                nb.recent = {x for x in nb.recent if x > s - 64}
        nb.rssi_sum += rssi
        nb.rssi_n += 1
        nb.last = t

        k = f.kind
        if k in "DR":
            key = (j, k, f.orig, f.seq)
            pe = self.pending.pop(key, None)
            if pe is not None and pe[0] >= t:
                nb.over[-1] += 1
                if pe[1]:
                    nb.over_own[-1] += 1
            if f.nxt == self.id:
                self.handle_forward(f)
            else:
                self.expect(f.nxt, f, False)
        elif k == "B":
            nb.beacons += 1
            nb.cost, nb.hop, nb.parent = f.cost, f.hop, f.parent
            if (f.hop == 1 and self.asnl_known and j not in self.asnl):
                nb.bad_claims += 1
            self.update_route()
        elif k == "C":
            ctl_seq, asnl, bl = f.payload
            if ctl_seq > self.ctl_seen:
                self.ctl_seen = ctl_seq
                # a claim must be absent from the last two signed lists
                self.asnl = asnl | self.asnl_last
                self.asnl_last = asnl
                self.asnl_known = len(asnl) > 0
                if sim.cfg.mitigation:
                    self.blacklist = set(bl)
                if self.role != "sink":
                    g = f.copy()
                    g.phy, g.tx = self.phy, self.id
                    sim.at(t + sim.rng.uniform(0.002, 0.02), self.send, g)

    def handle_forward(self, f):
        sim = self.sim
        key = (f.kind, f.orig, f.seq)
        if key in self.fwd_seen:
            return
        self.fwd_seen[key] = sim.t
        if self.is_sink:
            sim.deliver(f)
            return
        if f.hop >= 15 or self.parent is None:
            return
        if sim.is_dropping(self):
            return
        g = f.copy()
        g.phy, g.tx, g.nxt, g.hop = self.phy, self.id, self.parent, f.hop + 1
        self.expect(self.parent, g, True)
        sim.at(sim.t + sim.rng.uniform(0.001, 0.003), self.send, g)

    # ----------------------------------------------------------- routing
    def update_route(self):
        if self.is_sink:
            return
        sim = self.sim
        t = sim.t
        best, best_c = None, INF
        cur_c = INF
        for j, nb in self.nbrs.items():
            if nb.cost == INF or t - nb.last > 3 * sim.cfg.t_beacon + 0.5:
                continue
            if nb.parent == self.id or j in self.blacklist:
                continue
            if sim.cfg.mitigation and j in self.local_suspects:
                continue
            # unestimated links are only usable while bootstrapping
            prr = nb.prr if nb.prr is not None else (
                0.7 if self.parent is None else 0.0)
            if prr < 0.6:
                continue
            c = nb.cost + 1.0 / prr
            if j == self.parent:
                cur_c = c
            if c < best_c:
                best, best_c = j, c
        if best is None:
            self.parent, self.cost, self.hop = None, INF, 255
            return
        if self.parent is None or cur_c == INF or best_c < cur_c - 0.3:
            self.parent = best
            self.cost = best_c
        else:
            self.cost = cur_c
        self.hop = self.nbrs[self.parent].hop + 1

    # ----------------------------------------------------------- windows
    def end_window(self, k):
        sim, p = self.sim, self.sim.cfg.params
        W = p.window_s
        t = sim.t
        exp_beacons = W / sim.cfg.t_beacon
        self.pending = {kk: v for kk, v in self.pending.items() if v[0] >= t}
        if len(self.fwd_seen) > 4000:
            self.fwd_seen = {kk: v for kk, v in self.fwd_seen.items()
                             if v > t - 60}
        recs = []
        for j, nb in self.nbrs.items():
            if nb.frames == 0 and sum(nb.hand) == 0 and t - nb.last > 3 * W:
                continue
            ratio = min(1.0, nb.beacons / exp_beacons)
            nb.prr = ratio if nb.prr is None else 0.7 * nb.prr + 0.3 * ratio
            rate = nb.frames / W
            r = NbrRecord(
                nbr=j, handed=sum(nb.hand), overheard=sum(nb.over),
                prr=nb.prr,
                rssi=(nb.rssi_sum / nb.rssi_n) if nb.rssi_n else 0.0,
                rssi_n=nb.rssi_n, rate=rate, rate_base=nb.mu,
                rate_dev=nb.dev, warm=nb.warm, replays=nb.replays,
                beacons=nb.beacons, bad_claims=nb.bad_claims,
                asnl_known=self.asnl_known,
                hand_own=sum(nb.hand_own), over_own=sum(nb.over_own))
            v = local_verdicts(r, p)
            if "FLOOD" not in v:
                if nb.warm == 0:
                    nb.mu = rate
                else:
                    nb.dev = 0.8 * nb.dev + 0.2 * abs(rate - nb.mu)
                    nb.mu = 0.8 * nb.mu + 0.2 * rate
            nb.warm += 1
            if FWD in v and sim.cfg.mitigation:
                self.local_suspects.add(j)
            recs.append((v, r))
            nb.beacons = nb.frames = nb.rssi_n = nb.replays = 0
            nb.bad_claims = 0
            nb.rssi_sum = 0.0
            for d in (nb.hand, nb.over, nb.hand_own, nb.over_own):
                d.append(0)
        # records with local alerts first, then by number of samples
        recs.sort(key=lambda x: (-len(x[0]), -x[1].rssi_n))
        records = [r for _, r in recs[:MAX_RECS]]
        sim.log_records(self, k, records)
        if self.role == "badmouth":
            records = sim.falsify(self, records)
        if self.is_sink:
            sim.fusion.add_report(self.id, k, records)
        else:
            size = HDR + 2 + REC_BYTES * len(records)
            sim.at(t + sim.rng.uniform(0.2, 3.0), self.originate, "R", size,
                   (k, records))
        if sim.cfg.mitigation:
            self.update_route()


class Simulator:
    def __init__(self, cfg: SimConfig):
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        self.t = 0.0
        self.q = []
        self.cnt = 0
        self.air = []
        self.fusion = Fusion(cfg.params)
        self.ctl_seq = 0
        self.attackers = set()
        self.badmouthers = set()
        self.decisions = []          # (t, id, type) from online fusion
        self.received_reports = []   # (k, mon, records) as seen by sink
        self.generated = []          # (k, mon, records) as generated (truth)
        self.gen_log = []            # (t, orig) honest data generated
        self.del_log = []            # (tgen, tdel, orig)
        self.tx_bytes = defaultdict(int)
        self.tx_frames = defaultdict(int)
        self._build()

    # ---------------------------------------------------------- topology
    def _build(self):
        cfg, rng = self.cfg, self.rng
        g = cfg.grid
        pos = []
        for y in range(g):
            for x in range(g):
                pos.append((x * cfg.spacing + rng.uniform(-cfg.jitter, cfg.jitter),
                            y * cfg.spacing + rng.uniform(-cfg.jitter, cfg.jitter)))
        # sink = left-middle node, renumbered to id 0
        si = (g // 2) * g
        pos[0], pos[si] = pos[si], pos[0]
        self.n_members = len(pos)
        self.nodes = []
        for i in range(len(pos)):
            self.nodes.append(Node(self, i, i, "sink" if i == SINK else "honest"))
        # attackers
        a = cfg.attack
        mid = [i for i in range(1, len(pos))
               if 0.25 * (g - 1) * cfg.spacing <= pos[i][0] <= 0.6 * (g - 1) * cfg.spacing
               and abs(pos[i][1] - pos[0][1]) <= 1.2 * cfg.spacing]
        if not mid:
            mid = list(range(1, len(pos)))
        self.victim_pool = mid
        if a in ("selfwd", "sinkhole"):
            v = None                     # chosen at t_attack: busiest relay
        if a in ("flood", "sybil"):
            v = rng.choice(mid)
            self.nodes[v].role = a
            self.attackers.add(v)
        if a == "sybil":
            phy = v
            for s in range(cfg.n_sybil):
                fid = 1000 + s
                fake = Node(self, fid, phy, "sybil_fake")
                self.nodes.append(fake)
                self.attackers.add(fid)
        if a == "replay":
            cx = sum(p[0] for p in pos) / len(pos)
            cy = pos[0][1]
            pos.append((cx + rng.uniform(-5, 5), cy + rng.uniform(-8, 8)))
            rep = Node(self, 900, len(pos) - 1, "replayer")
            rep.store = []
            self.nodes.append(rep)
            self.replayer = rep
        honest = [i for i in range(1, self.n_members) if i not in self.attackers]
        nb = int(round(cfg.badmouth_frac * len(honest)))
        for i in rng.sample(honest, nb):
            self.nodes[i].role = "badmouth"
            self.badmouthers.add(i)
        self.pos = pos
        n = len(pos)
        # link budget with symmetric static shadowing
        self.mean = [[-200.0] * n for _ in range(n)]
        for i in range(n):
            for k in range(i + 1, n):
                d = max(1.0, math.dist(pos[i], pos[k]))
                r = (cfg.ptx - cfg.pl0 - 10 * cfg.ple * math.log10(d)
                     + rng.gauss(0, cfg.sigma_s))
                self.mean[i][k] = self.mean[k][i] = r
        self.cand = [[(k, self.mean[i][k]) for k in range(n)
                      if k != i and self.mean[i][k] > cfg.sens - 10]
                     for i in range(n)]
        self.phy_node = {}
        for nd in self.nodes:
            if nd.role != "sybil_fake":
                self.phy_node[nd.phy] = nd

    # ---------------------------------------------------------- engine
    def at(self, t, fn, *args):
        self.cnt += 1
        heapq.heappush(self.q, (t, self.cnt, fn, args))

    def run(self):
        cfg, rng = self.cfg, self.rng
        W = cfg.params.window_s
        for nd in self.nodes:
            if nd.role == "replayer":
                continue
            self.at(rng.uniform(0, cfg.t_beacon), self.beacon, nd)
            if nd.role == "sybil_fake":
                continue
            if not nd.is_sink:
                self.at(rng.uniform(1, cfg.t_data) + 10, self.data, nd)
        k = 0
        while (k + 1) * W <= cfg.duration:
            self.at((k + 1) * W, self.window, k)
            self.at((k + 1) * W + 6.0, self.decide, k)
            self.at(k * W + 8.0, self.netctl)
            k += 1
        a = cfg.attack
        if a in ("selfwd", "sinkhole"):
            self.at(cfg.t_attack - 1e-3, self.compromise_relay)
        if a == "flood":
            self.at(cfg.t_attack, self.flood, self.nodes[next(iter(self.attackers))])
        if a == "replay":
            self.at(cfg.t_attack, self.replay)
        while self.q:
            t, _, fn, args = heapq.heappop(self.q)
            if t > cfg.duration + 7:
                break
            self.t = t
            fn(*args)
        return self

    # --------------------------------------------------------- channel
    def try_tx(self, nd, tries=0):
        if not nd.txq:
            nd.busy = False
            return
        t = self.t
        self.air = [a for a in self.air if a[1] > t - 0.01]
        mean = self.mean[nd.phy]
        if tries < 7:
            for (s, e, ph, _) in self.air:
                if s <= t < e and ph != nd.phy and mean[ph] > self.cfg.cs_thresh:
                    self.at(t + self.rng.uniform(2e-4, 1.5e-3), self.try_tx, nd,
                            tries + 1)
                    return
        f = nd.txq.popleft()
        f.phy = nd.phy
        dur = airtime(f.size)
        ent = (t, t + dur, nd.phy, f)
        self.air.append(ent)
        self.tx_bytes[(f.phy, f.kind)] += f.size
        self.tx_frames[(f.phy, f.kind)] += 1
        self.at(t + dur, self.end_tx, nd, ent)

    def end_tx(self, nd, ent):
        s, e, phy, f = ent
        cfg, rng = self.cfg, self.rng
        overl = [a for a in self.air if a is not ent and a[0] < e and a[1] > s]
        for (r, mr) in self.cand[phy]:
            rn = self.phy_node.get(r)
            if rn is None:
                continue
            rssi = mr + rng.gauss(0, cfg.sigma_f)
            if rng.random() > 1.0 / (1.0 + math.exp(-(rssi - cfg.sens))):
                continue
            lost = False
            for (s2, e2, ph2, _) in overl:
                if ph2 == r or self.mean[ph2][r] > rssi - cfg.capture_db:
                    lost = True
                    break
            if lost:
                continue
            if rn.role == "replayer":
                if len(rn.store) < 2000 and f.kind in "BD":
                    rn.store.append(f.copy())
                continue
            rn.on_rx(f, rssi)
        self.at(self.t + 1e-4, self.try_tx, nd)

    # --------------------------------------------------------- traffic
    def beacon(self, nd):
        cfg = self.cfg
        if nd.role == "sybil_fake":
            if self.t >= cfg.t_attack:
                real = self.nodes[nd.phy]
                f = Frame("B", nd.phy, nd.id, 0, nd.id, 0, BCAST, real.hop,
                          real.cost, real.parent, HDR + 8, self.t)
                nd.txq.append(f)
                f.txseq = nd.txseq
                nd.txseq += 1
                if not nd.busy:
                    nd.busy = True
                    self.at(self.t + 1e-5, self.try_tx, nd)
        else:
            nd.update_route()
            hop, cost, parent = nd.hop, nd.cost, nd.parent
            if nd.role == "sinkhole" and self.t >= cfg.t_attack:
                hop, cost, parent = 1, 1.0, SINK
            if nd.parent is not None:
                nd.joined = True
            # joined nodes keep beaconing; cost = inf poisons a lost route
            if nd.is_sink or nd.joined or nd.role == "sinkhole":
                nd.send(Frame("B", nd.phy, nd.id, 0, nd.id, 0, BCAST, hop,
                              cost, parent, HDR + 8, self.t))
        self.at(self.t + cfg.t_beacon + self.rng.uniform(-0.1, 0.1),
                self.beacon, nd)

    def data(self, nd):
        if nd.id not in self.attackers and nd.role != "badmouth":
            self.gen_log.append((self.t, nd.id))
        nd.originate("D", HDR + 16)
        self.at(self.t + self.cfg.t_data, self.data, nd)

    def deliver(self, f):
        if f.kind == "D":
            if f.orig not in self.attackers and f.orig not in self.badmouthers:
                self.del_log.append((f.tgen, self.t, f.orig))
        elif f.kind == "R":
            k, records = f.payload
            self.received_reports.append((k, f.orig, records))
            self.fusion.add_report(f.orig, k, records)

    def netctl(self):
        sink = self.nodes[SINK]
        # signed sink-neighbour list; empty until link estimates exist
        asnl = frozenset(j for j, nb in sink.nbrs.items()
                         if (nb.prr is not None and nb.prr >= 0.3)
                         or nb.beacons >= 2)
        if self.t < 2 * self.cfg.params.window_s:     # bootstrap phase
            asnl = frozenset()
        bl = tuple(sorted(self.fusion.blacklist)) if self.cfg.mitigation else ()
        self.ctl_seq += 1
        size = HDR + 4 + 2 * (len(asnl) + len(bl)) + 64   # + ECDSA-P256 sig
        sink.send(Frame("C", sink.phy, SINK, 0, SINK, self.ctl_seq, BCAST, 0, 0,
                        None, size, self.t, (self.ctl_seq, asnl, bl)))

    def window(self, k):
        for nd in self.nodes:
            if nd.role not in ("sybil_fake", "replayer"):
                nd.end_window(k)

    def decide(self, k):
        for j, typ in self.fusion.decide(k, self.t):
            self.decisions.append((self.t, j, typ))

    # --------------------------------------------------------- attacks
    def compromise_relay(self):
        desc = defaultdict(int)
        for nd in self.nodes[1:self.n_members]:
            seen, p = set(), nd.parent
            while p not in (None, SINK) and p not in seen:
                seen.add(p)
                desc[p] += 1
                p = self.nodes[p].parent
        v = max(self.victim_pool, key=lambda i: (desc[i], -i))
        self.nodes[v].role = self.cfg.attack
        self.attackers.add(v)
        # a bad-mouther cannot also be the compromised relay
        if v in self.badmouthers:
            self.badmouthers.discard(v)

    def is_dropping(self, nd):
        if self.t < self.cfg.t_attack:
            return False
        if nd.role == "selfwd":
            return self.rng.random() < self.cfg.drop_p
        if nd.role == "sinkhole":
            return True
        return False

    def flood(self, nd):
        f = Frame("J", nd.phy, nd.id, 0, nd.id, 0, BCAST, 0, 0, None, 50, self.t)
        nd.send(f)
        self.at(self.t + self.rng.expovariate(self.cfg.flood_fps), self.flood, nd)

    def replay(self):
        rep = self.replayer
        if rep.store:
            f = self.rng.choice(rep.store).copy()
            f.phy = rep.phy
            rep.txq.append(f)                # replayed verbatim (old txseq)
            if not rep.busy:
                rep.busy = True
                self.at(self.t + 1e-5, self.try_tx, rep)
        self.at(self.t + self.rng.expovariate(self.cfg.replay_fps), self.replay)

    def falsify(self, nd, records):
        """Colluding bad-mouthers all accuse one common honest victim,
        fabricating a record when they do not actually hear it."""
        if getattr(self, "bm_target", None) is None:
            cands = [i for i in range(1, self.n_members)
                     if i not in self.attackers and i not in self.badmouthers]
            self.bm_target = max(cands, key=lambda i: sum(
                self.mean[i][b] > -85 for b in self.badmouthers))
        tgt = self.bm_target
        out = [r for r in records if r.nbr != tgt]
        out.append(NbrRecord(nbr=tgt, handed=12, overheard=0, prr=0.9,
                             rssi=-70.0, rssi_n=8, rate=1.0, rate_base=1.0,
                             rate_dev=0.2, warm=10, replays=0, beacons=5,
                             bad_claims=0, asnl_known=True))
        return out

    def log_records(self, nd, k, records):
        if nd.role in ("honest", "sink") or nd.id in self.attackers:
            self.generated.append((k, nd.id, records))

    # --------------------------------------------------------- results
    @property
    def honest(self):
        return [i for i in range(1, self.n_members)
                if i not in self.attackers and i not in self.badmouthers]
