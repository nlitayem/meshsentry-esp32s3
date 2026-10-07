#!/usr/bin/env python3
"""Run all simulation campaigns used in the paper and cache the traces.

Usage:  python run_experiments.py [--seeds 20] [--jobs 3]
Output: results/<campaign>.pkl
"""
import argparse
import os
import pickle
import time
from multiprocessing import Pool

from meshsentry.sim import SimConfig
from meshsentry.evaluate import run_one

ATTACKS = [None, "selfwd", "sinkhole", "flood", "replay", "sybil"]


def campaigns(n):
    c = {}
    c["main"] = [SimConfig(attack=a, seed=1000 + s) for a in ATTACKS for s in range(n)]
    c["droprate"] = [SimConfig(attack="selfwd", drop_p=p, seed=100 + s)
                     for p in (0.2, 0.4, 0.6, 0.8, 1.0) for s in range(n)]
    c["badmouth"] = [SimConfig(attack="selfwd", badmouth_frac=f, seed=200 + s)
                     for f in (0.0, 0.1, 0.2, 0.3, 0.4) for s in range(n)]
    c["mitigation"] = [SimConfig(attack=a, mitigation=m, seed=300 + s)
                       for a in ("sinkhole", "selfwd") for m in (False, True)
                       for s in range(n)]
    c["scale"] = [SimConfig(grid=g, seed=400 + s)
                  for g in (4, 5, 6, 7) for s in range(max(3, n // 4))]
    return c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()
    os.makedirs("results", exist_ok=True)
    for name, cfgs in campaigns(a.seeds).items():
        if a.only and name not in a.only:
            continue
        t0 = time.time()
        with Pool(a.jobs) as pool:
            runs = pool.map(run_one, cfgs, chunksize=1)
        with open(f"results/{name}.pkl", "wb") as fh:
            pickle.dump(runs, fh)
        print(f"{name}: {len(runs)} runs in {time.time() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
