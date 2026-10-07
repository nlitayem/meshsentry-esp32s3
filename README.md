# MeshSentry — collaborative intrusion detection for ESP-NOW meshes (ESP32-S3)

Research project: firmware, simulator, and IEEE conference paper draft.

```
esp32s3_mesh_ids/
├── firmware/                 ESP-IDF v6.1 project (target esp32s3)
│   ├── components/proto/     wire format (frame, report record, control frame)
│   ├── components/mesh/      ESP-NOW broadcast mesh, ETX routing, PSA-Crypto
│   │                         HMAC/ECDSA, signed control flood, window sync
│   ├── components/ids/       ids_monitor (per-neighbour features), ids_detect
│   │                         (binomial / EWMA / route / replay), ids_fusion (sink)
│   ├── components/attack/    testbed attack emulation (attacker role only)
│   ├── configs/              role overlays: sink, node, attack_<type>
│   └── tools/                build_all.sh, gen_keys.py, collect_logs.py,
│                             footprint_tex.py
├── sim/                      discrete-event simulator + reference IDS (Python)
│   ├── meshsentry/           sim.py, ids.py (mirrors the C code), evaluate.py
│   ├── run_experiments.py    all campaigns -> results/*.pkl
│   └── make_figures.py       figures -> paper/figures, results/summary.json
└── paper/                    IEEEtran conference paper (main.tex, refs.bib)
```

## Firmware

```bash
. ~/esp/esp-idf-v6.1/export.sh
cd firmware
tools/build_all.sh                 # builds build_sink, build_node, build_attack_*
idf.py -B build_sink  -p /dev/ttyACM0 flash monitor
idf.py -B build_node  -p /dev/ttyACM1 flash          # repeat per node
python tools/collect_logs.py /dev/ttyACM0 sink.csv   # sink decisions + reports
```

The first build runs `tools/gen_keys.py`, which creates `keys/mesh_keys.h`
(network HMAC key and sink ECDSA-P256 key pair). Flash every node of one
testbed from the same checkout so that all nodes share the keys. These are
testbed keys only. A deployment should use per-device provisioning (eFuse
HMAC key, DS peripheral).

Role, node ID, TX power (default 2 dBm, for multi-hop range on a desk), and
all IDS thresholds are set in `idf.py menuconfig` → *MeshSentry ...*.

The attacker images are for controlled experiments on equipment you own.

## Simulation and figures

```bash
python3 -m venv .venv && .venv/bin/pip install -r sim/requirements.txt
cd sim
../.venv/bin/python run_experiments.py --seeds 20 --jobs 3   # ~6 min on 4 cores
../.venv/bin/python make_figures.py
```

## Paper

```bash
cd paper && tectonic main.tex      # or: latexmk -pdf main.tex
```
`paper/footprint.tex` is generated from the real build by
`firmware/tools/footprint_tex.py`. The red `[TODO: ...]` markers flag the
author's affiliation, the hardware testbed results, and the per-frame CPU and
energy measurements that are still to be done.
