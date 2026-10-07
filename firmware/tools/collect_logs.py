#!/usr/bin/env python3
"""Capture MeshSentry CSV events from a node's USB console.

Every firmware line starting with "MS," is written to a CSV file:
    MS,<sink_ms>,<node>,<EVENT>,<fields...>
Events: GEN, DLV, REC (own records), RPT (records received by the sink),
DEC (sink decisions), STAT (per-window counters).

Usage:  python tools/collect_logs.py /dev/ttyACM0 sink.csv
Requires pyserial (installed in the ESP-IDF Python environment).
"""
import sys

import serial


def main(port, out, baud=115200):
    with serial.Serial(port, baud, timeout=1) as ser, open(out, "a") as fh:
        print(f"logging {port} -> {out} (Ctrl+C to stop)")
        while True:
            line = ser.readline().decode(errors="replace").strip()
            if line.startswith("MS,"):
                fh.write(line[3:] + "\n")
                fh.flush()
                if ",DEC," in line:
                    print(line)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    try:
        main(sys.argv[1], sys.argv[2])
    except KeyboardInterrupt:
        pass
