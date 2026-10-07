#!/usr/bin/env bash
# Build every role variant into build_<role>/ (requires ESP-IDF in the env).
# Usage: tools/build_all.sh [role...]   roles: sink node attack_selfwd ...
set -euo pipefail
cd "$(dirname "$0")/.."
roles=("$@")
[ ${#roles[@]} -eq 0 ] && roles=(sink node attack_selfwd attack_sinkhole attack_flood attack_replay attack_sybil)
for r in "${roles[@]}"; do
    echo "=== $r"
    idf.py -B "build_$r" -D SDKCONFIG="build_$r/sdkconfig" \
        -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;configs/$r.defaults" \
        set-target esp32s3 build > "build_$r.log" 2>&1 \
        && grep -h "Project build complete" "build_$r.log" \
        || { grep -E " error: " "build_$r.log" | head; exit 1; }
done
