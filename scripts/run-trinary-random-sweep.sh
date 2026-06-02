#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./run-trinary-random-sweep.sh [options]

Run randomized trinary/qmag synthetic sweeps and emit a statistical summary.

Options:
  --iterations N        Number of randomized sweeps to run (default: 10000)
  --seed N              PRNG seed (default: current epoch)
  --iters-per-pass N     QIHSE_BENCH_ITERS for each benchmark pass (default: 1)
  --output-dir PATH      Output directory (default: results/sweep10000)
  --build                Force lib rebuild before benchmark run
  --c-flags "FLAGS"      Extra compile flags for benchmark binary
  -h, --help            Show this help message
EOF
}

iterations=10000
seed=""
iters_per_pass=1
output_dir="results/sweep10000"
extra_cflags=""
force_rebuild=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iterations)
            iterations=$2
            shift 2
            ;;
        --seed)
            seed=$2
            shift 2
            ;;
        --iters-per-pass)
            iters_per_pass=$2
            shift 2
            ;;
        --output-dir)
            output_dir=$2
            shift 2
            ;;
        --c-flags)
            extra_cflags=$2
            shift 2
            ;;
        --build)
            force_rebuild=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ "$iterations" -le 0 ]]; then
    echo "--iterations must be >= 1" >&2
    exit 1
fi

if [[ "$iters_per_pass" -le 0 ]]; then
    echo "--iters-per-pass must be >= 1" >&2
    exit 1
fi

if [[ -z "$seed" ]]; then
    seed=$(date +%s)
fi

cd "$(cd "$(dirname "$0")" && pwd)"

if [[ "$force_rebuild" -eq 1 ]]; then
    make -s lib
fi

mkdir -p "$output_dir"

binary="/tmp/qihse_trinary_search_path_bench_rand"
source_file="benchmarks/qihse_trinary_db_candidate_bench.c"

cc_cmd=(gcc -std=c99 -Wall -Wextra -I. -I./core -I./algorithms -I./backends/cpu -I./backends/npu \
    -I./orchestration/include -I./memory/include -I./quantization/include -I./ml/include \
    -fPIC -lm -pthread -D_GNU_SOURCE -O3 -DQIHSE_BENCH_ITERS=${iters_per_pass} -o "$binary" "$source_file" -L. -lqihse -ldl -lpthread -lm)

if [[ -n "$extra_cflags" ]]; then
    read -r -a extra_flags <<< "$extra_cflags"
    cc_cmd+=("${extra_flags[@]}")
fi

echo "[sweep] compile: ${cc_cmd[*]}"
"${cc_cmd[@]}"

sweep_log="$output_dir/sweep.log"
sweep_meta="$output_dir/sweep.meta"
sweep_summary="$output_dir/summary.txt"
sweep_summary_json="$output_dir/summary.json"

: > "$sweep_log"
: > "$sweep_meta"

declare -a datasets=(aligned banded weighted magnitude_skew near_tie)
declare -a modes=(scalar weighted magnitude)

state=$((seed & 0x7fffffff))
if [[ "$state" -le 0 ]]; then
    state=123456789
fi

rand_int() {
    state=$(( (1103515245 * state + 12345) & 2147483647 ))
    printf '%d' "$state"
}

for ((i = 1; i <= iterations; ++i)); do
    r_dataset=$(rand_int)
    r_mode=$(rand_int)
    idx_dataset=$((r_dataset % ${#datasets[@]}))
    idx_mode=$((r_mode % ${#modes[@]}))
    dataset=${datasets[$idx_dataset]}
    mode=${modes[$idx_mode]}

    printf 'iter=%d dataset=%s mode=%s\n' "$i" "$dataset" "$mode" >> "$sweep_meta"
    QIHSE_BENCH_SWEEP=1 \
        QIHSE_BENCH_DATASET="$dataset" \
        QIHSE_BENCH_TRINARY_SCORE="$mode" \
        LD_LIBRARY_PATH=. "$binary" >> "$sweep_log"

    if ((i % 500 == 0)); then
        echo "[sweep] progress ${i}/${iterations}"
    fi
done

echo "[sweep] writing summary from $output_dir"
python3 - <<'PY'
import json
import math
import re
from statistics import mean

from pathlib import Path

log_path = Path(r"$sweep_log")
meta_path = Path(r"$sweep_meta")
summary_txt = Path(r"$sweep_summary")
summary_json = Path(r"$sweep_summary_json")

log_lines = [line.strip() for line in log_path.read_text().splitlines() if line.strip()]
meta_lines = [line.strip() for line in meta_path.read_text().splitlines() if line.strip()]

pat_meta = re.compile(r"iter=(\\d+) dataset=([^ ]+) mode=([^ ]+)")
pat_header = re.compile(r"dataset=([^ ]+) score=([^ ]+) query_path=([^ ]+) .* candidates=(\\d+) topk=(\\d+) iterations=(\\d+)")
pat_stats = re.compile(r"speedup_vs_full=([0-9.]+)x recall_at_(\\d+)=([0-9.]+) ordered_at_\\d+=([0-9.]+)")

runs = []
for line in meta_lines:
    m = pat_meta.match(line)
    if m:
        runs.append((int(m.group(1)), m.group(2), m.group(3)))

if len(log_lines) % 2 != 0:
    raise SystemExit("sweep log is incomplete")

passes = len(log_lines) // 2
passes_per_run = 9
max_runs = min(len(runs), passes // passes_per_run)

records = []
for p in range(max_runs * passes_per_run):
    header = log_lines[p * 2]
    stats = log_lines[p * 2 + 1]
    hm = pat_header.match(header)
    sm = pat_stats.match(stats)
    if not hm or not sm:
        raise SystemExit(f"malformed sweep pair at pass={p}")
    run_id = (p // passes_per_run) + 1
    _, dataset, mode = runs[run_id - 1]
    records.append(
        dict(
            sweep=run_id,
            dataset=dataset,
            mode=mode,
            score=hm.group(2),
            candidates=int(hm.group(4)),
            topk=int(hm.group(5)),
            speedup=float(sm.group(1)),
            recall=float(sm.group(3)),
            ordered=float(sm.group(4)),
        )
    )

def ci(successes, total):
    if total == 0:
        return 0.0, 0.0, 0.0
    ph = successes / total
    se = math.sqrt(ph * (1 - ph) / total)
    lo = max(0.0, ph - 1.96 * se)
    hi = min(1.0, ph + 1.96 * se)
    return ph, lo, hi

def bucket(stats, predicate):
    subset = [r for r in records if predicate(r)]
    n = len(subset)
    wins = sum(1 for r in subset if r["recall"] >= 0.999 and r["speedup"] > 1.0)
    p, lo, hi = ci(wins, n)
    return {
        "n": n,
        "wins": wins,
        "rate": p,
        "ci95": [lo, hi],
        "mean_speedup": mean(r["speedup"] for r in subset) if subset else 0.0,
        "mean_recall": mean(r["recall"] for r in subset) if subset else 0.0,
    }

summary = {
    "iterations": int(r"$iterations"),
    "passes_per_run": passes_per_run,
    "iters_per_pass": int(r"$iters_per_pass"),
    "seed": int(r"$seed"),
    "sweeps_parsed": max_runs,
    "pass_records": len(records),
    "qmag_pass": bucket(records, lambda r: r["mode"] == "magnitude"),
    "qtri_pass": bucket(records, lambda r: r["mode"] in ("scalar", "weighted")),
    "full_candidate": {
        m: bucket(records, lambda r, m=m: r["mode"] == m and r["candidates"] == 2048)
        for m in ("scalar", "weighted", "magnitude")
    },
}

sweep_level = {}
for mode in ("scalar", "weighted", "magnitude"):
    mode_runs = [r for r in runs if r[2] == mode]
    if not mode_runs:
        sweep_level[mode] = {"n": 0, "wins": 0, "rate": 0.0, "ci95": [0.0, 0.0]}
        continue
    wins = 0
    total = 0
    for run_id, _, m in mode_runs:
        if m != mode:
            continue
        base = (run_id - 1) * passes_per_run
        slice_ = records[base: base + passes_per_run]
        total += 1
        if any(r["recall"] >= 0.999 and r["speedup"] > 1.0 for r in slice_):
            wins += 1
    p, lo, hi = ci(wins, total)
    sweep_level[mode] = {"n": total, "wins": wins, "rate": p, "ci95": [lo, hi]}

summary["sweep_level"] = sweep_level

for mode in ("scalar", "weighted", "magnitude"):
    vals = sorted(r["speedup"] for r in records if r["mode"] == mode)
    if vals:
        n = len(vals)
        summary.setdefault("speedup_quantiles", {})[mode] = {
            "min": vals[0],
            "p50": vals[int(0.50 * (n - 1))],
            "p90": vals[int(0.90 * (n - 1))],
            "p95": vals[int(0.95 * (n - 1))],
            "p99": vals[int(0.99 * (n - 1))],
            "max": vals[-1],
        }

with summary_txt.open("w", encoding="utf-8") as out:
    out.write(f"iterations={summary['iterations']} sweeps_parsed={summary['sweeps_parsed']} pass_records={summary['pass_records']}\n")
    out.write("qmag_pass_win_rate={:.6f} ci95=[{:.6f},{:.6f}]\n".format(summary['qmag_pass']["rate"], summary['qmag_pass']["ci95"][0], summary['qmag_pass']["ci95"][1]))
    out.write("qmag_full_pass_win_rate={:.6f}\n".format(summary['full_candidate']['magnitude']["rate"]))
    out.write("qtri_pass_win_rate={:.6f} ci95=[{:.6f},{:.6f}]\n".format(summary['qtri_pass']["rate"], summary['qtri_pass']["ci95"][0], summary['qtri_pass']["ci95"][1]))
    for mode, mode_summary in summary['sweep_level'].items():
        out.write("sweep_mode={mode} wins={wins}/{total} rate={rate:.6f} ci95=[{lo:.6f},{hi:.6f}]\n".format(
            mode=mode,
            wins=mode_summary['wins'],
            total=mode_summary['n'],
            rate=mode_summary['rate'],
            lo=mode_summary['ci95'][0],
            hi=mode_summary['ci95'][1],
        ))

summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
PY

echo "[sweep] summary written: $sweep_summary"
echo "[sweep] summary json written: $sweep_summary_json"
