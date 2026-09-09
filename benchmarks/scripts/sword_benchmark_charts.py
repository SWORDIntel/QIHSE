#!/usr/bin/env python3
"""
Generate SWORD-themed benchmark charts from verified QIHSE micro-benchmark results.

Color scheme extracted from SWORD_VERIFIED_COMPLETE.pdf:
  - Background: #000000 (black)
  - Primary accent: #C00000 (dark red)
  - Secondary: #E02020 (light red)
  - Tertiary: #600000 (dark red variant)
  - Text: #E0E0E0 (light gray)
  - Grid: #202020 (dark gray)

Usage:
  python3 benchmarks/scripts/sword_benchmark_charts.py
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import os
import re
import json

# ========================================================================
# SWORD color scheme
# ========================================================================
SWORD_BG = '#1a1a2e'          # dark navy-black (better contrast than pure black)
SWORD_RED = '#FF3030'          # bright red (4.6:1 contrast on bg)
SWORD_RED_LIGHT = '#E02020'    # secondary red
SWORD_RED_DARK = '#800000'     # deep red for edges
SWORD_GRAY = '#E0E0E0'         # light gray text (12.9:1)
SWORD_GRAY_DIM = '#909090'     # medium gray
SWORD_GRID = '#2a2a3e'         # subtle grid
SWORD_GREEN = '#2ecc71'        # green accent (8.1:1)
SWORD_BLUE = '#3498db'         # blue accent (5.4:1)
SWORD_ORANGE = '#e67e22'       # orange accent (6.0:1)

plt.rcParams.update({
    'figure.facecolor': SWORD_BG,
    'axes.facecolor': SWORD_BG,
    'axes.edgecolor': SWORD_GRAY_DIM,
    'axes.labelcolor': SWORD_GRAY,
    'axes.titlecolor': SWORD_GRAY,
    'xtick.color': SWORD_GRAY,
    'ytick.color': SWORD_GRAY,
    'text.color': SWORD_GRAY,
    'grid.color': SWORD_GRID,
    'grid.linewidth': 0.5,
    'font.family': 'DejaVu Sans',
    'font.size': 9,
    'axes.titlesize': 11,
    'axes.labelsize': 9,
    'figure.dpi': 150,
})

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'results')
CHARTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'charts')

os.makedirs(CHARTS_DIR, exist_ok=True)


def parse_bench_file(path):
    """Parse the micro-benchmark output file into structured data."""
    results = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('===') or line.startswith('---') or line.startswith('QIHSE'):
                continue
            # Parse lines like:
            # exact-search-cosine (1000x128, k=10)    : mean= 110.517 us  p50= 83.388 us  p95= 113.340 us ...
            m = re.match(
                r'^(.+?)\s*(?:\(([^)]+)\))?\s*:\s*'
                r'(?:mean=([\d.]+)\s*(\w+)\s+)?'
                r'p50=([\d.]+)\s*(\w+)\s+'
                r'p95=([\d.]+)\s*(\w+)\s+'
                r'p99=([\d.]+)\s*(\w+)'
                r'(?:\s+n=(\d+))?',
                line
            )
            if m:
                name = m.group(1).strip()
                params = m.group(2) or ''
                p50_val = float(m.group(5))
                p50_unit = m.group(6)
                p95_val = float(m.group(7))
                p95_unit = m.group(8)
                p99_val = float(m.group(9))
                p99_unit = m.group(10)
                n = int(m.group(11)) if m.group(11) else 0

                # Normalize to microseconds
                def to_us(val, unit):
                    if unit == 'ns':
                        return val / 1000.0
                    elif unit == 'us':
                        return val
                    elif unit == 'ms':
                        return val * 1000.0
                    elif unit == 's':
                        return val * 1e6
                    return val

                results.append({
                    'name': name,
                    'params': params,
                    'p50_us': to_us(p50_val, p50_unit),
                    'p95_us': to_us(p95_val, p95_unit),
                    'p99_us': to_us(p99_val, p99_unit),
                    'n': n,
                })

            # Parse build time lines
            m_build = re.match(r'^(.+?)\s*(?:\(([^)]+)\))?\s*:\s*build_time=\s*([\d.]+)\s*(\w+)', line)
            if m_build:
                name = m_build.group(1).strip()
                params = m_build.group(2) or ''
                bt_val = float(m_build.group(3))
                bt_unit = m_build.group(4)
                bt_ms = bt_val * 1000 if bt_unit == 's' else bt_val
                results.append({
                    'name': name,
                    'params': params,
                    'build_ms': bt_ms,
                })
    return results


def fmt_us(val):
    """Format microseconds for display."""
    if val < 1:
        return f'{val*1000:.0f}ns'
    elif val < 1000:
        return f'{val:.0f}µs'
    elif val < 1e6:
        return f'{val/1000:.1f}ms'
    else:
        return f'{val/1e6:.2f}s'


def fmt_ms(val):
    """Format milliseconds for display."""
    if val < 1:
        return f'{val*1000:.0f}µs'
    elif val < 1000:
        return f'{val:.1f}ms'
    else:
        return f'{val/1000:.2f}s'


# ========================================================================
# Chart 1: Exact Search Latency by Scale (log scale)
# ========================================================================
def chart_exact_search_by_scale(data):
    exact = [d for d in data if d['name'].startswith('exact-search-') and 'p50_us' in d]
    if not exact:
        return

    metrics = {}
    for d in exact:
        metric = d['name'].replace('exact-search-', '')
        size = d['params'].split(',')[0].strip() if d['params'] else ''
        if metric not in metrics:
            metrics[metric] = {'sizes': [], 'p50': [], 'p95': [], 'p99': []}
        metrics[metric]['sizes'].append(size)
        metrics[metric]['p50'].append(d['p50_us'])
        metrics[metric]['p95'].append(d['p95_us'])
        metrics[metric]['p99'].append(d['p99_us'])

    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(next(iter(metrics.values()))['sizes']))
    width = 0.25

    colors = [SWORD_RED, SWORD_RED_LIGHT, SWORD_GRAY_DIM]
    for i, (metric, vals) in enumerate(sorted(metrics.items())):
        offset = (i - 1) * width
        bars = ax.bar(x + offset, vals['p50'], width, label=metric.replace('-', ' ').title(),
                      color=colors[i], edgecolor=SWORD_RED_DARK, linewidth=0.5)
        for bar, val in zip(bars, vals['p50']):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.15,
                    fmt_us(val), ha='center', va='bottom', fontsize=7, color=SWORD_GRAY)

    ax.set_ylabel('p50 Latency (µs, log scale)')
    ax.set_title('Exact Float32 Search Latency by Dataset Scale\n(128-dim, k=10, authenticated operator)',
                 fontweight='bold', pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(next(iter(metrics.values()))['sizes'])
    ax.set_yscale('log')
    ax.legend(loc='upper left', framealpha=0.3, facecolor=SWORD_BG, edgecolor=SWORD_GRAY_DIM)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, 'exact_search_by_scale.png'),
                dpi=150, bbox_inches='tight', facecolor=SWORD_BG)
    plt.close()
    print(f'  exact_search_by_scale.png')


def get_row_count(d):
    """Extract the row count from params like '10000x128, k=10'."""
    params = d.get('params', '')
    m = re.match(r'(\d+)x', params)
    return int(m.group(1)) if m else 0


# ========================================================================
# Chart 2: Search Method Comparison (10K×128)
# ========================================================================
def chart_method_comparison(data):
    labels = []
    p50s = []
    p95s = []
    colors = []

    target_rows = 10000

    # Exact float32
    for d in data:
        if d['name'] == 'exact-search-cosine' and get_row_count(d) == target_rows and 'p50_us' in d:
            labels.append('Exact\nCosine')
            p50s.append(d['p50_us'])
            p95s.append(d['p95_us'])
            colors.append(SWORD_RED)
            break
    for d in data:
        if d['name'] == 'exact-search-dotproduct' and get_row_count(d) == target_rows and 'p50_us' in d:
            labels.append('Exact\nDot')
            p50s.append(d['p50_us'])
            p95s.append(d['p95_us'])
            colors.append(SWORD_RED_LIGHT)
            break
    # Graph search
    for d in data:
        if d['name'] == 'graph-search' and get_row_count(d) == target_rows and 'p50_us' in d:
            labels.append('HNSW\nGraph')
            p50s.append(d['p50_us'])
            p95s.append(d['p95_us'])
            colors.append(SWORD_GREEN)
            break
    # INT8
    for d in data:
        if d['name'] == 'int8-search' and get_row_count(d) == target_rows and 'p50_us' in d:
            labels.append('INT8\nQuant')
            p50s.append(d['p50_us'])
            p95s.append(d['p95_us'])
            colors.append(SWORD_BLUE)
            break
    # Trinary
    for d in data:
        if d['name'] == 'trinary-scalar' and get_row_count(d) == target_rows and 'p50_us' in d:
            labels.append('Trinary\nScalar')
            p50s.append(d['p50_us'])
            p95s.append(d['p95_us'])
            colors.append(SWORD_ORANGE)
            break
    # Metadata filtered
    for d in data:
        if d['name'] == 'metadata-filtered' and get_row_count(d) == target_rows and 'p50_us' in d:
            labels.append('Metadata\nFiltered')
            p50s.append(d['p50_us'])
            p95s.append(d['p95_us'])
            colors.append(SWORD_GRAY_DIM)
            break

    if not labels:
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(labels))
    width = 0.35

    bars1 = ax.bar(x - width/2, p50s, width, label='p50', color=colors,
                   edgecolor=SWORD_RED_DARK, linewidth=0.5)
    bars2 = ax.bar(x + width/2, p95s, width, label='p95', color=colors,
                   edgecolor=SWORD_RED_DARK, linewidth=0.5, alpha=0.5)

    for bar, val in zip(bars1, p50s):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.05,
                fmt_us(val), ha='center', va='bottom', fontsize=7, color=SWORD_GRAY)

    ax.set_ylabel('Latency (µs, log scale)')
    ax.set_title('Search Method Comparison (10K×128, k=10)\nAuthenticated operator, real search paths',
                 fontweight='bold', pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_yscale('log')
    ax.legend(loc='upper right', framealpha=0.3, facecolor=SWORD_BG, edgecolor=SWORD_GRAY_DIM)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, 'method_comparison_10k.png'),
                dpi=150, bbox_inches='tight', facecolor=SWORD_BG)
    plt.close()
    print(f'  method_comparison_10k.png')


# ========================================================================
# Chart 3: Latency Percentiles (p50/p95/p99) for 100K×128
# ========================================================================
def chart_percentiles_100k(data):
    entries = []
    for d in data:
        params = d.get('params', '')
        if '100000' in params and 'p50_us' in d:
            label = d['name'].replace('exact-search-', 'Exact ').replace('graph-search', 'Graph').replace('int8-search', 'INT8').replace('trinary-scalar', 'Trinary').replace('metadata-filtered', 'Filtered').replace('unfiltered', 'Unfiltered').replace('exact-float32', 'Float32')
            entries.append((label, d['p50_us'], d['p95_us'], d['p99_us']))

    if not entries:
        return

    entries.sort(key=lambda e: e[1])
    labels = [e[0] for e in entries]
    p50s = [e[1] for e in entries]
    p95s = [e[2] for e in entries]
    p99s = [e[3] for e in entries]

    fig, ax = plt.subplots(figsize=(12, 7))
    y = np.arange(len(labels))
    height = 0.25

    ax.barh(y - height, p50s, height, label='p50', color=SWORD_RED, edgecolor=SWORD_RED_DARK, linewidth=0.5)
    ax.barh(y, p95s, height, label='p95', color=SWORD_RED_LIGHT, edgecolor=SWORD_RED_DARK, linewidth=0.5, alpha=0.8)
    ax.barh(y + height, p99s, height, label='p99', color=SWORD_GRAY_DIM, edgecolor=SWORD_RED_DARK, linewidth=0.5, alpha=0.6)

    for i, (p50, p95, p99) in enumerate(zip(p50s, p95s, p99s)):
        ax.text(p50 * 1.05, i - height, fmt_us(p50), va='center', fontsize=7, color=SWORD_GRAY)
        ax.text(p95 * 1.05, i, fmt_us(p95), va='center', fontsize=7, color=SWORD_GRAY)
        ax.text(p99 * 1.05, i + height, fmt_us(p99), va='center', fontsize=7, color=SWORD_GRAY)

    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.set_xlabel('Latency (µs, log scale)')
    ax.set_title('Latency Percentiles at 100K×128 Scale\n(128-dim, k=10, authenticated operator)',
                 fontweight='bold', pad=12)
    ax.set_xscale('log')
    ax.invert_yaxis()
    ax.legend(loc='lower right', framealpha=0.3, facecolor=SWORD_BG, edgecolor=SWORD_GRAY_DIM)
    ax.grid(axis='x', alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, 'percentiles_100k.png'),
                dpi=150, bbox_inches='tight', facecolor=SWORD_BG)
    plt.close()
    print(f'  percentiles_100k.png')


# ========================================================================
# Chart 4: Index Build Time Comparison
# ========================================================================
def chart_build_times(data):
    builds = [d for d in data if 'build_ms' in d]
    if not builds:
        return

    builds.sort(key=lambda d: d['build_ms'])
    labels = []
    times = []
    for d in builds:
        params = d.get('params', '')
        label = f"{d['name'].replace('graph-build', 'HNSW Graph').replace('int8-build', 'INT8 Quant')}\n({params})"
        labels.append(label)
        times.append(d['build_ms'])

    fig, ax = plt.subplots(figsize=(10, 6))
    colors_bar = [SWORD_RED if 'HNSW' in l else SWORD_BLUE if 'INT8' in l else SWORD_GRAY_DIM for l in labels]
    bars = ax.barh(labels, times, color=colors_bar, edgecolor=SWORD_RED_DARK, linewidth=0.5)

    for bar, val in zip(bars, times):
        ax.text(val * 1.02, bar.get_y() + bar.get_height()/2,
                fmt_ms(val), va='center', fontsize=8, color=SWORD_GRAY)

    ax.set_xlabel('Build Time (ms, log scale)')
    ax.set_title('Index Build Time by Method and Scale\n(128-dim vectors)',
                 fontweight='bold', pad=12)
    ax.set_xscale('log')
    ax.invert_yaxis()
    ax.grid(axis='x', alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, 'build_times.png'),
                dpi=150, bbox_inches='tight', facecolor=SWORD_BG)
    plt.close()
    print(f'  build_times.png')


# ========================================================================
# Chart 5: Metadata Filtering Speedup
# ========================================================================
def chart_metadata_filter(data):
    filtered = []
    unfiltered = []
    for d in data:
        if d['name'] == 'metadata-filtered' and 'p50_us' in d:
            filtered.append(d)
        elif d['name'] == 'unfiltered' and 'p50_us' in d:
            unfiltered.append(d)

    if not filtered or not unfiltered:
        return

    # Match by scale
    pairs = []
    for f in filtered:
        f_scale = get_row_count(f)
        for u in unfiltered:
            u_scale = get_row_count(u)
            if f_scale == u_scale and f_scale > 0:
                pairs.append((str(f_scale), f['p50_us'], u['p50_us']))
                break

    if not pairs:
        return

    labels = [p[0] for p in pairs]
    f_vals = [p[1] for p in pairs]
    u_vals = [p[2] for p in pairs]

    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(labels))
    width = 0.35

    bars1 = ax.bar(x - width/2, u_vals, width, label='Unfiltered', color=SWORD_RED,
                   edgecolor=SWORD_RED_DARK, linewidth=0.5)
    bars2 = ax.bar(x + width/2, f_vals, width, label='Filtered (10%/5%)', color=SWORD_GREEN,
                   edgecolor=SWORD_RED_DARK, linewidth=0.5)

    for bar, val in zip(bars1, u_vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.05,
                fmt_us(val), ha='center', va='bottom', fontsize=8, color=SWORD_GRAY)
    for bar, val in zip(bars2, f_vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.05,
                fmt_us(val), ha='center', va='bottom', fontsize=8, color=SWORD_GRAY)

    ax.set_ylabel('p50 Latency (µs, log scale)')
    ax.set_title('Metadata Filtering Impact\n(Early row skip vs full scan)',
                 fontweight='bold', pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels([f'{l}×128' for l in labels])
    ax.set_yscale('log')
    ax.legend(loc='upper left', framealpha=0.3, facecolor=SWORD_BG, edgecolor=SWORD_GRAY_DIM)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(CHARTS_DIR, 'metadata_filtering.png'),
                dpi=150, bbox_inches='tight', facecolor=SWORD_BG)
    plt.close()
    print(f'  metadata_filtering.png')


# ========================================================================
# Main
# ========================================================================
def main():
    bench_file = os.path.join(RESULTS_DIR, 'micro_bench_results.txt')
    if not os.path.exists(bench_file):
        print(f'Error: {bench_file} not found. Run bench-micro first.')
        return

    print('Parsing benchmark results...')
    data = parse_bench_file(bench_file)
    print(f'  Parsed {len(data)} data points')

    # Save structured JSON
    json_path = os.path.join(RESULTS_DIR, 'micro_bench_results.json')
    with open(json_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f'  Saved JSON: {json_path}')

    print('Generating charts:')
    chart_exact_search_by_scale(data)
    chart_method_comparison(data)
    chart_percentiles_100k(data)
    chart_build_times(data)
    chart_metadata_filter(data)

    print(f'\nAll charts saved to: {CHARTS_DIR}/')


if __name__ == '__main__':
    main()
