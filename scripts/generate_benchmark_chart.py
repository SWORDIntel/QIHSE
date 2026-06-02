#!/usr/bin/env python3
"""Generate QIHSE benchmark comparison chart from micro-bench results."""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import os
import sys

def parse_bench_file(path):
    """Parse benchmark output file for key metrics."""
    results = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if 'exact-search-cosine' in line and '1000x128' in line:
                results['exact_1k'] = float(line.split('mean=')[1].split()[0])
            elif 'exact-search-cosine' in line and '10000x128' in line:
                results['exact_10k'] = float(line.split('mean=')[1].split()[0])
            elif 'exact-search-cosine' in line and '100000x128' in line:
                results['exact_100k'] = float(line.split('mean=')[1].split()[0])
            elif 'int8-search' in line and '1000x128' in line:
                results['int8_1k'] = float(line.split('mean=')[1].split()[0])
            elif 'int8-search' in line and '10000x128' in line:
                results['int8_10k'] = float(line.split('mean=')[1].split()[0])
            elif 'int8-search' in line and '100000x128' in line:
                results['int8_100k'] = float(line.split('mean=')[1].split()[0])
            elif 'graph-search' in line and '1000x128' in line:
                results['graph_1k'] = float(line.split('mean=')[1].split()[0])
            elif 'graph-search' in line and '10000x128' in line:
                results['graph_10k'] = float(line.split('mean=')[1].split()[0])
            elif 'batch-search' in line and '10000x128' in line:
                results['batch_10k'] = float(line.split('mean=')[1].split()[0])
            elif 'serial-search' in line and '10000x128' in line:
                results['serial_10k'] = float(line.split('mean=')[1].split()[0])
    return results

def main():
    bench_file = sys.argv[1] if len(sys.argv) > 1 else '/tmp/bench_results.txt'
    out_file = sys.argv[2] if len(sys.argv) > 2 else 'benchmarks/qihse_benchmark_chart.png'

    if not os.path.exists(bench_file):
        print(f"Benchmark file not found: {bench_file}")
        sys.exit(1)

    r = parse_bench_file(bench_file)

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('QIHSE Benchmark Results (Haswell AVX2)', fontsize=16, fontweight='bold')

    # --- Panel 1: Search latency by dataset size ---
    ax = axes[0, 0]
    sizes = ['1K', '10K', '100K']
    x = np.arange(len(sizes))
    width = 0.25

    exact_vals = [r.get('exact_1k', 0)/1000, r.get('exact_10k', 0)/1000, r.get('exact_100k', 0)/1000]
    int8_vals = [r.get('int8_1k', 0)/1000, r.get('int8_10k', 0)/1000, r.get('int8_100k', 0)/1000]
    graph_vals = [r.get('graph_1k', 0)/1000, r.get('graph_10k', 0)/1000, 0]

    bars1 = ax.bar(x - width, exact_vals, width, label='Exact float32', color='#3498db')
    bars2 = ax.bar(x, int8_vals, width, label='INT8 quantized', color='#e74c3c')
    bars3 = ax.bar(x + width, graph_vals, width, label='Graph index', color='#2ecc71')

    ax.set_ylabel('Latency (ms)')
    ax.set_title('Search Latency by Dataset Size (k=10, 128 dims)')
    ax.set_xticks(x)
    ax.set_xticklabels(sizes)
    ax.legend()
    ax.set_yscale('log')
    ax.grid(axis='y', alpha=0.3)

    # Add value labels
    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.annotate(f'{height:.2f}',
                            xy=(bar.get_x() + bar.get_width() / 2, height),
                            xytext=(0, 3), textcoords="offset points",
                            ha='center', va='bottom', fontsize=7)

    # --- Panel 2: Speedup comparison ---
    ax = axes[0, 1]
    categories = ['INT8 vs\nExact (10K)', 'Graph vs\nExact (10K)', 'Graph vs\nExact (1K)']
    speedups = [
        r.get('exact_10k', 1) / r.get('int8_10k', 1) if r.get('int8_10k') else 0,
        r.get('exact_10k', 1) / r.get('graph_10k', 1) if r.get('graph_10k') else 0,
        r.get('exact_1k', 1) / r.get('graph_1k', 1) if r.get('graph_1k') else 0,
    ]
    colors = ['#e74c3c', '#2ecc71', '#2ecc71']
    bars = ax.bar(categories, speedups, color=colors, edgecolor='black')
    ax.set_ylabel('Speedup Factor (x)')
    ax.set_title('Relative Speedup vs Exact float32')
    ax.axhline(y=1, color='gray', linestyle='--', alpha=0.5)
    ax.grid(axis='y', alpha=0.3)
    for bar, val in zip(bars, speedups):
        ax.annotate(f'{val:.1f}x',
                    xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontweight='bold')

    # --- Panel 3: Batch vs Serial (10K vectors) ---
    ax = axes[1, 0]
    batch_mean = r.get('batch_10k', 0) / 1000
    serial_mean = r.get('serial_10k', 0) / 1000
    labels = ['Serial (32 queries)', 'Batch (32 queries)']
    values = [serial_mean, batch_mean]
    colors = ['#95a5a6', '#9b59b6']
    bars = ax.bar(labels, values, color=colors, edgecolor='black')
    ax.set_ylabel('Total Time (ms)')
    ax.set_title('Batch vs Serial Search (10K vectors, 32 queries)')
    ax.grid(axis='y', alpha=0.3)
    for bar, val in zip(bars, values):
        ax.annotate(f'{val:.1f} ms',
                    xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontweight='bold')
    if serial_mean > batch_mean:
        improvement = (serial_mean - batch_mean) / serial_mean * 100
        ax.text(0.5, 0.95, f'Batch improvement: {improvement:.1f}%',
                transform=ax.transAxes, ha='center', va='top',
                bbox=dict(boxstyle='round', facecolor='lightgreen', alpha=0.8))

    # --- Panel 4: Feature summary table ---
    ax = axes[1, 1]
    ax.axis('off')
    features = [
        ['Feature', 'Status'],
        ['AVX2 Distance Functions', 'Enabled (-march=haswell)'],
        ['Graph Index (HNSW-style)', 'Persistent (index.qgraph)'],
        ['INT8 Quantization', 'Persistent (vectors.qint8)'],
        ['Binary Quantization', 'In-memory (vectors.qbinary)'],
        ['Sparse Vectors (BM25)', 'In-memory inverted index'],
        ['Query Result Cache', 'LRU + FNV-1a keyed'],
        ['Parallel Graph Build', 'Pthread (disabled by default)'],
        ['Memory Prefetching', '_mm_prefetch in hot paths'],
        ['Config File', '.qihse.conf + env overrides'],
        ['Python Bindings', 'ctypes wrapper'],
        ['CLI Tool', 'qihse-db script'],
    ]
    table = ax.table(cellText=features, loc='center', cellLoc='left')
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 1.5)
    for i in range(len(features[0])):
        table[(0, i)].set_facecolor('#34495e')
        table[(0, i)].set_text_props(weight='bold', color='white')
    for i in range(1, len(features)):
        for j in range(len(features[0])):
            color = '#ecf0f1' if i % 2 == 0 else '#bdc3c7'
            table[(i, j)].set_facecolor(color)
    ax.set_title('Implemented Features', fontweight='bold', pad=20)

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    plt.savefig(out_file, dpi=150, bbox_inches='tight')
    print(f"Chart saved to {out_file}")

if __name__ == '__main__':
    main()
