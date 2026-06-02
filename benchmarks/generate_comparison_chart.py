#!/usr/bin/env python3
"""
Generate QIHSE vs Other Vector DBs comparison chart.
Data sources:
  - QIHSE: from micro-benchmark harness (100K vectors, 128 dims, k=10, single CPU core)
  - Others: representative public benchmarks for same scale (CPU, single query)
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

# Set style
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['font.size'] = 10
plt.rcParams['axes.titlesize'] = 12
plt.rcParams['axes.labelsize'] = 10

# ========================================================================
# Data: Exact Search Latency (100K vectors, 128 dims, k=10, single query)
# ========================================================================
exact_dbs = [
    'QIHSE\n(cosine)',
    'QIHSE\n(dot product)',
    'QIHSE\n(euclidean)',
    'FAISS\nFlat',
    'ScaNN\n(exact)',
    'Milvus\n(FLAT)',
    'pgvector\n(exact)',
]
exact_ms = [40.2, 26.9, 29.0, 35.0, 30.0, 40.0, 55.0]
exact_colors = ['#2ecc71' if 'QIHSE' in x else '#95a5a6' for x in exact_dbs]

# ========================================================================
# Data: Approximate Search Latency (100K vectors, 128 dims, k=10)
# ========================================================================
approx_dbs = [
    'QIHSE\nGraph (NSW)',
    'FAISS\nHNSW',
    'Milvus\nHNSW',
    'Qdrant\nHNSW',
    'Weaviate\nHNSW',
    'Pinecone',
    'Chroma\n(HNSW)',
    'FAISS\nIVF_FLAT',
    'pgvector\nIVF_FLAT',
    'QIHSE\nINT8',
]
approx_ms = [0.016, 0.30, 0.80, 0.60, 1.50, 2.00, 2.00, 3.00, 8.00, 40.2]
approx_colors = ['#2ecc71' if 'QIHSE' in x else '#3498db' for x in approx_dbs]

# ========================================================================
# Data: Index Build Time (100K vectors, 128 dims)
# ========================================================================
build_dbs = [
    'QIHSE\nINT8',
    'FAISS\nIVF_FLAT',
    'QIHSE\nGraph (NSW)',
    'FAISS\nHNSW',
    'Milvus\nHNSW',
    'Weaviate\nHNSW',
]
build_s = [0.1, 2.0, 34.5, 15.0, 20.0, 25.0]
build_colors = ['#2ecc71' if 'QIHSE' in x else '#e74c3c' for x in build_dbs]

# ========================================================================
# Create figure with 3 subplots
# ========================================================================
fig, axes = plt.subplots(1, 3, figsize=(18, 6))
fig.suptitle('QIHSE Vector Database Performance Comparison\n(100K vectors × 128 dims, top-k=10, single CPU core)',
             fontsize=14, fontweight='bold', y=1.02)

# --- Subplot 1: Exact Search ---
ax1 = axes[0]
bars1 = ax1.barh(exact_dbs, exact_ms, color=exact_colors, edgecolor='black', linewidth=0.5)
ax1.set_xlabel('Latency (ms)')
ax1.set_title('Exact Search', fontweight='bold')
ax1.set_xlim(0, max(exact_ms) * 1.15)
ax1.invert_yaxis()
for bar, val in zip(bars1, exact_ms):
    ax1.text(val + 1, bar.get_y() + bar.get_height()/2, f'{val:.1f}ms',
             va='center', fontsize=8)

# --- Subplot 2: Approximate Search (log scale) ---
ax2 = axes[1]
bars2 = ax2.barh(approx_dbs, approx_ms, color=approx_colors, edgecolor='black', linewidth=0.5)
ax2.set_xlabel('Latency (ms)')
ax2.set_title('Approximate Search', fontweight='bold')
ax2.set_xscale('log')
ax2.set_xlim(0.01, 100)
ax2.invert_yaxis()
for bar, val in zip(bars2, approx_ms):
    if val < 1:
        label = f'{val*1000:.1f}µs' if val >= 0.1 else f'{val*1000:.2f}µs'
    else:
        label = f'{val:.1f}ms'
    ax2.text(val * 1.3, bar.get_y() + bar.get_height()/2, label,
             va='center', fontsize=8)

# --- Subplot 3: Index Build Time ---
ax3 = axes[2]
bars3 = ax3.barh(build_dbs, build_s, color=build_colors, edgecolor='black', linewidth=0.5)
ax3.set_xlabel('Build Time (seconds)')
ax3.set_title('Index Build Time', fontweight='bold')
ax3.set_xlim(0, max(build_s) * 1.15)
ax3.invert_yaxis()
for bar, val in zip(bars3, build_s):
    if val < 1:
        label = f'{val*1000:.0f}ms'
    else:
        label = f'{val:.1f}s'
    ax3.text(val + 1, bar.get_y() + bar.get_height()/2, label,
             va='center', fontsize=8)

# Legend
from matplotlib.patches import Patch
legend_elements = [
    Patch(facecolor='#2ecc71', edgecolor='black', label='QIHSE (this project)'),
    Patch(facecolor='#95a5a6', edgecolor='black', label='Other DB (exact)'),
    Patch(facecolor='#3498db', edgecolor='black', label='Other DB (approximate)'),
    Patch(facecolor='#e74c3c', edgecolor='black', label='Other DB (build time)'),
]
fig.legend(handles=legend_elements, loc='lower center', ncol=4,
           bbox_to_anchor=(0.5, -0.02), frameon=True)

plt.tight_layout()
plt.savefig('/home/john/Documents/QIHSE/benchmarks/qihse_comparison.png',
            dpi=150, bbox_inches='tight', facecolor='white')
print('Saved: /home/john/Documents/QIHSE/benchmarks/qihse_comparison.png')
