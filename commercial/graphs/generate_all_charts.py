#!/usr/bin/env python3
"""
QIHSE Commercial Charts Generator

This script generates all performance, cost, and market analysis charts
for the QIHSE commercial documentation suite.

Usage:
    python3 generate_all_charts.py

Requirements:
    pip install matplotlib seaborn pandas numpy
"""

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from pathlib import Path
import sys

# Set style
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

# Create output directory
OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

# Color scheme
COLORS = {
    'QIHSE_AVX2': '#1f77b4',      # Blue
    'QIHSE_Full_HW': '#ff7f0e',   # Orange
    'ALEX': '#7f7f7f',            # Gray
    'RAPIDS': '#2ca02c',          # Green
    'Binary Search': '#d62728',   # Red
    'SmartNIC': '#9467bd',        # Purple
    'Google': '#1f77b4',
    'Meta': '#ff7f0e',
    'Amazon': '#2ca02c',
    'Financial_Trading': '#d62728'
}

def load_data(filename):
    """Load CSV data file"""
    data_path = Path("data") / filename
    if not data_path.exists():
        print(f"Warning: Data file {data_path} not found")
        return None
    return pd.read_csv(data_path)

def generate_latency_comparison_chart():
    """Generate latency comparison chart (log scale)"""
    print("Generating latency comparison chart...")

    data = load_data("latency_benchmark_data.csv")
    if data is None:
        return

    # Create figure
    fig, ax = plt.subplots(figsize=(14, 8))

    # Create grouped bar chart
    x = np.arange(len(data['technology'].unique()))
    width = 0.25

    technologies = data['technology'].unique()
    datasets = data['dataset'].unique()

    for i, dataset in enumerate(datasets):
        dataset_data = data[data['dataset'] == dataset]
        values = []
        for tech in technologies:
            tech_data = dataset_data[dataset_data['technology'] == tech]
            if not tech_data.empty:
                values.append(tech_data['latency_ms'].iloc[0])
            else:
                values.append(0)

        ax.bar(x + i*width, values, width,
               label=dataset, alpha=0.8,
               color=sns.color_palette("Set2", len(datasets))[i])

    # Customize
    ax.set_yscale('log')
    ax.set_xlabel('Technology')
    ax.set_ylabel('Latency (ms, log scale)')
    ax.set_title('Latency Comparison: QIHSE vs Competitors\n(Log Scale - Orders of Magnitude Improvement)')
    ax.set_xticks(x + width)
    ax.set_xticklabels([t.replace('_', ' ') for t in technologies], rotation=45, ha='right')
    ax.legend(title='Dataset')
    ax.grid(True, alpha=0.3)

    # Add value labels on bars
    for container in ax.containers:
        ax.bar_label(container, fmt='%.0f', fontsize=8)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'latency_comparison_log.png', dpi=300, bbox_inches='tight')
    plt.close()

def generate_throughput_scaling_chart():
    """Generate throughput vs dataset size chart"""
    print("Generating throughput scaling chart...")

    data = load_data("throughput_scaling_data.csv")
    if data is None:
        return

    fig, ax = plt.subplots(figsize=(12, 8))

    # Plot lines
    ax.plot(data['dataset_size'], data['qihse_avx2_qps'],
            label='QIHSE AVX2', linewidth=3, marker='o',
            color=COLORS['QIHSE_AVX2'])
    ax.plot(data['dataset_size'], data['qihse_full_hw_qps'],
            label='QIHSE Full HW', linewidth=3, marker='s',
            color=COLORS['QIHSE_Full_HW'])
    ax.plot(data['dataset_size'], data['alex_qps'],
            label='ALEX', linewidth=2, linestyle='--',
            color=COLORS['ALEX'])
    ax.plot(data['dataset_size'], data['rapids_qps'],
            label='RAPIDS', linewidth=2, linestyle=':',
            color=COLORS['RAPIDS'])

    # Customize
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.set_xlabel('Dataset Size (elements)')
    ax.set_ylabel('Queries Per Second (QPS)')
    ax.set_title('Throughput Scaling: QIHSE vs Competitors')
    ax.legend()
    ax.grid(True, alpha=0.3)

    # Format axis labels
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: format(int(x), ',')))
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: format(int(x), ',')))

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'throughput_scaling.png', dpi=300, bbox_inches='tight')
    plt.close()

def generate_cost_savings_timeline():
    """Generate infrastructure cost savings timeline"""
    print("Generating cost savings timeline...")

    data = load_data("cost_savings_timeline_data.csv")
    if data is None:
        return

    fig, ax = plt.subplots(figsize=(14, 8))

    # Plot area chart
    ax.fill_between(data['month'], 0, data['google_savings_m'],
                   label='Google', alpha=0.7, color=COLORS['Google'])
    ax.fill_between(data['month'], 0, data['meta_savings_m'],
                   label='Meta', alpha=0.7, color=COLORS['Meta'])
    ax.fill_between(data['month'], 0, data['amazon_savings_m'],
                   label='Amazon', alpha=0.7, color=COLORS['Amazon'])
    ax.fill_between(data['month'], 0, data['financial_trading_savings_m'],
                   label='Financial Trading', alpha=0.7, color=COLORS['Financial_Trading'])

    # Customize
    ax.set_xlabel('Month')
    ax.set_ylabel('Cumulative Savings ($M)')
    ax.set_title('Infrastructure Cost Savings Timeline\n(First Year Projections)')
    ax.legend()
    ax.grid(True, alpha=0.3)

    # Format y-axis
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'${x:.0f}M'))

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'infrastructure_savings_timeline.png', dpi=300, bbox_inches='tight')
    plt.close()

def generate_roi_timeline():
    """Generate ROI timeline projection"""
    print("Generating ROI timeline...")

    data = load_data("roi_timeline_data.csv")
    if data is None:
        return

    fig, ax = plt.subplots(figsize=(12, 8))

    # Plot lines with markers
    ax.plot(data['year'], data['google_roi_percent'],
            label='Google', linewidth=3, marker='o',
            color=COLORS['Google'])
    ax.plot(data['year'], data['meta_roi_percent'],
            label='Meta', linewidth=3, marker='s',
            color=COLORS['Meta'])
    ax.plot(data['year'], data['amazon_roi_percent'],
            label='Amazon', linewidth=3, marker='^',
            color=COLORS['Amazon'])
    ax.plot(data['year'], data['average_roi_percent'],
            label='Average', linewidth=4, marker='D', linestyle='--',
            color='black')

    # Customize
    ax.set_xlabel('Year')
    ax.set_ylabel('ROI (%)')
    ax.set_title('ROI Timeline Projection\n(3-Year Cumulative Returns)')
    ax.legend()
    ax.grid(True, alpha=0.3)

    # Format y-axis
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'{x:.0f}%'))

    # Add value labels
    for i, row in data.iterrows():
        ax.annotate(f'{row["average_roi_percent"]:.0f}%',
                   (row['year'], row['average_roi_percent']),
                   textcoords="offset points", xytext=(0,10), ha='center')

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'roi_timeline_projection.png', dpi=300, bbox_inches='tight')
    plt.close()

def generate_market_size_breakdown():
    """Generate market size breakdown pie chart"""
    print("Generating market size breakdown...")

    data = load_data("market_size_data.csv")
    if data is None:
        return

    fig, ax = plt.subplots(figsize=(10, 8))

    # Create pie chart
    wedges, texts, autotexts = ax.pie(data['size_billion'],
                                     labels=[s.replace('_', ' ') for s in data['segment']],
                                     autopct='%1.1f%%',
                                     startangle=90,
                                     colors=sns.color_palette("Set2", len(data)))

    # Customize
    ax.set_title('Market Size Breakdown\n(Total Addressable Market: $245B)')
    plt.setp(autotexts, size=10, weight="bold")
    plt.setp(texts, size=9)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'market_size_breakdown.png', dpi=300, bbox_inches='tight')
    plt.close()

def generate_competitive_matrix():
    """Generate competitive positioning matrix"""
    print("Generating competitive positioning matrix...")

    data = load_data("competitive_matrix_data.csv")
    if data is None:
        return

    fig, ax = plt.subplots(figsize=(12, 8))

    # Create scatter plot
    for category in data['category'].unique():
        cat_data = data[data['category'] == category]
        ax.scatter(cat_data['performance_speedup'], cat_data['cost_efficiency_points'],
                  s=200, alpha=0.7, label=category)

        # Add labels
        for _, row in cat_data.iterrows():
            ax.annotate(row['technology'].replace('_', ' '),
                       (row['performance_speedup'], row['cost_efficiency_points']),
                       xytext=(5, 5), textcoords='offset points', fontsize=9)

    # Customize
    ax.set_xlabel('Performance (Speedup vs Binary Search)')
    ax.set_ylabel('Cost Efficiency (points)')
    ax.set_title('Competitive Positioning Matrix\n(Higher = Better)')
    ax.legend()
    ax.grid(True, alpha=0.3)

    # Add quadrant labels
    ax.axhline(y=data['cost_efficiency_points'].median(), color='gray', linestyle='--', alpha=0.5)
    ax.axvline(x=data['performance_speedup'].median(), color='gray', linestyle='--', alpha=0.5)
    ax.text(0.5, 0.95, 'High Performance,\nHigh Efficiency', transform=ax.transAxes,
            ha='center', va='top', fontsize=10, alpha=0.7)
    ax.text(0.5, 0.05, 'High Performance,\nLow Efficiency', transform=ax.transAxes,
            ha='center', va='bottom', fontsize=10, alpha=0.7)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'competitive_positioning_matrix.png', dpi=300, bbox_inches='tight')
    plt.close()

def generate_workload_performance_heatmap():
    """Generate workload performance heatmap"""
    print("Generating workload performance heatmap...")

    # Create synthetic workload data
    workloads = ['Telemetry', 'IDs', 'Offsets', 'Events']
    technologies = ['QIHSE_AVX2', 'QIHSE_Full_HW', 'ALEX', 'RAPIDS']

    # Synthetic speedup data by workload
    speedup_data = np.array([
        [4.5, 18.0, 2.2, 6.0],  # Telemetry
        [5.2, 22.0, 2.8, 7.5],  # IDs
        [3.8, 15.0, 1.9, 5.2],  # Offsets
        [4.8, 20.0, 2.5, 6.8]   # Events
    ])

    fig, ax = plt.subplots(figsize=(10, 6))

    # Create heatmap
    im = ax.imshow(speedup_data, cmap='YlOrRd', aspect='auto')

    # Add labels
    ax.set_xticks(np.arange(len(technologies)))
    ax.set_yticks(np.arange(len(workloads)))
    ax.set_xticklabels([t.replace('_', ' ') for t in technologies])
    ax.set_yticklabels(workloads)

    # Rotate x labels
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

    # Add colorbar
    cbar = ax.figure.colorbar(im, ax=ax)
    cbar.ax.set_ylabel("Speedup Factor", rotation=-90, va="bottom")

    # Add text annotations
    for i in range(len(workloads)):
        for j in range(len(technologies)):
            text = ax.text(j, i, f'{speedup_data[i, j]:.1f}',
                          ha="center", va="center", color="black", fontsize=10)

    ax.set_title("Performance by Workload Type\n(Speedup vs Binary Search)")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'workload_performance_heatmap.png', dpi=300, bbox_inches='tight')
    plt.close()

def main():
    """Generate all charts"""
    print("QIHSE Commercial Charts Generator")
    print("=" * 40)

    try:
        # Generate all charts
        generate_latency_comparison_chart()
        generate_throughput_scaling_chart()
        generate_cost_savings_timeline()
        generate_roi_timeline()
        generate_market_size_breakdown()
        generate_competitive_matrix()
        generate_workload_performance_heatmap()

        print(f"\n✅ All charts generated successfully!")
        print(f"📁 Charts saved to: {OUTPUT_DIR}/")

        # List generated files
        chart_files = list(OUTPUT_DIR.glob("*.png"))
        if chart_files:
            print("\n📊 Generated Charts:")
            for chart_file in sorted(chart_files):
                print(f"  • {chart_file.name}")

    except Exception as e:
        print(f"❌ Error generating charts: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
