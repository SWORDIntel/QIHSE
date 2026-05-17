#!/usr/bin/env python3
"""
NOT_STISLA Benchmark Visualization Script

Generates comprehensive charts and graphs from tuned/enhanced NOT_STISLA benchmark results.
Supports multiple output formats and interactive visualizations.
"""

import json
import csv
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np
import pandas as pd
from pathlib import Path
import argparse
import sys
from datetime import datetime

class NotStislaBenchmarkVisualizer:
    def __init__(self, results_file):
        """Initialize visualizer with benchmark results"""
        self.results_file = Path(results_file)
        self.data = None
        self.df = None

        # Load and process data
        self._load_data()

        # Set up matplotlib style
        plt.style.use('default')
        plt.rcParams['figure.figsize'] = (14, 10)
        plt.rcParams['font.size'] = 10
        plt.rcParams['axes.labelsize'] = 12
        plt.rcParams['axes.titlesize'] = 14
        plt.rcParams['xtick.labelsize'] = 10
        plt.rcParams['ytick.labelsize'] = 10

    def _load_data(self):
        """Load benchmark data from JSON or CSV file"""
        if self.results_file.suffix.lower() == '.json':
            with open(self.results_file, 'r') as f:
                self.data = json.load(f)
            self.df = pd.json_normalize(self.data['benchmarks'])
        elif self.results_file.suffix.lower() == '.csv':
            self.df = pd.read_csv(self.results_file)
            # Convert to similar structure as JSON
            self.data = {
                'not_stisla_version': 'Unknown',
                'timestamp': datetime.now().timestamp(),
                'benchmarks': self.df.to_dict('records')
            }
        else:
            raise ValueError("Unsupported file format. Use .json or .csv")

        print(f"Loaded {len(self.df)} benchmark results")

    def generate_speedup_comparison(self, output_file=None):
        """Generate speedup comparison chart"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))

        # Filter out failed benchmarks
        df = self.df[self.df['array_size'] > 0].copy()

        # Create size categories
        df['size_category'] = pd.cut(df['array_size'],
                                   bins=[0, 1000, 10000, 100000, 1000000, float('inf')],
                                   labels=['Tiny', 'Small', 'Medium', 'Large', 'Huge'])

        # Speedup vs baseline binary search
        sizes = []
        enhanced_speedups = []
        core_speedups = []

        for _, row in df.iterrows():
            if row['enhanced_vs_binary'] > 0:
                sizes.append(row['array_size'])
                enhanced_speedups.append(row['enhanced_vs_binary'])
                core_speedups.append(row['classical_vs_binary'])

        ax1.scatter(sizes, enhanced_speedups, alpha=0.7, s=50, label='Tuned/Enhanced NOT_STISLA Search', color='#1f77b4')
        ax1.scatter(sizes, core_speedups, alpha=0.7, s=50, label='NOT_STISLA Core Search', color='#ff7f0e')
        ax1.set_xscale('log')
        ax1.set_xlabel('Array Size (log scale)')
        ax1.set_ylabel('Speedup Factor')
        ax1.set_title('Speedup vs Baseline Binary Search by Array Size')
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        # Accuracy comparison
        if 'accuracy_rate' in df.columns:
            accuracies = df['accuracy_rate'] * 100
            sizes_acc = df['array_size']

            scatter = ax2.scatter(sizes_acc, accuracies, c=df['data_entropy'],
                                cmap='viridis', alpha=0.7, s=50)
            ax2.set_xscale('log')
            ax2.set_xlabel('Array Size (log scale)')
            ax2.set_ylabel('Accuracy (%)')
            ax2.set_title('Accuracy by Array Size and Data Entropy')
            plt.colorbar(scatter, ax=ax2, label='Data Entropy')
            ax2.grid(True, alpha=0.3)

        # Timing comparison
        if len(df) > 0:
            df_sorted = df.sort_values('array_size')
            ax3.plot(df_sorted['array_size'], df_sorted['enhanced_time_ns'],
                    'o-', label='Tuned/Enhanced NOT_STISLA Search', color='#1f77b4', linewidth=2)
            ax3.plot(df_sorted['array_size'], df_sorted['classical_time_ns'],
                    's-', label='NOT_STISLA Core Search', color='#ff7f0e', linewidth=2)
            ax3.plot(df_sorted['array_size'], df_sorted['binary_time_ns'],
                    '^-', label='Baseline Binary Search', color='#2ca02c', linewidth=2)
            ax3.set_xscale('log')
            ax3.set_yscale('log')
            ax3.set_xlabel('Array Size (log scale)')
            ax3.set_ylabel('Time per Operation (ns, log scale)')
            ax3.set_title('Timing Comparison')
            ax3.legend()
            ax3.grid(True, alpha=0.3)

        # Hardware utilization (if available)
        if 'primary_accelerator' in df.columns:
            hardware_counts = df['primary_accelerator'].value_counts()
            hardware_counts.plot(kind='bar', ax=ax4, color='#17becf', alpha=0.7)
            ax4.set_xlabel('Hardware Accelerator')
            ax4.set_ylabel('Benchmark Count')
            ax4.set_title('Hardware Utilization Distribution')
            ax4.tick_params(axis='x', rotation=45)
            ax4.grid(True, alpha=0.3)

        plt.tight_layout()

        if output_file:
            plt.savefig(output_file, dpi=150, bbox_inches='tight')
            print(f"Speedup comparison chart saved to: {output_file}")
        else:
            plt.show()

        plt.close()

    def generate_detailed_report(self, output_file=None):
        """Generate detailed performance report"""
        fig = plt.figure(figsize=(16, 12))
        gs = gridspec.GridSpec(3, 3, figure=fig)

        # Filter valid results
        df = self.df[self.df['array_size'] > 0].copy()

        # 1. Performance overview
        ax1 = fig.add_subplot(gs[0, :2])
        if len(df) > 0:
            x = np.arange(len(df))
            width = 0.25

            ax1.bar(x - width, df['enhanced_vs_binary'], width, label='Tuned/enhanced vs baseline',
                   alpha=0.8, color='#1f77b4')
            ax1.bar(x, df['enhanced_vs_classical'], width, label='Tuned/enhanced vs core',
                   alpha=0.8, color='#ff7f0e')
            ax1.bar(x + width, df['classical_vs_binary'], width, label='Core vs baseline',
                   alpha=0.8, color='#2ca02c')

            ax1.set_xlabel('Benchmark')
            ax1.set_ylabel('Speedup Factor')
            ax1.set_title('Performance Overview - All Benchmarks')
            ax1.set_xticks(x)
            ax1.set_xticklabels(df['benchmark_name'], rotation=45, ha='right')
            ax1.legend()
            ax1.grid(True, alpha=0.3)

        # 2. Accuracy distribution
        ax2 = fig.add_subplot(gs[0, 2])
        if 'accuracy_rate' in df.columns:
            accuracies = df['accuracy_rate'] * 100
            ax2.hist(accuracies, bins=10, alpha=0.7, color='#17becf', edgecolor='black')
            ax2.axvline(accuracies.mean(), color='red', linestyle='--', linewidth=2,
                       label=f'Mean: {accuracies.mean():.1f}%')
            ax2.set_xlabel('Accuracy (%)')
            ax2.set_ylabel('Frequency')
            ax2.set_title('Accuracy Distribution')
            ax2.legend()
            ax2.grid(True, alpha=0.3)

        # 3. Scaling analysis
        ax3 = fig.add_subplot(gs[1, :2])
        if len(df) > 1:
            df_sorted = df.sort_values('array_size')

            # Fit power law for scaling analysis
            x = np.log(df_sorted['array_size'])
            y_enhanced = np.log(df_sorted['enhanced_time_ns'])
            y_core = np.log(df_sorted['classical_time_ns'])
            y_binary = np.log(df_sorted['binary_time_ns'])

            # Linear fits
            enhanced_fit = np.polyfit(x, y_enhanced, 1)
            core_fit = np.polyfit(x, y_core, 1)
            binary_fit = np.polyfit(x, y_binary, 1)

            ax3.plot(df_sorted['array_size'], df_sorted['enhanced_time_ns'], 'o',
                    label=f'Tuned/Enhanced NOT_STISLA Search (slope: {enhanced_fit[0]:.2f})', color='#1f77b4')
            ax3.plot(df_sorted['array_size'], df_sorted['classical_time_ns'], 's',
                    label=f'NOT_STISLA Core Search (slope: {core_fit[0]:.2f})', color='#ff7f0e')
            ax3.plot(df_sorted['array_size'], df_sorted['binary_time_ns'], '^',
                    label=f'Baseline Binary Search (slope: {binary_fit[0]:.2f})', color='#2ca02c')

            ax3.set_xscale('log')
            ax3.set_yscale('log')
            ax3.set_xlabel('Array Size (log scale)')
            ax3.set_ylabel('Time per Operation (ns, log scale)')
            ax3.set_title('Scaling Analysis - Time Complexity')
            ax3.legend()
            ax3.grid(True, alpha=0.3)

        # 4. Hardware efficiency
        ax4 = fig.add_subplot(gs[1, 2])
        if 'primary_accelerator' in df.columns and 'memory_usage_mb' in df.columns:
            hardware_groups = df.groupby('primary_accelerator')['memory_usage_mb'].mean()
            hardware_groups.plot(kind='bar', ax=ax4, color='#9c27b0', alpha=0.7)
            ax4.set_xlabel('Hardware Accelerator')
            ax4.set_ylabel('Avg Memory Usage (MB)')
            ax4.set_title('Memory Usage by Hardware')
            ax4.tick_params(axis='x', rotation=45)
            ax4.grid(True, alpha=0.3)

        # 5. Error analysis
        ax5 = fig.add_subplot(gs[2, :])
        if all(col in df.columns for col in ['false_positives', 'false_negatives', 'verification_fallbacks']):
            error_data = df[['false_positives', 'false_negatives', 'verification_fallbacks']].sum()

            if error_data.sum() > 0:
                wedges, texts, autotexts = ax5.pie(error_data, labels=error_data.index,
                                                  autopct='%1.1f%%', startangle=90)
                ax5.set_title('Error Distribution Across All Benchmarks')
                ax5.axis('equal')

                # Improve text readability
                for text in texts:
                    text.set_fontsize(8)
                for autotext in autotexts:
                    autotext.set_fontsize(8)
            else:
                ax5.text(0.5, 0.5, 'No Errors Detected\n100% Accuracy',
                        ha='center', va='center', transform=ax5.transAxes,
                        fontsize=14, color='green')
                ax5.set_title('Error Analysis')
                ax5.set_xlim(0, 1)
                ax5.set_ylim(0, 1)
                ax5.axis('off')

        # Add metadata
        if self.data:
            fig.suptitle(f'NOT_STISLA Benchmark Results - {self.data.get("not_stisla_version", "Unknown Version")}\n'
                        f'Generated: {datetime.fromtimestamp(self.data.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")}\n'
                        f'Total Benchmarks: {len(df)}', fontsize=12, y=0.98)

        plt.tight_layout()

        if output_file:
            plt.savefig(output_file, dpi=150, bbox_inches='tight')
            print(f"Detailed report saved to: {output_file}")
        else:
            plt.show()

        plt.close()

    def generate_summary_stats(self):
        """Generate summary statistics"""
        df = self.df[self.df['array_size'] > 0]

        if len(df) == 0:
            print("No valid benchmark results found")
            return

        print("\n" + "="*80)
        print("NOT_STISLA BENCHMARK SUMMARY STATISTICS")
        print("="*80)

        print(f"Total benchmarks run: {len(df)}")
        print(f"NOT_STISLA version: {self.data.get('not_stisla_version', 'Unknown')}")
        print(f"Timestamp: {datetime.fromtimestamp(self.data.get('timestamp', 0))}")

        # Performance statistics
        print(f"\nPERFORMANCE STATISTICS:")
        print(f"Average tuned/enhanced NOT_STISLA speedup vs baseline: {df['enhanced_vs_binary'].mean():.1f}x")
        print(f"Average tuned/enhanced NOT_STISLA speedup vs core search: {df['enhanced_vs_classical'].mean():.1f}x")
        print(f"Average accuracy: {df['accuracy_rate'].mean()*100:.2f}%")

        # Timing statistics
        print(f"\nTIMING STATISTICS (nanoseconds per operation):")
        print(f"Tuned/enhanced NOT_STISLA average: {df['enhanced_time_ns'].mean():.0f} ns")
        print(f"NOT_STISLA core search average: {df['classical_time_ns'].mean():.0f} ns")
        print(f"Baseline binary search average: {df['binary_time_ns'].mean():.0f} ns")

        # Hardware statistics
        if 'primary_accelerator' in df.columns:
            hardware_counts = df['primary_accelerator'].value_counts()
            print(f"\nHARDWARE UTILIZATION:")
            for hw, count in hardware_counts.items():
                percentage = (count / len(df)) * 100
                print(f"  {hw}: {count} benchmarks ({percentage:.1f}%)")

        # Error statistics
        if all(col in df.columns for col in ['false_positives', 'false_negatives']):
            total_fp = df['false_positives'].sum()
            total_fn = df['false_negatives'].sum()
            total_queries = df['queries_tested'].sum()

            print(f"\nERROR STATISTICS:")
            if total_queries > 0:
                print(f"False positives: {total_fp} ({total_fp/total_queries*100:.3f}%)")
                print(f"False negatives: {total_fn} ({total_fn/total_queries*100:.3f}%)")
                print(f"Total accuracy: {(total_queries - total_fp - total_fn)/total_queries*100:.3f}%")

        print("="*80)

def main():
    parser = argparse.ArgumentParser(description='NOT_STISLA Benchmark Visualization')
    parser.add_argument('input_file', help='Benchmark results file (.json or .csv)')
    parser.add_argument('--output-dir', default='charts', help='Output directory for charts')
    parser.add_argument('--format', choices=['png', 'pdf', 'svg'], default='png',
                       help='Output format for charts')
    parser.add_argument('--no-display', action='store_true',
                       help='Do not display plots interactively')

    args = parser.parse_args()

    # Setup matplotlib backend for non-interactive mode
    if args.no_display:
        import matplotlib
        matplotlib.use('Agg')

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    try:
        # Initialize visualizer
        viz = NotStislaBenchmarkVisualizer(args.input_file)

        # Generate summary statistics
        viz.generate_summary_stats()

        # Generate speedup comparison chart
        speedup_file = output_dir / f'not_stisla_speedup_comparison.{args.format}'
        viz.generate_speedup_comparison(str(speedup_file))

        # Generate detailed report
        report_file = output_dir / f'not_stisla_detailed_report.{args.format}'
        viz.generate_detailed_report(str(report_file))

        print(f"\nCharts saved to: {output_dir}/")
        print("Generated files:")
        print(f"  - {speedup_file.name}")
        print(f"  - {report_file.name}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
