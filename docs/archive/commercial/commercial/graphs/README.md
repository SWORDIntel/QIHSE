# QIHSE Commercial Visual Assets

This directory contains specifications and data for generating professional graphs and charts used in QIHSE commercial documentation.

## Graph Generation Instructions

### Prerequisites
```bash
pip install matplotlib seaborn pandas numpy
```

### Generating Charts
```bash
# Generate all performance charts
python3 generate_performance_charts.py

# Generate all cost analysis charts
python3 generate_cost_charts.py

# Generate all market analysis charts
python3 generate_market_charts.py

# Generate all charts
python3 generate_all_charts.py
```

## Chart Specifications

### 1. Performance Comparison Charts

#### 1.1 Latency Comparison (Log Scale)
- **File**: `latency_comparison_log.png`
- **Type**: Bar chart with log scale
- **Data**: `data/latency_benchmark_data.csv`
- **X-axis**: Technology (Binary Search, ALEX, RAPIDS, QIHSE AVX2, QIHSE Full HW)
- **Y-axis**: Latency (ms, log scale)
- **Datasets**: SIFT1M, GIST1M, MS MARCO

#### 1.2 Throughput vs Dataset Size
- **File**: `throughput_scaling.png`
- **Type**: Line chart
- **Data**: `data/throughput_scaling_data.csv`
- **X-axis**: Dataset size (log scale)
- **Y-axis**: QPS (Queries Per Second)
- **Lines**: QIHSE AVX2, QIHSE Full HW, Competitors

#### 1.3 Speedup Breakdown by Component
- **File**: `speedup_breakdown.png`
- **Type**: Stacked bar chart
- **Data**: `data/speedup_components_data.csv`
- **Components**: SIMD, Algorithm, Memory, Hardware

#### 1.4 Performance by Workload Type
- **File**: `workload_performance_heatmap.png`
- **Type**: Heatmap
- **Data**: `data/workload_performance_data.csv`
- **X-axis**: Workload Type (Telemetry, IDs, Offsets, Events)
- **Y-axis**: Technology
- **Color**: Speedup factor

### 2. Cost Analysis Charts

#### 2.1 Infrastructure Cost Savings Over Time
- **File**: `infrastructure_savings_timeline.png`
- **Type**: Area chart
- **Data**: `data/cost_savings_timeline_data.csv`
- **X-axis**: Time (months)
- **Y-axis**: Cumulative savings ($M)
- **Areas**: Google, Meta, Amazon, Financial Trading

#### 2.2 Cost Per Query Comparison
- **File**: `cost_per_query_comparison.png`
- **Type**: Bar chart
- **Data**: `data/cost_per_query_data.csv`
- **X-axis**: Technology/Configuration
- **Y-axis**: Cost per query ($)
- **Bars**: Current, QIHSE AVX2, QIHSE Full HW

#### 2.3 ROI Timeline Projection
- **File**: `roi_timeline_projection.png`
- **Type**: Line chart with markers
- **Data**: `data/roi_timeline_data.csv`
- **X-axis**: Time (years)
- **Y-axis**: ROI percentage
- **Lines**: Google, Meta, Amazon, Average

#### 2.4 TCO Comparison (3-Year View)
- **File**: `tco_comparison_3year.png`
- **Type**: Stacked bar chart
- **Data**: `data/tco_comparison_data.csv`
- **X-axis**: Company
- **Y-axis**: Total cost ($M)
- **Stacks**: Traditional vs QIHSE (3-year TCO)

### 3. Market Analysis Charts

#### 3.1 Market Size Breakdown
- **File**: `market_size_breakdown.png`
- **Type**: Pie chart
- **Data**: `data/market_size_data.csv`
- **Segments**: Database Market, Search Infrastructure, HPC, Cloud Services

#### 3.2 Competitive Positioning Matrix
- **File**: `competitive_positioning_matrix.png`
- **Type**: Scatter plot
- **Data**: `data/competitive_matrix_data.csv`
- **X-axis**: Performance (Speedup factor)
- **Y-axis**: Cost Efficiency (points)
- **Points**: QIHSE AVX2, QIHSE Full HW, ALEX, RAPIDS, SmartNIC

#### 3.3 Adoption Timeline Projection
- **File**: `adoption_timeline_projection.png`
- **Type**: Area chart (stacked)
- **Data**: `data/adoption_timeline_data.csv`
- **X-axis**: Year
- **Y-axis**: Market penetration (%)
- **Areas**: Early adopters, Mainstream, Laggards

#### 3.4 Revenue Potential by Segment
- **File**: `revenue_potential_segments.png`
- **Type**: Horizontal bar chart
- **Data**: `data/revenue_potential_data.csv`
- **Y-axis**: Market segment
- **X-axis**: Revenue potential ($M)
- **Bars**: Year 1, Year 2, Year 3

## Data File Formats

### CSV Structure Example
```csv
technology,dataset,latency_ms,qps,speedup
Binary Search,SIFT1M,6500,150,1.0
ALEX,SIFT1M,3300,300,2.0
RAPIDS,SIFT1M,670,1500,8.0
QIHSE_AVX2,SIFT1M,220,4500,29.5
QIHSE_Full_HW,SIFT1M,67,15000,97.0
```

### Color Scheme
- **QIHSE AVX2**: #1f77b4 (Blue)
- **QIHSE Full HW**: #ff7f0e (Orange)
- **Competitors**: #7f7f7f (Gray)
- **Baseline**: #d62728 (Red)

## Chart Styling Guidelines

### General
- **Font**: Arial or Helvetica, 10-12pt
- **Colors**: Professional color palette (blues, grays, accent colors)
- **Grid**: Light gray grid lines
- **Legend**: Upper right or lower right position
- **Title**: Clear, descriptive titles

### Performance Charts
- **Log scales**: Use for latency comparisons spanning orders of magnitude
- **Error bars**: Include confidence intervals where applicable
- **Annotations**: Highlight key data points and QIHSE advantages

### Cost Charts
- **Currency formatting**: $X.XM or $X.XK format
- **Time axes**: Month/Year labels
- **Break-even lines**: Highlight payback periods

### Market Charts
- **Percentages**: 0-100% scales
- **Large numbers**: Use M/B suffixes for millions/billions
- **Growth indicators**: Include CAGR annotations

## Export Formats

### Primary Formats
- **PNG**: 1920x1080 for presentations
- **SVG**: Scalable vector format for web
- **PDF**: Print-quality for documents

### Usage Guidelines
- **Presentations**: PNG at 1920x1080
- **Web content**: SVG for scalability
- **Print documents**: PDF at 300 DPI
- **Reports**: PNG at 1200x800

## Automation Scripts

### generate_performance_charts.py
```python
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

# Load data
latency_data = pd.read_csv('data/latency_benchmark_data.csv')

# Create latency comparison chart
plt.figure(figsize=(12, 8))
sns.barplot(data=latency_data, x='technology', y='latency_ms',
            hue='dataset', palette='Set2')
plt.yscale('log')
plt.title('Latency Comparison: Binary Search vs QIHSE')
plt.ylabel('Latency (ms, log scale)')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('latency_comparison_log.png', dpi=300, bbox_inches='tight')
```

### generate_cost_charts.py
```python
import matplotlib.pyplot as plt
import pandas as pd

# Load cost data
savings_data = pd.read_csv('data/cost_savings_timeline_data.csv')

# Create savings timeline
plt.figure(figsize=(12, 8))
for company in savings_data['company'].unique():
    company_data = savings_data[savings_data['company'] == company]
    plt.plot(company_data['month'], company_data['cumulative_savings_m'],
             label=company, linewidth=3)

plt.title('Infrastructure Cost Savings Timeline')
plt.xlabel('Month')
plt.ylabel('Cumulative Savings ($M)')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('infrastructure_savings_timeline.png', dpi=300, bbox_inches='tight')
```

## Quality Assurance

### Chart Review Checklist
- [ ] Data accuracy verified against source benchmarks
- [ ] Scales appropriate (log where needed)
- [ ] Colors accessible and professional
- [ ] Legends clear and positioned well
- [ ] Titles descriptive and accurate
- [ ] Axes labeled with units
- [ ] Grid lines not overwhelming
- [ ] Font sizes readable
- [ ] Exported at correct resolutions

### Data Validation
- [ ] CSV files match specification format
- [ ] Calculations verified with formulas
- [ ] Benchmarks reproducible
- [ ] Statistical significance considered
- [ ] Error bars included where applicable

This visual assets package provides professional, data-driven graphics that effectively communicate QIHSE's performance advantages and commercial value proposition.
