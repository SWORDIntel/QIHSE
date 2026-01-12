# QIHSE Search Model

Quantum-Inspired Hilbert Space Expansion (QIHSE) search model for high-performance similarity search and retrieval operations.

## Overview

QIHSE implements a quantum-inspired search ecosystem that leverages modern heterogeneous hardware (CPU SIMD, NPU, GPU) for accelerated similarity search operations. The system uses Random Fourier Features (RFF) for kernel embedding, superposition states for candidate management, and Grover amplification for result optimization.

## Key Features

- **Heterogeneous Execution**: Parallel execution across CPU (AVX2/AVX512), Intel NPU (OpenVINO), and GPU (SYCL/CUDA)
- **Quantum-Inspired Algorithms**: RFF kernel embedding, superposition states, Grover amplification
- **Adaptive Precision**: Dynamic INT2/INT4/INT8/FP16/BF16 quantization based on accuracy requirements
- **Memory Hierarchy**: HMA (Holographic Memory Architecture) with superposition, interaction, and entanglement tiers
- **Real-time Adaptation**: ML-driven parameter optimization using Thompson Sampling

## Architecture

```
Input Data → RFF Projection → Superposition Encoding → Heterogeneous Search → Result Aggregation
                    ↓
            Grover Amplification
                    ↓
        Adaptive Quantization ← ML Optimization Engine
```

## Performance Targets

- **Throughput**: 10M queries/second on Intel Meteor Lake NPU
- **Latency**: <100μs per query for 1K candidates
- **Accuracy**: >95% recall@10 across benchmark datasets
- **Energy Efficiency**: <1W per 1M queries

## Hardware Requirements

- **CPU**: AVX2/AVX512 support (Intel 8th gen+ or AMD Zen+)
- **NPU**: Intel Meteor Lake NPU (128MB) or compatible
- **GPU**: Intel Arc (SYCL) or NVIDIA RTX 30-series+ (CUDA)
- **Memory**: 16GB+ system RAM, 256MB+ device memory per accelerator

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Build native components
./build.sh

# Run training
python train_qihse_model.py --config config.yaml
```

## Usage

```python
from qihse import QIHSESearch

# Initialize with heterogeneous backend
search = QIHSESearch(device="auto")  # CPU/NPU/GPU auto-selection

# Index documents
search.index(documents, embeddings)

# Search with quantum-inspired optimization
results = search.search(query_embedding, k=10)
```

## Benchmarks

See `evaluation_results/` for detailed benchmark results across:
- SIFT1M (1M vectors, 128D)
- GIST1M (1M vectors, 960D)
- MS MARCO (vector search)
- TSP/Job Shop (constraint optimization)
- Graph search benchmarks

## Configuration

See `config.yaml` for detailed configuration options including:
- Device selection and load balancing
- Quantization precision ladders
- Memory hierarchy tuning
- ML optimization parameters
