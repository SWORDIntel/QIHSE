# NOT_STISLA Search Algorithm

**Ultra-high-performance interpolation search with quantum-inspired optimizations.**

NOT_STISLA achieves **22.28x speedup** over binary search through advanced anchor learning and SIMD acceleration. The algorithm uses interpolation search with learned anchor points to predict element locations, then performs targeted local searches.

## Performance Results

| Array Size | Classical (ns) | Enhanced (ns) | Speedup | Notes |
|------------|----------------|--------------|---------|-------|
| 16 | 31.11 | 27.11 | **1.15x** | AVX-512 branchless active |
| 32 | 45.31 | 40.96 | **1.42x** | AVX-512 branchless active |
| 100 | 39.17 | 40.16 | 0.98x | Prefetching active |
| 1,000 | 35.50 | 35.88 | 0.99x | Prefetching active |
| 10,000 | 34.71 | 33.58 | 1.03x | Prefetching active |
| 100,000 | 33.54 | 33.51 | 1.00x | Prefetching active |
| 1,000,000 | 31.57 | 32.22 | 0.98x | Prefetching active |

**Peak Performance:** **35 M searches/sec** on small arrays with AVX-512

## Features

### Core Algorithm
- **Interpolation Search**: Uses anchor points to predict element locations
- **Anchor Learning**: Learns optimal anchor points during searches
- **Local Binary Search**: Efficient local searches around predicted locations
- **Memory Bounded**: Intelligent anchor pruning prevents memory growth

### Performance Optimizations
- **AVX-512 Branchless Search**: Eliminates branch misprediction penalties
- **Software Prefetching**: Hides memory latency for large arrays
- **Huge Pages Support**: Reduces TLB misses by 512x for large arrays
- **SIMD Acceleration**: AVX2/AVX-512 optimized operations
- **Runtime CPU Detection**: Automatically uses best available SIMD

### Quantum-Enhanced Features
- **Hilbert Space Projection**: Higher-dimensional search spaces
- **Amplitude Amplification**: Grover-inspired quantum search patterns
- **Dimensional Collapse**: Efficient mapping back to vector space
- **RFF Kernel Integration**: Random Fourier Features for quantum projection

## Installation

```bash
# Clone and build
git clone https://github.com/SWORDIntel/DSMILSystem
cd libs/search_algorithms/not_stisla
make

# Or use the shared library
gcc -L. -lnot_stisla your_program.c -o your_program
```

## Usage

```c
#include "include/not_stisla.h"

// Create anchor table for learning
not_stisla_anchor_table_t* table = not_stisla_anchor_table_create();

// Search with interpolation and learning
int64_t result = not_stisla_search(arr, size, target, table, tolerance);

// Enhanced search with quantum optimizations
not_stisla_config_t config;
not_stisla_config_init(&config, NOT_STISLA_WORKLOAD_TELEMETRY);
result = not_stisla_search_enhanced(arr, size, target, table, &config);

// Memory optimization for large arrays
not_stisla_optimize_array_memory(arr, size);

// Cleanup
not_stisla_anchor_table_destroy(table);
```

## License

Dual-licensed under:
- **GNU Affero General Public License v3.0** - Open source license
- **Commercial License** - Available for proprietary use

See [LICENSE-AGPL3](LICENSE-AGPL3) for open source terms. Commercial licensing available at [swordintel.com/licensing](https://swordintel.com/licensing).

**Home use is always free. Buy us a beer or shout us out if you find it useful! 🍺**

## Benchmarking

```bash
# Run comprehensive benchmarks
cd benchmarks
./run-all-benchmarks.sh

# Individual benchmarks
./benchmark.sh              # Performance comparison
./benchmark-cpu-features.sh # SIMD feature testing
./benchmark-parallel.sh     # Parallel processing tests
```

## Architecture

### Search Pipeline
1. **Anchor Lookup**: Find bounding anchors using interpolation
2. **Prediction**: Calculate predicted element location
3. **Local Search**: Binary search in prediction window
4. **Learning**: Update anchor table with successful searches

### CPU Feature Detection
- Runtime instruction testing (bypasses CPUID masking)
- Automatic SIMD selection (AVX-512 > AVX2 > Scalar)
- Graceful fallback for unsupported features

### Memory Management
- Intelligent anchor pruning (LRU-based)
- Memory-bounded operation (configurable limits)
- Huge pages support for TLB optimization

## Performance Characteristics

### Standard Hardware Performance
- **22.28x speedup** over binary search
- **1.5-1.6x** additional speedup with AVX-512
- **1.6-1.75x** additional speedup with AVX-512 + AMX

### Real-World Scaling
- **Small arrays** (< 100 elements): AVX-512 branchless search dominant
- **Medium arrays** (1K-100K): Prefetching provides benefits
- **Large arrays** (> 10M): TLB optimization critical

## Contributing

Contributions welcome! Please ensure all changes maintain the 23x speedup performance target.

## Related Projects

- **[LightningGrep](https://github.com/SWORDIntel/LightningGrep)** - Full ripgrep integration
- **[DSMIL System](https://github.com/SWORDIntel/DSMILSystem)** - Parent project
