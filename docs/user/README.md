# QIHSE User Guide

This guide provides comprehensive instructions for installing, configuring, and using the QIHSE (Quantum-Inspired Hilbert Space Expansion) search ecosystem.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Configuration](#configuration)
4. [Basic Usage](#basic-usage)
5. [Advanced Usage](#advanced-usage)
6. [Performance Tuning](#performance-tuning)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)

## Installation

### System Requirements

#### Minimum Requirements
- **CPU**: x86-64 with AVX2 support
- **RAM**: 8GB
- **Storage**: 10GB free space
- **OS**: Linux (Ubuntu 18.04+, CentOS 7+, RHEL 7+)

#### Recommended Requirements
- **CPU**: x86-64 with AVX-512 and AMX support (Intel Xeon or Core i9)
- **RAM**: 32GB+
- **Storage**: 50GB+ NVMe SSD
- **GPU**: NVIDIA RTX 30-series or Intel Arc A-series (optional)
- **NPU**: Intel Meteor Lake or later (optional)

### Installing Dependencies

#### Ubuntu/Debian
```bash
# Update package lists
sudo apt update

# Install build tools
sudo apt install -y build-essential cmake pkg-config

# Install Intel OneAPI (for AMX/AVX-512 support)
wget -O- https://apt.repos.intel.com/intel-gpg-keys/GPG-PUB-KEY-INTEL-SW-PRODUCTS.PUB \
| gpg --dearmor | sudo tee /usr/share/keyrings/oneapi-archive-keyring.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/oneapi-archive-keyring.gpg] https://apt.repos.intel.com/oneapi all main" \
| sudo tee /etc/apt/sources.list.d/oneAPI.list

sudo apt update
sudo apt install -y intel-oneapi-basekit intel-oneapi-advisor

# Install OpenVINO (for NPU support)
sudo apt install -y libopenvino-dev openvino

# Install CUDA (for NVIDIA GPU support - optional)
# wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/cuda-ubuntu2004.pin
# sudo mv cuda-ubuntu2004.pin /etc/apt/preferences.d/cuda-repository-pin-600
# wget https://developer.download.nvidia.com/compute/cuda/11.8.0/local_installers/cuda_11.8.0_520.61.05_linux.run
# sudo sh cuda_11.8.0_520.61.05_linux.run --no-opengl-libs --no-man-page --no-drm

# Install development libraries
sudo apt install -y libssl-dev libnuma-dev libhwloc-dev
```

#### CentOS/RHEL
```bash
# Install build tools
sudo yum groupinstall -y "Development Tools"
sudo yum install -y cmake pkgconfig

# Install Intel OneAPI
sudo rpm --import https://yum.repos.intel.com/intel-gpg-keys/GPG-PUB-KEY-INTEL-SW-PRODUCTS.PUB
sudo rpm -Uhv https://yum.repos.intel.com/intel-gpg-keys/GPG-PUB-KEY-INTEL-SW-PRODUCTS-2023.PUB

sudo yum-config-manager --add-repo https://yum.repos.intel.com/oneAPI
sudo yum install -y intel-oneapi-basekit intel-oneapi-advisor

# Install OpenVINO
sudo rpm -ivh https://storage.openvinotoolkit.org/repositories/openvino/packages/2023.0/l_openvino_toolkit_ubuntu20_2023.0.0.11146.394a6a8da9a3_x86_64.rpm

# Install CUDA (optional)
# Download and install CUDA toolkit from NVIDIA

# Install development libraries
sudo yum install -y openssl-devel numactl-devel hwloc-devel
```

### Building QIHSE

```bash
# Clone the repository
git clone <repository-url>
cd qihse-breakthroughalgo

# Build the system
make -j$(nproc)

# Run tests
make test

# Install system
sudo make install

# Update library cache
sudo ldconfig
```

### Verifying Installation

```bash
# Check QIHSE version
qihse-info --version

# Test hardware detection
qihse-info --hardware

# Run basic functionality test
qihse-test --basic

# Check library dependencies
ldd /usr/local/lib/libqihse.so
```

## Quick Start

### Basic Vector Search Example

```c
#include <qihse/qihse.h>
#include <stdio.h>

int main() {
    // Initialize QIHSE
    qihse_search_context_t* ctx = qihse_search_init();
    if (!ctx) {
        fprintf(stderr, "Failed to initialize QIHSE\n");
        return 1;
    }

    // Configure for basic usage
    qihse_config_t config = *qihse_config_default();
    config.verification_mode = QIHSE_VERIFY_FAST;
    config.confidence_threshold = 0.9;

    // Load dataset (example: SIFT1M)
    int ret = qihse_search_load_vectors(ctx, "data/sift1m.bin",
                                        QIHSE_FORMAT_SIFT, &config);
    if (ret != QIHSE_SUCCESS) {
        fprintf(stderr, "Failed to load dataset: %d\n", ret);
        qihse_search_destroy(ctx);
        return 1;
    }

    // Create query vector (128-dimensional)
    float query[128];
    for (int i = 0; i < 128; i++) {
        query[i] = (float)rand() / RAND_MAX; // Random query
    }

    // Search for 10 nearest neighbors
    uint32_t result_ids[10];
    float result_distances[10];

    ret = qihse_search_vector(ctx, query, 10, result_ids, result_distances);
    if (ret != QIHSE_SUCCESS) {
        fprintf(stderr, "Search failed: %d\n", ret);
        qihse_search_destroy(ctx);
        return 1;
    }

    // Print results
    printf("Top 10 nearest neighbors:\n");
    for (int i = 0; i < 10; i++) {
        printf("  ID: %u, Distance: %.4f\n", result_ids[i], result_distances[i]);
    }

    // Cleanup
    qihse_search_destroy(ctx);
    return 0;
}
```

### Compiling and Running

```bash
# Compile the example
gcc -o vector_search_example vector_search_example.c \
    -lqihse -lm -lpthread -I/usr/local/include

# Run the example
./vector_search_example
```

## Configuration

### Configuration File Format

QIHSE uses JSON configuration files for complex setups:

```json
{
  "hardware": {
    "cpu": {
      "avx2": true,
      "avx512": true,
      "amx": true
    },
    "npu": {
      "openvino": true,
      "pim_operations": true
    },
    "gpu": {
      "intel_arc": true,
      "nvidia_cuda": true
    }
  },
  "quantum": {
    "mode": "hybrid",
    "rff_dimension": 2048,
    "rff_gamma": 1.0
  },
  "verification": {
    "mode": "precision",
    "confidence_threshold": 0.95,
    "max_verification_time_ms": 1000
  },
  "memory": {
    "max_memory_mb": 8192,
    "enable_uma": true,
    "memory_policy": "performance"
  },
  "ml": {
    "enable_self_optimization": true,
    "batch_size": 64,
    "learning_rate": 0.001
  },
  "energy": {
    "enable_energy_aware": true,
    "max_power_watts": 200,
    "thermal_limit_celsius": 80.0
  },
  "distributed": {
    "enable_distributed": false,
    "cluster_name": "qihse-cluster",
    "cluster_port": 8080
  },
  "security": {
    "level": "cnsa2",
    "key_store_path": "/etc/qihse/keys"
  }
}
```

### Loading Configuration

```c
// Load from file
qihse_config_t* config = qihse_config_load("config.json");
if (!config) {
    fprintf(stderr, "Failed to load configuration\n");
    return 1;
}

// Validate configuration
qihse_error_info_t error;
if (qihse_config_validate(config, &error) != QIHSE_SUCCESS) {
    fprintf(stderr, "Invalid configuration: %s\n", error.message);
    qihse_config_free(config);
    return 1;
}

// Use configuration
qihse_search_context_t* ctx = qihse_search_init();
qihse_config_update(ctx, config);
```

### Runtime Configuration Updates

```c
// Get current configuration
const qihse_config_t* current = qihse_config_get(ctx);

// Create new configuration with modifications
qihse_config_t* new_config = qihse_config_default();
new_config->confidence_threshold = 0.99; // Increase precision

// Check if restart is required
if (qihse_config_requires_restart(current, new_config)) {
    printf("Configuration change requires restart\n");
    // Save new configuration and restart application
    qihse_config_save(new_config, "config.json");
} else {
    // Update configuration at runtime
    qihse_config_update(ctx, new_config);
}
```

## Basic Usage

### Vector Search Operations

#### Single Query Search

```c
// Load dataset
qihse_search_load_vectors(ctx, "data/sift1m.bin", QIHSE_FORMAT_SIFT, &config);

// Single vector search
float query[128] = { /* 128-dimensional query vector */ };
uint32_t k = 100; // Number of nearest neighbors
uint32_t result_ids[k];
float result_distances[k];

int ret = qihse_search_vector(ctx, query, k, result_ids, result_distances);
if (ret == QIHSE_SUCCESS) {
    for (uint32_t i = 0; i < k; i++) {
        printf("Neighbor %u: ID=%u, Distance=%.4f\n",
               i, result_ids[i], result_distances[i]);
    }
}
```

#### Batch Query Search

```c
// Batch search with multiple queries
uint32_t num_queries = 10;
uint32_t k = 50;
float queries[num_queries][128]; // 10 queries
uint32_t result_ids[num_queries * k];
float result_distances[num_queries * k];
uint32_t result_counts[num_queries];

int ret = qihse_search_vector_batch(ctx, (float*)queries, num_queries, k,
                                    result_ids, result_distances, result_counts);

for (uint32_t q = 0; q < num_queries; q++) {
    printf("Query %u results:\n", q);
    uint32_t start_idx = q * k;
    for (uint32_t i = 0; i < result_counts[q]; i++) {
        printf("  ID=%u, Distance=%.4f\n",
               result_ids[start_idx + i], result_distances[start_idx + i]);
    }
}
```

#### Approximate Search with Bounds

```c
// Approximate search with epsilon bound
float epsilon = 0.1; // Allow 10% approximation
uint32_t result_ids[k];
float result_distances[k];

int ret = qihse_search_ann(ctx, query, k, epsilon, result_ids, result_distances);
// Results guaranteed to be within (1+ε) of optimal
```

### Graph Search Operations

```c
// Load graph dataset
qihse_search_load_graph(ctx, "data/livejournal.bin", QIHSE_FORMAT_GRAPH, &config);

// Breadth-first search
uint32_t start_node = 42;
uint32_t max_depth = 3;
uint32_t result_nodes[1000];
uint32_t result_distances[1000];
uint32_t num_results;

int ret = qihse_search_graph(ctx, start_node, QIHSE_GRAPH_BFS, max_depth,
                             result_nodes, result_distances, &num_results);
```

### Constraint Optimization

```c
// Traveling Salesman Problem
qihse_tsp_config_t tsp_config = {
    .num_cities = 100,
    .coordinates = city_coords, // float[num_cities][2]
    .optimization_goal = QIHSE_TSP_MINIMIZE_DISTANCE
};

qihse_tsp_solution_t solution;
int ret = qihse_search_tsp(ctx, &tsp_config, &solution);

if (ret == QIHSE_SUCCESS) {
    printf("TSP Solution: Distance=%.2f, Path=[", solution.total_distance);
    for (uint32_t i = 0; i < solution.path_length; i++) {
        printf("%u%s", solution.path[i], i < solution.path_length - 1 ? "," : "");
    }
    printf("]\n");
}
```

## Advanced Usage

### Self-Optimizing Runtime

```c
// Enable ML-based optimization
qihse_config_t config = *qihse_config_default();
config.enable_self_optimization = true;
config.ml_batch_size = 128;
config.ml_learning_rate = 0.001;

// Initialize with ML engine
qihse_search_context_t* ctx = qihse_search_init();
qihse_config_update(ctx, &config);

// The system will automatically learn and optimize query processing
// over time based on workload patterns and performance feedback
```

### Heterogeneous Execution

```c
// Configure all available backends
qihse_config_t config = *qihse_config_default();
config.enable_cpu_avx2 = true;
config.enable_cpu_avx512 = true;
config.enable_cpu_amx = true;
config.enable_npu = true;
config.enable_gpu_intel = true;
config.enable_gpu_nvidia = true;

// QIHSE will automatically select optimal backends for each operation
// based on hardware availability and workload characteristics
```

### Energy-Aware Optimization

```c
// Configure energy constraints
qihse_config_t config = *qihse_config_default();
config.enable_energy_aware = true;
config.max_power_watts = 150;     // Power budget
config.thermal_limit_celsius = 75.0; // Thermal limit

// System will optimize for energy efficiency while maintaining performance
// Automatically adjusts precision, frequency, and backend selection
```

### Distributed Search

```c
// Configure distributed cluster
qihse_config_t config = *qihse_config_default();
config.enable_distributed = true;
config.cluster_name = "production-cluster";
config.cluster_port = 8080;

// Initialize distributed manager
qihse_distributed_manager_t* dist_mgr = qihse_distributed_init(
    node_id, "node1.cluster.internal", 8080);

// Join cluster
qihse_distributed_join_cluster(dist_mgr, "seed-node.cluster.internal", 8080);

// System now operates as part of distributed cluster with automatic
// load balancing, fault tolerance, and coherence management
```

### Custom Verification Levels

```c
// High-precision verification for critical applications
qihse_config_t config = *qihse_config_default();
config.verification_mode = QIHSE_VERIFY_PRECISION;
config.confidence_threshold = 0.99; // 99% confidence minimum
config.max_verification_time_ms = 2000; // Allow more time for verification

// Results guaranteed to meet 99% confidence threshold
// Automatic rejection of results below threshold
```

## Performance Tuning

### Memory Optimization

```c
// Optimize memory usage for large datasets
qihse_config_t config = *qihse_config_default();
config.max_memory_mb = 16384;     // 16GB limit
config.enable_uma = true;         // Unified memory
config.memory_policy = QIHSE_MEMORY_PERFORMANCE; // Performance-optimized

// Use HMA for quantum-inspired operations
config.quantum_mode = QIHSE_QUANTUM_HYBRID;
config.rff_dimension = 4096;      // Higher dimensional space
```

### Hardware-Specific Tuning

```c
// AVX-512 optimized configuration
qihse_config_t config = *qihse_config_default();
config.enable_cpu_avx512 = true;
config.enable_cpu_amx = true;     // Enable matrix operations

// NPU acceleration for inference workloads
config.enable_npu = true;
config.enable_pim_operations = true; // Enable PIM operations

// GPU acceleration for batch processing
config.enable_gpu_nvidia = true;
config.enable_gpu_intel = true;
```

### Workload-Specific Optimization

```c
// Vector search optimization
qihse_config_t vector_config = *qihse_config_default();
vector_config.rff_dimension = 2048;
vector_config.verification_mode = QIHSE_VERIFY_FAST;

// Graph search optimization
qihse_config_t graph_config = *qihse_config_default();
graph_config.memory_policy = QIHSE_MEMORY_BANDWIDTH;
graph_config.enable_distributed = true;

// Constraint optimization
qihse_config_t constraint_config = *qihse_config_default();
constraint_config.verification_mode = QIHSE_VERIFY_EXACT;
constraint_config.max_verification_time_ms = 5000;
```

## Troubleshooting

### Common Issues

#### Hardware Detection Failures

```bash
# Check CPU features
qihse-info --cpu-features

# Test AVX2 support
qihse-test --avx2

# Check GPU availability
qihse-info --gpu

# Verify NPU functionality
qihse-test --npu
```

#### Memory Issues

```bash
# Check memory usage
qihse-info --memory

# Monitor memory allocation
qihse-debug --memory-trace

# Check for memory leaks
valgrind --leak-check=full ./your_application
```

#### Performance Issues

```bash
# Run performance benchmark
qihse-benchmark --comprehensive

# Profile application
qihse-profile --your-app-config.json

# Check regression
qihse-regression --detect
```

#### Configuration Problems

```bash
# Validate configuration
qihse-config --validate config.json

# Show effective configuration
qihse-config --effective config.json

# Generate default configuration
qihse-config --default > config.json
```

### Error Codes and Solutions

| Error Code | Description | Solution |
|------------|-------------|----------|
| `QIHSE_ERROR_INVALID_ARGUMENT` | Invalid parameter | Check function arguments |
| `QIHSE_ERROR_OUT_OF_MEMORY` | Memory allocation failed | Reduce memory usage or increase limits |
| `QIHSE_ERROR_IO` | I/O operation failed | Check file permissions and paths |
| `QIHSE_ERROR_TIMEOUT` | Operation timed out | Increase timeout values or check hardware |
| `QIHSE_ERROR_HARDWARE` | Hardware not supported | Check hardware compatibility |
| `QIHSE_ERROR_VERIFICATION` | Verification failed | Adjust verification settings |
| `QIHSE_ERROR_SECURITY` | Security violation | Check security configuration |

### Logging and Debugging

```c
// Enable detailed logging
setenv("QIHSE_LOG_LEVEL", "DEBUG", 1);
setenv("QIHSE_LOG_FILE", "/var/log/qihse.log", 1);

// Enable performance profiling
setenv("QIHSE_PROFILE", "1", 1);
setenv("QIHSE_PROFILE_FILE", "/tmp/qihse_profile.json", 1);

// Enable memory debugging
setenv("QIHSE_MEMORY_DEBUG", "1", 1);
```

## Best Practices

### Performance Optimization

1. **Choose Appropriate Verification Levels**
   - Use `QIHSE_VERIFY_FAST` for real-time applications
   - Use `QIHSE_VERIFY_PRECISION` for critical accuracy requirements
   - Use `QIHSE_VERIFY_NONE` only for development/testing

2. **Configure Hardware Backends**
   - Enable all available hardware acceleration
   - Monitor backend utilization with `qihse-info --backend-stats`
   - Tune RFF dimensions based on dataset characteristics

3. **Memory Management**
   - Set appropriate memory limits based on system resources
   - Enable UMA for systems with multiple memory types
   - Monitor memory usage with `qihse-info --memory`

### Reliability and Monitoring

1. **Enable Self-Optimization**
   - Allow the ML engine to learn from your workload patterns
   - Monitor learning progress with `qihse-info --ml-stats`
   - Backup learned models periodically

2. **Set Up Monitoring**
   - Monitor system health with regular benchmark runs
   - Enable regression detection for performance monitoring
   - Log security events and system anomalies

3. **Configure for Production**
   - Use CNSA 2.0 compliant security settings
   - Enable energy-aware optimization for data centers
   - Configure distributed operation for high availability

### Security Best Practices

1. **Key Management**
   - Store keys securely using hardware security modules
   - Rotate keys regularly according to your security policy
   - Use separate keys for different security domains

2. **Access Control**
   - Implement proper authentication and authorization
   - Use role-based access control for administrative functions
   - Audit all security-relevant operations

3. **Data Protection**
   - Enable encryption for data at rest and in transit
   - Use secure communication protocols (TLS 1.3+)
   - Implement proper data sanitization and validation

### Maintenance and Updates

1. **Regular Backups**
   - Backup configuration files and learned models
   - Document system configuration and customizations
   - Test backup restoration procedures regularly

2. **Performance Monitoring**
   - Run regular benchmark suites to detect performance degradation
   - Monitor hardware health and utilization
   - Update to latest versions for security and performance improvements

3. **Capacity Planning**
   - Monitor resource usage trends
   - Plan hardware upgrades based on growth projections
   - Test scaling characteristics with representative workloads

---

This guide covers the essential aspects of installing, configuring, and using QIHSE. For detailed API documentation, see the [API Reference](api/). For deployment in production environments, see the [Deployment Guide](deployment/).
