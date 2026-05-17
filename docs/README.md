# QIHSE Technical Documentation

Comprehensive documentation for the QIHSE search algorithm, hardware backends, and integration layers.

## 🛠️ Architecture & Core
- **[Heterogeneous Integration Guide](qihse_integration/HETEROGENEOUS_INTEGRATION.md)** - Details on NPU, iGPU, and GPU offloading.
- **[Engineering API Reference](engineering/api-reference.md)** - Function-level C documentation.
- **[Hilbert Expansion Diagram](diagrams/hilbert-expansion.txt)** - Visual representation of the space projection.

## 🔌 Integration Modules
- **[CUDA Integration](cuda-integration/qihse_cuda_kernels.cu)** - GPU acceleration details.
- **[Julia Accelerator](julia-integration/qihse_julia_accelerator.jl)** - Quantum-inspired math using Julia.
- **[Fortran Integration](fortran-integration/README.md)** - High-precision eigenvalue solvers.

## 💰 Cost & Value
- **[Database Cost Analysis](cost-analysis/database-costs.md)** - Infrastructure savings.
- **[Customer Value Proposition](customer/value-proposition.md)** - Use-case benefits.

---
For implementation details, see the source code in `qihse/`. The anchor-search utilities are integrated directly into QIHSE's native algorithm layer.
