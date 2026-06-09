# Phase 0: Core ABI + Plugin Architecture

## Implementation Plan for Stable C ABI Foundation

**Duration:** 2 weeks
**Priority:** Critical (Foundation)
**Dependencies:** None

---

## Objectives

1. **Define stable C ABI** that survives major version changes
2. **Implement basic plugin loader** for backend discovery
3. **Create SearchOp contracts** for all core operations
4. **Establish ABI compatibility testing** framework

---

## 1. ABI Specification Design

### Core ABI Principles

```c
// qihse/core/qihse_abi.h - NEVER CHANGES after v1.0

#define QIHSE_ABI_VERSION 100  // v1.0.0

// Opaque handles (ABI stable)
typedef struct qihse_context* qihse_context_t;
typedef struct qihse_backend* qihse_backend_t;
typedef struct qihse_search_op* qihse_search_op_t;

// Stable error codes (negative for errors)
typedef enum {
    QIHSE_OK = 0,
    QIHSE_ERROR_INVALID_ARGUMENT = -1,
    QIHSE_ERROR_OUT_OF_MEMORY = -2,
    QIHSE_ERROR_BACKEND_UNAVAILABLE = -3,
    QIHSE_ERROR_TIMEOUT = -4,
    QIHSE_ERROR_VERIFICATION_FAILED = -5
} qihse_error_t;
```

### Memory Management ABI

```c
// Stable memory management (zero-copy promise)
typedef struct {
    void* data;
    size_t size;
    qihse_data_type_t type;
    qihse_memory_flags_t flags;  // HOST, DEVICE, PINNED, etc.
} qihse_buffer_t;

// ABI-stable allocation/deallocation
qihse_error_t qihse_buffer_create(qihse_context_t ctx,
                                  size_t size,
                                  qihse_data_type_t type,
                                  qihse_memory_flags_t flags,
                                  qihse_buffer_t* buffer);

void qihse_buffer_destroy(qihse_buffer_t* buffer);
```

### Search Operation ABI

```c
// Core search operations (ABI stable)
typedef struct {
    const char* name;
    qihse_search_op_type_t type;
    qihse_data_type_t input_type;
    qihse_data_type_t output_type;
    bool supports_batching;
    bool supports_quantization;
    uint32_t min_version;  // ABI version requirement
} qihse_search_op_info_t;

// Operation execution (ABI stable)
qihse_error_t qihse_search_execute(
    qihse_context_t ctx,
    qihse_search_op_t op,
    const qihse_buffer_t* inputs,
    size_t num_inputs,
    qihse_buffer_t* outputs,
    size_t num_outputs,
    const qihse_search_config_t* config
);
```

---

## 2. Plugin Architecture Implementation

### Backend Plugin Interface

```c
// qihse/plugins/qihse_plugin.h

typedef struct {
    uint32_t abi_version;
    const char* name;
    const char* description;
    qihse_backend_type_t type;
    uint32_t priority;  // 0-100, higher = preferred
} qihse_plugin_info_t;

// Plugin lifecycle (ABI stable)
typedef qihse_error_t (*qihse_plugin_init_fn)(
    const qihse_plugin_info_t* info,
    qihse_backend_t* backend
);

typedef void (*qihse_plugin_shutdown_fn)(qihse_backend_t backend);

// Operation support query (ABI stable)
typedef bool (*qihse_plugin_supports_op_fn)(
    qihse_backend_t backend,
    qihse_search_op_t op
);
```

### Plugin Discovery and Loading

```c
// Plugin registry
typedef struct {
    qihse_plugin_info_t info;
    void* dl_handle;  // dlopen handle
    qihse_plugin_init_fn init;
    qihse_plugin_shutdown_fn shutdown;
    qihse_plugin_supports_op_fn supports_op;
    // ... other function pointers
} qihse_plugin_t;

// Plugin directory scanning
qihse_error_t qihse_plugin_load_directory(
    qihse_context_t ctx,
    const char* plugin_dir
);

// Backend enumeration
qihse_error_t qihse_backend_enumerate(
    qihse_context_t ctx,
    qihse_backend_info_t* backends,
    size_t* num_backends
);
```

---

## 3. SearchOp Contract Definitions

### Core Operation Contracts

#### Vector Search (ANN/top-K)

```c
// Contract: vector_knn_search
typedef struct {
    qihse_buffer_t query_vectors;     // [num_queries, dimensions]
    qihse_buffer_t database_vectors;  // [num_vectors, dimensions]
    uint32_t k;                       // top-k results
    float radius;                     // search radius (optional)
    qihse_metric_type_t metric;       // L2, cosine, etc.
} qihse_vector_search_config_t;

// Output: [num_queries, k] indices + distances
```

#### Graph Search

```c
// Contract: graph_search
typedef struct {
    qihse_buffer_t adjacency_matrix;  // CSR/CSC format
    qihse_buffer_t start_nodes;       // [num_queries]
    qihse_graph_algorithm_t algorithm; // BFS, DFS, shortest_path, etc.
    uint32_t max_depth;              // search depth limit
    qihse_buffer_t node_weights;      // optional node weights
} qihse_graph_search_config_t;
```

#### Constraint Search

```c
// Contract: constraint_search
typedef struct {
    qihse_buffer_t candidates;        // [num_candidates, feature_dims]
    qihse_buffer_t constraints;       // Constraint expressions
    qihse_buffer_t constraint_weights; // [num_constraints]
    qihse_optimization_goal_t goal;   // minimize/maximize
} qihse_constraint_search_config_t;
```

---

## 4. ABI Compatibility Testing

### Version Compatibility Matrix

```c
// ABI version compatibility
typedef struct {
    uint32_t min_abi_version;
    uint32_t max_abi_version;
    qihse_compatibility_flags_t flags;
} qihse_abi_compatibility_t;

// Runtime version checking
qihse_error_t qihse_check_abi_compatibility(
    uint32_t requested_version,
    qihse_abi_compatibility_t* compat
);
```

### Contract Testing Framework

```c
// Operation contract validation
typedef struct {
    const char* op_name;
    qihse_test_case_t* test_cases;
    size_t num_test_cases;
    qihse_contract_validator_fn validator;
} qihse_contract_test_t;

// Automated contract testing
qihse_error_t qihse_validate_backend_contracts(
    qihse_backend_t backend,
    const qihse_contract_test_t* tests,
    size_t num_tests
);
```

---

## 5. Implementation Roadmap

### Week 1: Core ABI Definition
- [ ] Define stable C types and error codes
- [ ] Implement basic buffer management ABI
- [ ] Create SearchOp info structures
- [ ] Define operation execution ABI

### Week 2: Plugin System
- [ ] Implement plugin loading mechanism
- [ ] Create backend enumeration API
- [ ] Build basic plugin registry
- [ ] Add ABI compatibility checking

### Testing & Validation
- [ ] Create ABI compliance test suite
- [ ] Implement contract validation framework
- [ ] Test plugin loading/unloading
- [ ] Validate memory management ABI

---

## 6. Success Criteria

### Functional Requirements
- ✅ ABI headers compile on all target platforms (Linux, macOS, Windows)
- ✅ Plugin loading works for CPU backend
- ✅ All SearchOp contracts defined and documented
- ✅ ABI version checking implemented

### Quality Requirements
- ✅ Zero ABI-breaking changes possible without major version bump
- ✅ Comprehensive contract test coverage (>90%)
- ✅ Plugin isolation (crashes don't affect main process)
- ✅ Memory safety in all ABI functions

### Performance Requirements
- ✅ Plugin loading overhead < 100ms
- ✅ ABI dispatch overhead < 1μs per call
- ✅ Memory allocation overhead < 10% of raw malloc

---

## 7. Risk Mitigation

### ABI Stability Risks
**Risk:** ABI changes break backward compatibility
**Mitigation:**
- Strict semantic versioning
- ABI compatibility testing in CI
- Deprecation warnings for old APIs

### Plugin Isolation Risks
**Risk:** Plugin crashes bring down entire system
**Mitigation:**
- Sandbox plugins in separate processes
- Timeout mechanisms for plugin operations
- Comprehensive error handling

### Cross-Platform Compatibility
**Risk:** ABI works differently on different platforms
**Mitigation:**
- Cross-platform CI testing
- Platform-specific ABI validation
- Extensive testing on all supported platforms

---

## 8. Dependencies & Prerequisites

### Build Dependencies
- C99 compiler (GCC/Clang/MSVC)
- CMake 3.20+ for build system
- dlfcn.h for dynamic loading (POSIX systems)

### Runtime Dependencies
- Dynamic linker (ld.so/dlfcn on Unix, DLL loading on Windows)
- Sufficient memory for plugin loading
- File system access for plugin directories

---

## 9. Documentation Requirements

### API Documentation
- [ ] Complete ABI reference manual
- [ ] Plugin development guide
- [ ] SearchOp contract specifications
- [ ] Platform-specific ABI notes

### Developer Documentation
- [ ] ABI design rationale
- [ ] Version compatibility guide
- [ ] Testing and validation procedures
- [ ] Troubleshooting common issues

---

## 10. Next Phase Integration

### Hand-offs to Phase 1
- ✅ Stable ABI for backend implementation
- ✅ Plugin loading mechanism for CPU backend
- ✅ SearchOp contracts for SIMD implementation
- ✅ Testing framework for backend validation

### Phase 1 Dependencies
- Phase 0 must deliver working plugin system
- ABI must be stable for 6+ months
- Contract tests must pass for all backends

---

**Phase 0 Status:** Ready for Implementation
**Estimated Effort:** 2 weeks (80 hours)
**Risk Level:** Low (well-understood C ABI patterns)
**Confidence:** High (standard C ABI practices)
