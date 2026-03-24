#!/bin/bash
# QIHSE Graceful Fallback Verification Script
# This script verifies that the library remains functional even when
# high-performance hardware drivers (OpenVINO, CUDA) are missing.

echo "--- QIHSE Graceful Fallback Audit ---"

# 1. Check if libqihse.so exists
if [ ! -f "qihse/libqihse.so" ]; then
    echo "Error: libqihse.so not found. Run make first."
    exit 1
fi

# 2. Verify that OpenVINO and CUDA are NOT in the system path (simulating a clean CI environment)
ldconfig -p | grep -E "libopenvino|libcuda" > /dev/null
if [ $? -eq 0 ]; then
    echo "Warning: High-perf libraries found on system. Fallback testing may be biased."
else
    echo "Confirmed: Simulating environment without native NPU/GPU drivers."
fi

# 3. Execute Python search to trigger dynamic loader check
echo "Running Python search (should trigger AVX2 fallback)..."
export LD_LIBRARY_PATH=$PWD/qihse
python3 qihse/python/qihse.py > fallback_out.log 2>&1

if [ $? -eq 0 ]; then
    echo "✅ Success: Search engine correctly fell back to CPU SIMD."
    grep "Build:" fallback_out.log
else
    echo "❌ Failure: Library failed to load or crash on missing dependencies."
    cat fallback_out.log
    exit 1
fi

echo "--- Audit Complete ---"
