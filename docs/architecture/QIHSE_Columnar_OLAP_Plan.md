# QIHSE Columnar OLAP Engine Plan

## 1. Overview
The QIHSE Columnar OLAP Engine provides high-performance, SIMD-accelerated columnar storage for analytical workloads. Unlike the row-based document store, data here is stored in contiguous, type-homogeneous blocks (columns) optimized for aggregations, scans, and CPU cache locality.

## 2. Core Components

### 2.1 Dictionary Encoding (`QIHSE_COL_TYPE_STRING_DICT`)
For high-cardinality string columns (e.g., categories, tags), storing raw strings repeatedly wastes memory and bandwidth. Dictionary encoding maintains a hash map of unique strings to integer IDs. The columnar chunk stores only the integer IDs. Aggregations and filtering can operate directly on the integer IDs.

### 2.2 Run-Length Encoding (RLE) (`QIHSE_ENCODING_RLE`)
For sorted or low-cardinality data with many repeated adjacent values, RLE compresses the chunk by storing pairs of `(value, run_length)`. When a chunk's data meets a repetition threshold, it dynamically switches from `QIHSE_ENCODING_RAW` to `QIHSE_ENCODING_RLE`.

### 2.3 Vector-Accelerated Aggregations
Existing aggregation functions (`qihse_column_sum_int64`, `qihse_column_sum_float32`) use `#pragma GCC ivdep` and SIMD directives. These must be enhanced to properly handle chunks that are compressed via RLE. 

## 3. Implementation Plan

1. **Extend `qihse_column.h`**:
   - Add `qihse_column_append_string` for dictionary encoding.
   - Add `qihse_column_sum_int64_rle` internally or update the existing sum functions to branch based on `chunk->encoding`.

2. **Modify `qihse_column_store.c`**:
   - Add dictionary state to `qihse_column_node_t` (a simple array of unique strings or a hash map).
   - Implement `qihse_column_append_string` which assigns an integer ID to the string and stores the ID in the columnar chunk (using `int32_t`).
   - Modify `append_value` to dynamically switch a chunk to `QIHSE_ENCODING_RLE` if the chunk is highly repetitive. 
   - Update `qihse_column_sum_int64` and `qihse_column_sum_float32` to correctly aggregate RLE-encoded chunks (`value * run_length`).

3. **Testing**:
   - Create `tests/test_column_store.c`.
   - Test appending integers, floats, and strings.
   - Test that RLE chunks correctly aggregate sums.
   - Test that string dictionaries successfully compress repeated strings.
