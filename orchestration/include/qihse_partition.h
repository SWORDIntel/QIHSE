/*
 * QIHSE - Work Partitioning Header
 *
 * Intelligent workload partitioning across heterogeneous devices.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_PARTITION_H
#define QIHSE_PARTITION_H

#include "qihse_hetero.h"
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration for internal device entry */
struct qihse_device_entry_s;
typedef struct qihse_device_entry_s qihse_device_entry_t;

/* ============================================================================
 * PARTITIONING STRATEGIES
 * ============================================================================ */

/**
 * Workload partitioning strategies.
 */
typedef enum qihse_partition_strategy_e {
    QIHSE_PARTITION_GREEDY = 0,        /* Assign each operation to best device */
    QIHSE_PARTITION_LOAD_BALANCED = 1, /* Distribute load across devices */
    QIHSE_PARTITION_ADAPTIVE = 2,      /* Adaptive partitioning based on runtime feedback */
} qihse_partition_strategy_t;

/* ============================================================================
 * PARTITIONING API
 * ============================================================================ */

/**
 * Partition workload across heterogeneous devices.
 *
 * This function analyzes the characteristics of each operation in the batch
 * and assigns them to the most suitable devices based on the selected strategy.
 *
 * @param pool Heterogeneous compute pool
 * @param batch Work batch to partition
 * @param strategy Partitioning strategy to use
 * @param partitions Output array of device assignments (size = batch->num_operations)
 * @return 0 on success, negative error code on failure
 */
int qihse_partition_workload(
    qihse_hetero_pool_t pool,
    const qihse_work_batch_t* batch,
    qihse_partition_strategy_t strategy,
    qihse_device_type_t* partitions
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_PARTITION_H */
