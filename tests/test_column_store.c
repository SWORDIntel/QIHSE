#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "qihse_column.h"

int main(void) {
    printf("Testing Columnar OLAP Engine...\n");
    
    qihse_column_store_t* store = qihse_column_store_create();
    if (!store) {
        printf("Failed to create column store\n");
        return 1;
    }

    bool ok = true;
    
    // 1. Test Float column with RAW to RLE transition
    qihse_column_create(store, "revenue", QIHSE_COL_TYPE_FLOAT32);
    
    // Append 100,000 values of 1.5f (Will trigger RLE compression at 65536)
    for (int i = 0; i < 100000; i++) {
        qihse_column_append_float32(store, "revenue", 1.5f);
    }
    
    float total_revenue = qihse_column_sum_float32(store, "revenue");
    printf("Total Revenue: %.2f (Expected: 150000.00)\n", total_revenue);
    if (total_revenue < 149999.0f || total_revenue > 150001.0f) {
        printf("FAIL: Float RLE Aggregation Incorrect\n");
        ok = false;
    } else {
        printf("PASS: Float RLE Aggregation\n");
    }

    // 2. Test Integer column with dictionary strings
    qihse_column_create(store, "categories", QIHSE_COL_TYPE_STRING_DICT);
    
    qihse_column_append_string(store, "categories", "Electronics");
    qihse_column_append_string(store, "categories", "Clothing");
    qihse_column_append_string(store, "categories", "Electronics");
    qihse_column_append_string(store, "categories", "Groceries");
    
    // Test Integer accumulation with RAW to RLE transition
    qihse_column_create(store, "sales", QIHSE_COL_TYPE_INT64);
    for (int i = 0; i < 70000; i++) {
        qihse_column_append_int64(store, "sales", 5);
    }
    
    int64_t total_sales = qihse_column_sum_int64(store, "sales");
    printf("Total Sales: %lld (Expected: 350000)\n", (long long)total_sales);
    if (total_sales != 350000) {
        printf("FAIL: Integer RLE Aggregation Incorrect\n");
        ok = false;
    } else {
        printf("PASS: Integer RLE Aggregation\n");
    }

    qihse_column_store_destroy(store);
    
    if (ok) {
        printf("ALL PASS\n");
        return 0;
    }
    return 1;
}
