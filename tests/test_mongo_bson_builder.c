#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_mongo_wire.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail_calloc_countdown;
static int fail_malloc_once;
static int fail_realloc_once;

void* __real_calloc(size_t count, size_t size);
void* __real_malloc(size_t size);
void* __real_realloc(void* ptr, size_t size);

void* __wrap_calloc(size_t count, size_t size) {
    if (fail_calloc_countdown > 0 && --fail_calloc_countdown == 0) return NULL;
    return __real_calloc(count, size);
}

void* __wrap_malloc(size_t size) {
    if (fail_malloc_once) { fail_malloc_once = 0; return NULL; }
    return __real_malloc(size);
}

void* __wrap_realloc(void* ptr, size_t size) {
    if (fail_realloc_once) { fail_realloc_once = 0; return NULL; }
    return __real_realloc(ptr, size);
}

static void test_builder_length_and_views(void) {
    bson_t* doc = bson_create();
    assert(doc);
    assert(bson_append_int32(doc, "x", 17) == 0);
    size_t size = bson_size(doc);
    assert(size == doc->len + 1u);
    assert(bson_size(doc) == size);
    const uint8_t* data = bson_data(doc);
    assert(data && bson_size(doc) == size);
    int32_t declared = 0;
    memcpy(&declared, data, sizeof(declared));
    assert((size_t)declared == size && data[size - 1u] == 0);

    bson_t serialized = {
        .data = (uint8_t*)data,
        .len = size,
        .cap = size
    };
    assert(bson_size(&serialized) == size);
    assert(bson_data(&serialized) == data);
    bson_t* copy = bson_copy(&serialized);
    assert(copy && bson_size(copy) == size);
    assert(memcmp(bson_data(copy), data, size) == 0);

    bson_t* parent = bson_create();
    assert(parent && bson_append_document(parent, "nested", copy) == 0);
    size_t parent_size = bson_size(parent);
    const uint8_t* parent_data = bson_data(parent);
    assert(parent_data && parent_size == bson_size(parent));
    bson_t parsed = {
        .data = (uint8_t*)parent_data,
        .len = parent_size,
        .cap = parent_size
    };
    bson_element_t nested;
    assert(bson_find_element(&parsed, "nested", &nested) == 0);
    assert(nested.type == BSON_DOCUMENT && nested.v.doc.len == (int32_t)size);
    assert(memcmp(nested.v.doc.data, data, size) == 0);

    bson_destroy(parent);
    bson_destroy(copy);
    bson_destroy(doc);
}

static void test_allocation_failures(void) {
    fail_calloc_countdown = 2;
    assert(bson_create() == NULL); /* data allocation fails after the struct */
    fail_calloc_countdown = 0;

    bson_t* src = bson_create();
    assert(src && bson_append_int32(src, "v", 1) == 0);
    fail_malloc_once = 1;
    assert(bson_copy(src) == NULL);

    bson_t* growing = bson_create();
    assert(growing);
    char text[1024];
    memset(text, 'z', sizeof(text) - 1u);
    text[sizeof(text) - 1u] = '\0';
    fail_realloc_once = 1;
    assert(bson_append_string(growing, "large", text) == -1);
    assert(bson_size(growing) == 0);
    assert(bson_data(growing) == NULL);
    bson_destroy(growing); /* failed growth retains the original allocation */
    bson_destroy(src);
}

static void test_transactional_mutation(void) {
    bson_t* doc = bson_create();
    char payload[220];
    memset(payload, 'p', sizeof(payload) - 1u);
    payload[sizeof(payload) - 1u] = '\0';
    assert(doc && bson_append_string(doc, "v", payload) == 0);
    const size_t old_size = bson_size(doc);
    uint8_t old_bytes[256];
    assert(old_size <= sizeof(old_bytes));
    memcpy(old_bytes, bson_data(doc), old_size);

    bson_element_t replacement = {.type = BSON_STRING, .v.str = payload};
    fail_realloc_once = 1;
    assert(bson_set_field(doc, "other", &replacement, NULL) == -1);
    assert(bson_size(doc) == old_size);
    assert(memcmp(bson_data(doc), old_bytes, old_size) == 0);

    fail_calloc_countdown = 1;
    bson_remove_key(doc, "v");
    fail_calloc_countdown = 0;
    assert(bson_size(doc) == old_size);
    assert(memcmp(bson_data(doc), old_bytes, old_size) == 0);

    bson_destroy(doc);
}

int main(void) {
    test_builder_length_and_views();
    test_allocation_failures();
    test_transactional_mutation();
    puts("test_mongo_bson_builder: all assertions passed");
    return 0;
}
