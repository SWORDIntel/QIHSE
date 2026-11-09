/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_codegraph_json.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static size_t checks;
static void accept(const char *text) {
    struct json_object *obj = cg_json_parse_object(text, strlen(text));
    assert(obj);
    json_object_put(obj);
    checks++;
}
static void reject_size(const char *text, size_t length) {
    struct json_object *obj = cg_json_parse_object(text, length);
    assert(!obj);
    checks++;
}
static void reject(const char *text) { reject_size(text, strlen(text)); }

int main(void) {
    const char *valid[] = {
        "{\"unknown\":\"\\ud800\"}",
        "{\"unknown\":\"\\udc00\"}",
        "{\"unknown\":\"\\ud800\\u0000\"}",
        "{}",
        "{\"Foo\":1,\"foo\":2,\"é\":3,\"é\":4}",
        " \n\t{\"freshness\":\"filesystem-content-v1\"}\r\n",
        "{\"λ\":\"λ and 😀\",\"escaped\":\"\\u03bb \\ud83d\\ude00\"}",
        "{\"a\\\"b\":1,\"a:b\":2,\"a/b\":3,\"a\\\\b\":4}",
        "{\"unknown\":{\"duplicate\":1,\"duplicate\":2},\"array\":[true,false,null,{},[]]}",
        "{\"unknown\":\"escaped zero \\u0000 and braces } : \\\" , [\"}",
        "{\"a\":-0,\"b\":-12.5,\"c\":1.2e+30,\"d\":1E-3,\"e\":0}",
        "{\"nested\":[{\"a\":\"colon: comma, braces{} brackets[]\"}, [1,2,3]]}"};
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++)
        accept(valid[i]);
    const char *invalid[] = {"",
                             " ",
                             "[]",
                             "null",
                             "true",
                             "1",
                             "\"object\"",
                             "{}{}",
                             "{} junk",
                             "{\"freshness\":\"bad\",\"freshness\":\"filesystem-content-v1\"}",
                             "{\"freshness\":1,\"\\u0066reshness\":2}",
                             "{\"\\u0066reshness\":1,\"freshness\":2}",
                             "{\"a/b\":1,\"a\\/b\":2}",
                             "{\"a\\\"b\":1,\"a\\u0022b\":2}",
                             "{\"λ\":1,\"\\u03bb\":2}",
                             "{\"\\ud800\":1,\"\\ufffd\":2}",
                             "{\"\\ud83d\\ude00\":1,\"😀\":2}",
                             "{\"\\u0000key\":1}",
                             "{\"key\\u0000suffix\":1}",
                             "{\"a\":1,}",
                             "{,}",
                             "{\"a\" 1}",
                             "{\"a\":}",
                             "{\"a\":[1,]}",
                             "{\"a\":NaN}",
                             "{\"a\":Infinity}",
                             "{\"a\":-Infinity}",
                             "{\"a\":01}",
                             "{\"a\":+1}",
                             "{\"a\":1.}",
                             "{\"a\":.1}",
                             "{\"a\":1e}",
                             "{\"a\":1e+}",
                             "{\"a\":--1}",
                             "{/* comment */\"a\":1}",
                             "{\"a\":1}// comment",
                             "{\"a\":undefined}",
                             "{\"a\":\"bad\\q\"}",

                             "{\"a\":\"\\u12\"}",
                             "{\"a\":\"line\nbreak\"}",
                             "{\"a\":\"\xc0\xaf\"}",
                             "{\"a\":\"\xed\xa0\x80\"}",
                             "{\"a\":\"\xf4\x90\x80\x80\"}",
                             "{\"a\":\"\xe2\x82\"}"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        reject(invalid[i]);
    assert(!cg_json_parse_object(NULL, 1));
    checks++;
    const char embedded[] = "{\"a\":1}\0{\"a\":2}";
    reject_size(embedded, sizeof(embedded) - 1);
    const char *truncation =
        "{\"freshness\":\"filesystem-content-v1\",\"unknown\":[{\"a\":\"λ\\\"quoted\"},42]}";
    for (size_t length = 0; length < strlen(truncation); length++)
        reject_size(truncation, length);
    accept(truncation);
    char deep[1024];
    size_t n = 0;
    memcpy(deep + n, "{\"a\":", 5);
    n += 5;
    for (unsigned i = 0; i < 128; i++)
        deep[n++] = '[';
    deep[n++] = '0';
    for (unsigned i = 0; i < 128; i++)
        deep[n++] = ']';
    deep[n++] = '}';
    reject_size(deep, n);
    char *large = malloc(CG_JSON_MAX_BYTES + 1);
    assert(large);
    memset(large, ' ', CG_JSON_MAX_BYTES + 1);
    large[0] = '{';
    large[1] = '}';
    struct json_object *obj = cg_json_parse_object(large, CG_JSON_MAX_BYTES);
    assert(obj);
    json_object_put(obj);
    checks++;
    reject_size(large, CG_JSON_MAX_BYTES + 1);
    free(large);
    /* Every one-byte truncation/mutation is independently bounded. */
    const char *seed = "{\"a\":{\"b\":[1,true,\"x\"]},\"c\":2}";
    for (size_t i = 0; i < strlen(seed); i++) {
        char mutated[128];
        strcpy(mutated, seed);
        mutated[i] = '\0';
        reject_size(mutated, strlen(seed));
    }
    /* Non-NUL-terminated slices end exactly at an inaccessible guard page. */
    long page_size = sysconf(_SC_PAGESIZE);
    assert(page_size > 0 && strlen(truncation) < (size_t)page_size);
    unsigned char *mapping = mmap(NULL, (size_t)page_size * 2, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(mapping != MAP_FAILED);
    assert(mprotect(mapping + page_size, (size_t)page_size, PROT_NONE) == 0);
    for (size_t length = 0; length <= strlen(truncation); length++) {
        char *slice = (char *)mapping + page_size - length;
        memcpy(slice, truncation, length);
        struct json_object *guarded = cg_json_parse_object(slice, length);
        assert((guarded != NULL) == (length == strlen(truncation)));
        if (guarded)
            json_object_put(guarded);
        checks++;
    }
    assert(munmap(mapping, (size_t)page_size * 2) == 0);
    /* Fixed-seed malformed corpus exercises every byte value and short length. */
    uint32_t random_state = UINT32_C(0x25b416a1);
    for (size_t trial = 0; trial < 4096; trial++) {
        char bytes[128];
        size_t length = trial % sizeof(bytes);
        for (size_t i = 0; i < length; i++) {
            random_state ^= random_state << 13;
            random_state ^= random_state >> 17;
            random_state ^= random_state << 5;
            bytes[i] = (char)random_state;
        }
        struct json_object *arbitrary = cg_json_parse_object(bytes, length);
        if (arbitrary)
            json_object_put(arbitrary);
        checks++;
    }
    printf("CodeGraph bounded JSON parser: %zu checks passed\n", checks);
    return 0;
}
