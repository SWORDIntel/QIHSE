#include "qihse_trinary_trie.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail_malloc;
void* __real_malloc(size_t size);
void* __wrap_malloc(size_t size) {
    if (fail_malloc > 0 && --fail_malloc == 0) return NULL;
    return __real_malloc(size);
}

typedef struct {
    const char** expected;
    size_t count;
    size_t seen;
    size_t stop_after;
} traversal_t;

static bool check_key(const char* key, void* value, size_t size, void* opaque) {
    traversal_t* state = opaque;
    assert(state->seen < state->count);
    assert(strcmp(key, state->expected[state->seen]) == 0);
    assert(size == 1 && value && *(char*)value == 'v');
    ++state->seen;
    return state->seen != state->stop_after;
}

int main(void) {
    qihse_trinary_trie_t* trie = qihse_trinary_trie_create();
    assert(trie);
    char long_key[8193];
    memset(long_key, 'm', sizeof(long_key) - 1);
    long_key[sizeof(long_key) - 1] = '\0';
    char value = 'v';
    const char* inserted[] = {"z", "b", "a", "bc", "ba", "m", long_key, "n"};
    const char* ordered[] = {"a", "b", "ba", "bc", "m", long_key, "n", "z"};
    for (size_t i = 0; i < sizeof(inserted) / sizeof(*inserted); ++i)
        assert(qihse_trinary_trie_insert(trie, inserted[i], &value, 1));

    traversal_t state = {ordered, sizeof(ordered) / sizeof(*ordered), 0, 0};
    assert(qihse_trinary_trie_foreach(trie, check_key, &state));
    assert(state.seen == state.count);

    state.seen = 0;
    state.stop_after = 3;
    assert(qihse_trinary_trie_foreach(trie, check_key, &state));
    assert(state.seen == 3);

    for (int failure = 1; failure <= 2; ++failure) {
        state.seen = 0;
        state.stop_after = 0;
        fail_malloc = failure;
        assert(!qihse_trinary_trie_foreach(trie, check_key, &state));
        assert(state.seen == 0);
        assert(fail_malloc == 0);
    }
    state.seen = 0;
    assert(qihse_trinary_trie_foreach(trie, check_key, &state));
    assert(state.seen == state.count);
    qihse_trinary_trie_destroy(trie);
    puts("trinary trie foreach: PASS");
    return 0;
}
