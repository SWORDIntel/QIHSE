/* Exercise the same semantic/security/concurrency checks while the allocator
 * declines all shrink requests. Production must retain a working cache, not
 * replace a best-effort memory trim with a canonical-load allocation spike. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <malloc.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

void *__real_realloc(void *pointer, size_t bytes);
static unsigned denied_shrinks;
void *__wrap_realloc(void *pointer, size_t bytes) {
  if (pointer && bytes && bytes < malloc_usable_size(pointer)) {
    ++denied_shrinks;
    errno = ENOMEM;
    return NULL;
  }
  return __real_realloc(pointer, bytes);
}
#define main persisted_main
#include "test_codegraph_persisted.c"
#undef main
int main(int argc, char **argv) {
  int status = persisted_main(argc, argv);
  assert(denied_shrinks > 0);
  fprintf(stderr, "Best-effort shrink failures exercised: %u\n",
          denied_shrinks);
  return status;
}
