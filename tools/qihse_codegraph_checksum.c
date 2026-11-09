#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_codegraph_checksum.h"
#include "codegraph_xxh3/include/qihse_xxh3.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static pthread_once_t backend_once = PTHREAD_ONCE_INIT;
static const qx3_backend *backend;
static void select_backend(void) { backend = qx3_backend_get("auto"); }
static bool active(qihse_user_t *u) {
  if (u && qihse_auth_user_is_active(u) && qihse_auth_can_access(u, 0, 0))
    return true;
  errno = EACCES;
  return false;
}
static bool known(cg_checksum_algorithm a) {
  return a == CG_CHECKSUM_SHA256 || a == CG_CHECKSUM_XXH3_128;
}
const char *cg_checksum_algorithm_name(cg_checksum_algorithm a) {
  return a == CG_CHECKSUM_SHA256     ? "sha256"
         : a == CG_CHECKSUM_XXH3_128 ? "xxh3-128"
                                     : NULL;
}
bool cg_checksum_valid(const cg_snapshot_checksum *c) {
  if (!c || !known(c->algorithm))
    return false;
  size_t n = c->algorithm == CG_CHECKSUM_SHA256 ? 64u : 32u;
  if (strnlen(c->hex, sizeof c->hex) != n)
    return false;
  for (size_t i = 0; i < n; i++)
    if (!((c->hex[i] >= '0' && c->hex[i] <= '9') ||
          (c->hex[i] >= 'a' && c->hex[i] <= 'f')))
      return false;
  return true;
}
static void hex_digest(const unsigned char *bytes, size_t n, char out[65]) {
  static const char h[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = h[bytes[i] >> 4];
    out[2 * i + 1] = h[bytes[i] & 15];
  }
  out[2 * n] = 0;
}
bool cg_snapshot_checksum_buffer_user(const void *bytes, size_t length,
                                      qihse_user_t *user,
                                      cg_checksum_algorithm algorithm,
                                      cg_snapshot_checksum *out) {
  if (!active(user))
    return false;
  if (!out || (!bytes && length) || !known(algorithm)) {
    errno = EINVAL;
    return false;
  }
  cg_snapshot_checksum value = {.algorithm = algorithm};
  if (algorithm == CG_CHECKSUM_XXH3_128) {
    pthread_once(&backend_once, select_backend);
    if (!backend) {
      errno = ENOTSUP;
      return false;
    }
    qx3_hex(qx3_hash128(backend, bytes, length), value.hex);
  } else {
    unsigned char digest[32];
    unsigned n = 0;
    if (EVP_Digest(bytes, length, digest, &n, EVP_sha256(), NULL) != 1 ||
        n != 32) {
      errno = EIO;
      return false;
    }
    hex_digest(digest, n, value.hex);
  }
  if (!active(user))
    return false;
  *out = value;
  return true;
}
static bool same(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
         a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
         a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
         a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
         a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
bool cg_snapshot_checksum_stream_user(FILE *source, qihse_user_t *user,
                                      cg_checksum_algorithm algorithm,
                                      cg_snapshot_checksum *out) {
  if (!active(user))
    return false;
  struct stat before, after;
  if (!source || !out || !known(algorithm) || fstat(fileno(source), &before) ||
      !S_ISREG(before.st_mode) || before.st_uid != geteuid() ||
      before.st_nlink != 1 || before.st_size < 0 ||
      (uint64_t)before.st_size > (UINT64_C(64) << 30)) {
    errno = EINVAL;
    return false;
  }
  EVP_MD_CTX *sha = NULL;
  qx3_stream *xxh = NULL;
  unsigned char *block = malloc(65536);
  bool ok = block != NULL;
  if (algorithm == CG_CHECKSUM_XXH3_128) {
    pthread_once(&backend_once, select_backend);
    xxh = backend ? qx3_stream_create(backend, 0) : NULL;
    ok = ok && xxh;
  } else {
    sha = EVP_MD_CTX_new();
    ok = ok && sha && EVP_DigestInit_ex(sha, EVP_sha256(), NULL) == 1;
  }
  for (off_t off = 0; ok && off < before.st_size;) {
    if (!active(user)) {
      ok = false;
      break;
    }
    size_t want = (uint64_t)(before.st_size - off) < 65536
                      ? (size_t)(before.st_size - off)
                      : 65536;
    ssize_t n = pread(fileno(source), block, want, off);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      ok = false;
      break;
    }
    ok = xxh ? qx3_stream_update(xxh, block, (size_t)n) == 0
             : EVP_DigestUpdate(sha, block, (size_t)n) == 1;
    off += n;
  }
  cg_snapshot_checksum value = {.algorithm = algorithm};
  if (ok && xxh)
    qx3_hex(qx3_stream_digest(xxh), value.hex);
  else if (ok) {
    unsigned char digest[32];
    unsigned n = 0;
    ok = EVP_DigestFinal_ex(sha, digest, &n) == 1 && n == 32;
    if (ok)
      hex_digest(digest, n, value.hex);
  }
  EVP_MD_CTX_free(sha);
  qx3_stream_free(xxh);
  free(block);
  if (!active(user))
    return false;
  if (!ok || fstat(fileno(source), &after) || !same(&before, &after)) {
    errno = EIO;
    return false;
  }
  *out = value;
  return true;
}
bool cg_snapshot_checksum_file_user(const char *path, qihse_user_t *user,
                                    cg_checksum_algorithm algorithm,
                                    cg_snapshot_checksum *out) {
  if (!active(user))
    return false;
  if (!path) {
    errno = EINVAL;
    return false;
  }
  int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0)
    return false;
  FILE *source = fdopen(fd, "rb");
  if (!source) {
    close(fd);
    return false;
  }
  bool ok = cg_snapshot_checksum_stream_user(source, user, algorithm, out);
  int error = errno;
  if (fclose(source) && ok) {
    ok = false;
    error = EIO;
  }
  errno = error;
  return ok;
}
