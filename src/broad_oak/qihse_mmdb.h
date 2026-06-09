#ifndef QIHSE_MMDB_H
#define QIHSE_MMDB_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Pure-C MaxMind MMDB binary format parser.
 * No external dependencies — reads the .mmdb file directly.
 *
 * Spec: https://maxmind.github.io/MaxMind-DB/
 */

typedef struct {
    uint8_t*  data;
    size_t    data_len;

    /* Parsed metadata */
    uint32_t  ip_version;
    uint32_t  record_size;     /* 28 or 32 bits */
    uint32_t  node_count;
    uint32_t  node_byte_size;  /* record_size * 2 / 8 */
    size_t    search_tree_size;
    size_t    data_section_offset;
} qihse_mmdb_t;

/*
 * Open and parse an MMDB file.  Returns NULL on failure.
 */
qihse_mmdb_t* qihse_mmdb_open(const char* path);

/*
 * Close and free an MMDB handle.
 */
void qihse_mmdb_close(qihse_mmdb_t* db);

/*
 * Look up an IPv4 or IPv6 address string and walk the data map by key_path.
 * key_path is a NULL-terminated array of strings, e.g.:
 *   {"country", "iso_code", NULL}
 *   {"city", "names", "en", NULL}
 *   {"autonomous_system_organization", NULL}
 *
 * Writes result into out (NUL-terminated). Returns true on success.
 */
bool qihse_mmdb_lookup_string(qihse_mmdb_t* db,
                              const char*   ip,
                              const char**  key_path,
                              char*         out,
                              size_t        out_len);

#endif /* QIHSE_MMDB_H */
