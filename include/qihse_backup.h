#ifndef QIHSE_BACKUP_H
#define QIHSE_BACKUP_H

#include "qihse_kv_store.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BACKUP_FULL = 0,
    BACKUP_INCREMENTAL = 1,
    BACKUP_WAL = 2
} backup_type_t;

typedef struct {
    backup_type_t type;
    char* path;
    uint64_t start_lsn;
    uint64_t end_lsn;
    time_t timestamp;
    size_t size_bytes;
    char* checksum;
} qihse_backup_info_t;

int qihse_backup_full(qihse_kv_store_t* kv, const char* output_path, qihse_backup_info_t* info);
int qihse_backup_incremental(qihse_kv_store_t* kv, const char* output_path, uint64_t since_lsn, qihse_backup_info_t* info);
int qihse_restore(qihse_kv_store_t* kv, const char* backup_path);
int qihse_backup_list(const char* dir, qihse_backup_info_t** out_backups, size_t* out_count);
int qihse_backup_verify(const char* backup_path);
void qihse_backup_info_free(qihse_backup_info_t* info);

#ifdef __cplusplus
}
#endif
#endif
