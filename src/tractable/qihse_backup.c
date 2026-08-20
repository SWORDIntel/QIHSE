#include "qihse_backup.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

/* Simple FNV-1a hash as checksum (not crypto, but sufficient for integrity) */
static uint64_t fnv1a_hash(const uint8_t* data, size_t len) {
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

/* Backup file format:
 * [8-byte magic: "QIHSEBAK"]
 * [4-byte version]
 * [4-byte type]
 * [8-byte start_lsn]
 * [8-byte end_lsn]
 * [8-byte timestamp]
 * [8-byte checksum (FNV-1a of data section)]
 * [8-byte data_length]
 * [data: sequence of (key_len, key, val_len, val) tuples]
 */
#define BACKUP_MAGIC "QIHSEBAK"
#define BACKUP_VERSION 1

static int write_backup_header(FILE* f, backup_type_t type, uint64_t start_lsn, uint64_t end_lsn, uint64_t checksum, uint64_t data_len) {
    fwrite(BACKUP_MAGIC, 1, 8, f);
    uint32_t ver = BACKUP_VERSION; fwrite(&ver, 4, 1, f);
    uint32_t t = (uint32_t)type; fwrite(&t, 4, 1, f);
    fwrite(&start_lsn, 8, 1, f);
    fwrite(&end_lsn, 8, 1, f);
    uint64_t ts = (uint64_t)time(NULL); fwrite(&ts, 8, 1, f);
    fwrite(&checksum, 8, 1, f);
    fwrite(&data_len, 8, 1, f);
    return 0;
}

static int read_backup_header(FILE* f, backup_type_t* type, uint64_t* start_lsn, uint64_t* end_lsn, uint64_t* timestamp, uint64_t* checksum, uint64_t* data_len) {
    char magic[8];
    if (fread(magic, 1, 8, f) != 8) return -1;
    if (memcmp(magic, BACKUP_MAGIC, 8) != 0) return -1;
    uint32_t ver; if (fread(&ver, 4, 1, f) != 1) return -1;
    uint32_t t; if (fread(&t, 4, 1, f) != 1) return -1;
    if (type) *type = (backup_type_t)t;
    if (fread(start_lsn, 8, 1, f) != 1) return -1;
    if (fread(end_lsn, 8, 1, f) != 1) return -1;
    if (fread(timestamp, 8, 1, f) != 1) return -1;
    if (fread(checksum, 8, 1, f) != 1) return -1;
    if (fread(data_len, 8, 1, f) != 1) return -1;
    return 0;
}

int qihse_backup_full(qihse_kv_store_t* kv, const char* output_path, qihse_backup_info_t* info) {
    if (!output_path) return -1;
    FILE* f = fopen(output_path, "wb");
    if (!f) return -1;
    
    /* Collect all KV pairs and compute checksum */
    /* Since we don't have a direct iterator API, we write a placeholder data section */
    /* In a real implementation, we'd iterate over all keys in the KV store */
    uint64_t checksum = 0;
    uint64_t data_len = 0;
    
    /* Write header first with placeholder, then seek back to update */
    write_backup_header(f, BACKUP_FULL, 0, 0, 0, 0);
    
    /* Write data section - for now, write empty data */
    /* TODO: iterate KV store and write all key-value pairs */
    
    /* Update header with actual values */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    data_len = (uint64_t)(file_size - 48); /* header is 48 bytes */
    
    /* Recompute checksum over data */
    fseek(f, 48, SEEK_SET);
    uint8_t* data = (uint8_t*)malloc(data_len > 0 ? data_len : 1);
    if (data_len > 0) fread(data, 1, data_len, f);
    checksum = fnv1a_hash(data, data_len);
    free(data);
    
    /* Seek back and update checksum and data_len */
    fseek(f, 32, SEEK_SET); /* checksum at offset 32 (8+4+4+8+8=32) */
    fwrite(&checksum, 8, 1, f);
    fwrite(&data_len, 8, 1, f);
    
    fclose(f);
    
    if (info) {
        info->type = BACKUP_FULL;
        info->path = strdup(output_path);
        info->start_lsn = 0;
        info->end_lsn = 0;
        info->timestamp = time(NULL);
        info->size_bytes = (size_t)file_size;
        char cksum_str[32];
        snprintf(cksum_str, sizeof(cksum_str), "%016lx", (unsigned long)checksum);
        info->checksum = strdup(cksum_str);
    }
    return 0;
}

int qihse_backup_incremental(qihse_kv_store_t* kv, const char* output_path, uint64_t since_lsn, qihse_backup_info_t* info) {
    if (!output_path) return -1;
    FILE* f = fopen(output_path, "wb");
    if (!f) return -1;
    
    write_backup_header(f, BACKUP_INCREMENTAL, since_lsn, 0, 0, 0);
    
    /* TODO: iterate KV store and write only keys modified since since_lsn */
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    uint64_t data_len = (uint64_t)(file_size - 48);
    uint64_t checksum = 0;
    
    if (data_len > 0) {
        fseek(f, 48, SEEK_SET);
        uint8_t* data = (uint8_t*)malloc(data_len);
        fread(data, 1, data_len, f);
        checksum = fnv1a_hash(data, data_len);
        free(data);
    }
    
    fseek(f, 32, SEEK_SET);
    fwrite(&checksum, 8, 1, f);
    fwrite(&data_len, 8, 1, f);
    
    fclose(f);
    
    if (info) {
        info->type = BACKUP_INCREMENTAL;
        info->path = strdup(output_path);
        info->start_lsn = since_lsn;
        info->end_lsn = 0;
        info->timestamp = time(NULL);
        info->size_bytes = (size_t)file_size;
        char cksum_str[32];
        snprintf(cksum_str, sizeof(cksum_str), "%016lx", (unsigned long)checksum);
        info->checksum = strdup(cksum_str);
    }
    return 0;
}

int qihse_restore(qihse_kv_store_t* kv, const char* backup_path) {
    if (!backup_path) return -1;
    FILE* f = fopen(backup_path, "rb");
    if (!f) return -1;
    
    backup_type_t type;
    uint64_t start_lsn, end_lsn, timestamp, checksum, data_len;
    if (read_backup_header(f, &type, &start_lsn, &end_lsn, &timestamp, &checksum, &data_len) != 0) {
        fclose(f);
        return -1;
    }
    
    /* Verify checksum */
    if (data_len > 0) {
        uint8_t* data = (uint8_t*)malloc(data_len);
        if (fread(data, 1, data_len, f) != data_len) { free(data); fclose(f); return -1; }
        uint64_t actual = fnv1a_hash(data, data_len);
        free(data);
        if (actual != checksum) { fclose(f); return -1; }
    }
    
    /* TODO: replay data into KV store */
    fclose(f);
    return 0;
}

int qihse_backup_list(const char* dir, qihse_backup_info_t** out_backups, size_t* out_count) {
    if (!dir || !out_backups || !out_count) return -1;
    DIR* d = opendir(dir);
    if (!d) return -1;
    
    size_t cap = 8;
    qihse_backup_info_t* backups = (qihse_backup_info_t*)calloc(cap, sizeof(qihse_backup_info_t));
    size_t count = 0;
    
    struct dirent* entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
        FILE* f = fopen(path, "rb");
        if (!f) continue;
        backup_type_t type;
        uint64_t start_lsn, end_lsn, timestamp, checksum, data_len;
        if (read_backup_header(f, &type, &start_lsn, &end_lsn, &timestamp, &checksum, &data_len) == 0) {
            if (count >= cap) { cap *= 2; backups = (qihse_backup_info_t*)realloc(backups, cap * sizeof(qihse_backup_info_t)); }
            backups[count].type = type;
            backups[count].path = strdup(path);
            backups[count].start_lsn = start_lsn;
            backups[count].end_lsn = end_lsn;
            backups[count].timestamp = (time_t)timestamp;
            char cksum_str[32];
            snprintf(cksum_str, sizeof(cksum_str), "%016lx", (unsigned long)checksum);
            backups[count].checksum = strdup(cksum_str);
            count++;
        }
        fclose(f);
    }
    closedir(d);
    *out_backups = backups;
    *out_count = count;
    return 0;
}

int qihse_backup_verify(const char* backup_path) {
    if (!backup_path) return -1;
    FILE* f = fopen(backup_path, "rb");
    if (!f) return -1;
    
    backup_type_t type;
    uint64_t start_lsn, end_lsn, timestamp, checksum, data_len;
    if (read_backup_header(f, &type, &start_lsn, &end_lsn, &timestamp, &checksum, &data_len) != 0) {
        fclose(f);
        return -1;
    }
    
    if (data_len > 0) {
        uint8_t* data = (uint8_t*)malloc(data_len);
        if (fread(data, 1, data_len, f) != data_len) { free(data); fclose(f); return -1; }
        uint64_t actual = fnv1a_hash(data, data_len);
        free(data);
        if (actual != checksum) { fclose(f); return -1; }
    }
    
    fclose(f);
    return 0;
}

void qihse_backup_info_free(qihse_backup_info_t* info) {
    if (!info) return;
    free(info->path);
    free(info->checksum);
}
