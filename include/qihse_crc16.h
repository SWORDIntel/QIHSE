#ifndef QIHSE_CRC16_H
#define QIHSE_CRC16_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_CLUSTER_SLOT_COUNT 16384u

typedef enum {
    QIHSE_CRC16_SCALAR = 0,
    QIHSE_CRC16_SLICE8 = 1,
    QIHSE_CRC16_PCLMUL = 2
} qihse_crc16_backend_t;

void qihse_crc16_init(void);
uint16_t qihse_crc16_xmodem(const void* data, size_t len);
uint16_t qihse_cluster_key_slot(const void* key, size_t key_len);
qihse_crc16_backend_t qihse_crc16_backend(void);
const char* qihse_crc16_backend_name(void);

#ifdef __cplusplus
}
#endif

#endif
