#ifndef QIHSE_EVENT_STREAM_H
#define QIHSE_EVENT_STREAM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Opaque handle for the QIHSE Event Stream (Commit Log).
 */
typedef struct qihse_event_stream qihse_event_stream_t;

/**
 * @brief Initializes the Event Stream broker, mapping log files into the OS Page Cache.
 * @param log_directory Path to store the immutable mmap segments.
 */
qihse_event_stream_t* qihse_event_stream_create(const char* log_directory);

/**
 * @brief Safely unmaps segments and destroys the broker handle.
 */
void qihse_event_stream_destroy(qihse_event_stream_t* stream);

/**
 * @brief Appends an immutable message to a specific topic log.
 * Write occurs directly into the mmap'd memory boundary.
 */
bool qihse_event_stream_append(qihse_event_stream_t* stream, const char* topic, const uint8_t* payload, size_t size);

/**
 * @brief Streams log data directly to a network socket using Zero-Copy DMA (sendfile).
 * The CPU does not touch the payload; it is transferred from the Page Cache to the NIC.
 * 
 * @param stream The stream instance.
 * @param topic The topic to read from.
 * @param offset The starting byte offset in the log.
 * @param network_socket_fd The active downstream TCP socket.
 * @param count Number of bytes to transmit.
 */
bool qihse_event_stream_consume_zero_copy(qihse_event_stream_t* stream, const char* topic, uint64_t offset, int network_socket_fd, size_t count);

#endif /* QIHSE_EVENT_STREAM_H */
