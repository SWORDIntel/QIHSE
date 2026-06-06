#include "qihse_event_stream.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/file.h>
struct qihse_event_stream {
    char *log_directory;
};

qihse_event_stream_t* qihse_event_stream_create(const char* log_directory) {
    if (!log_directory) return NULL;
    qihse_event_stream_t* stream = malloc(sizeof(qihse_event_stream_t));
    if (!stream) return NULL;
    stream->log_directory = strdup(log_directory);
    if (!stream->log_directory) {
        free(stream);
        return NULL;
    }
    return stream;
}

void qihse_event_stream_destroy(qihse_event_stream_t* stream) {
    if (stream) {
        free(stream->log_directory);
        free(stream);
    }
}

bool qihse_event_stream_append(qihse_event_stream_t* stream, const char* topic, const uint8_t* payload, size_t size) {
    if (!stream || !topic || !payload) return false;
    if (size == 0) return true;
    
    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/%s.log", stream->log_directory, topic);
    
    int fd = open(filepath, O_RDWR | O_CREAT, 0666);
    if (fd < 0) return false;
    
    // Acquire exclusive lock to prevent race conditions during state transitions
    // (fstat, ftruncate, and mmap)
    if (flock(fd, LOCK_EX) < 0) {
        close(fd);
        return false;
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        flock(fd, LOCK_UN);
        close(fd);
        return false;
    }
    
    off_t old_size = st.st_size;
    if (ftruncate(fd, old_size + size) < 0) {
        flock(fd, LOCK_UN);
        close(fd);
        return false;
    }
    
    long page_size = sysconf(_SC_PAGE_SIZE);
    // Properly align pa_offset to page size, without assuming page size is a power of 2,
    // thereby avoiding zero-copy mmap misalignment issues.
    off_t pa_offset = (old_size / (off_t)page_size) * (off_t)page_size;
    size_t map_size = size + (old_size - pa_offset);
    
    void* map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, pa_offset);
    if (map == MAP_FAILED) {
        if (ftruncate(fd, old_size) < 0) {
            // Ignore ftruncate rollback error
        }
        flock(fd, LOCK_UN);
        close(fd);
        return false;
    }
    
    memcpy((char*)map + (old_size - pa_offset), payload, size);
    
    munmap(map, map_size);
    flock(fd, LOCK_UN);
    close(fd);
    
    return true;
}

bool qihse_event_stream_consume_zero_copy(qihse_event_stream_t* stream, const char* topic, uint64_t offset, int network_socket_fd, size_t count) {
    if (!stream || !topic || network_socket_fd < 0) return false;
    
    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/%s.log", stream->log_directory, topic);
    
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) return false;
    
    off_t offset_copy = (off_t)offset;
    
    ssize_t sent = sendfile(network_socket_fd, fd, &offset_copy, count);
    
    close(fd);
    
    return sent >= 0;
}
