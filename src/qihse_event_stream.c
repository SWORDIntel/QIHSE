#include "qihse_event_stream.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

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
    
    char filepath[1024];
    snprintf(filepath, sizeof(filepath), "%s/%s.log", stream->log_directory, topic);
    
    FILE* f = fopen(filepath, "ab");
    if (!f) return false;
    
    size_t written = fwrite(payload, 1, size, f);
    fclose(f);
    
    return written == size;
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
