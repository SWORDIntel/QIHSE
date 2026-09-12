#include "qihse_resp_pubsub.h"

#include <fnmatch.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define QIHSE_PUBSUB_LOG_TOPIC "resp.pubsub"
#define QIHSE_PUBSUB_FNMATCH_MAX 4096u

typedef struct pubsub_client_s {
    void* context;
    qihse_resp_pubsub_delivery_fn delivery;
    struct pubsub_client_s* next;
} pubsub_client_t;

typedef struct pubsub_channel_s {
    char* name;
    size_t len;
    pubsub_client_t* clients;
    struct pubsub_channel_s* next;
} pubsub_channel_t;

typedef struct pubsub_pattern_s {
    char* pattern;
    pubsub_client_t* clients;
    struct pubsub_pattern_s* next;
} pubsub_pattern_t;

typedef struct pubsub_channel_policy_s {
    char* name;
    size_t len;
    uint16_t classification;
    uint16_t sci;
    bool publish_system_only;
    struct pubsub_channel_policy_s* next;
} pubsub_channel_policy_t;

struct qihse_resp_pubsub {
    pthread_rwlock_t lock;
    pubsub_channel_t* channels;
    pubsub_pattern_t* patterns;
    pubsub_channel_policy_t* channel_policies;
    uint16_t classification;
    uint16_t sci;
    qihse_event_stream_t* log;
    pthread_mutex_t log_lock;
    uint64_t messages_published;
};

qihse_resp_pubsub_t* qihse_resp_pubsub_create(const char* log_directory) {
    qihse_resp_pubsub_t* pubsub = calloc(1, sizeof(*pubsub));
    if (!pubsub) return NULL;
    if (pthread_rwlock_init(&pubsub->lock, NULL) != 0 || pthread_mutex_init(&pubsub->log_lock, NULL) != 0) {
        free(pubsub);
        return NULL;
    }
    if (log_directory) {
        pubsub->log = qihse_event_stream_open(log_directory, QIHSE_ES_DURABILITY_NONE, false);
        if (!pubsub->log) pubsub->log = qihse_event_stream_create(log_directory);
    }
    return pubsub;
}

void qihse_resp_pubsub_destroy(qihse_resp_pubsub_t* pubsub) {
    if (!pubsub) return;
    pthread_rwlock_wrlock(&pubsub->lock);
    pubsub_channel_t* channel = pubsub->channels;
    while (channel) {
        pubsub_channel_t* next_channel = channel->next;
        pubsub_client_t* client = channel->clients;
        while (client) {
            pubsub_client_t* next_client = client->next;
            free(client);
            client = next_client;
        }
        free(channel->name);
        free(channel);
        channel = next_channel;
    }
    pubsub_pattern_t* pattern = pubsub->patterns;
    while (pattern) {
        pubsub_pattern_t* next_pattern = pattern->next;
        pubsub_client_t* client = pattern->clients;
        while (client) {
            pubsub_client_t* next_client = client->next;
            free(client);
            client = next_client;
        }
        free(pattern->pattern);
        free(pattern);
        pattern = next_pattern;
    }
    pubsub_channel_policy_t* policy = pubsub->channel_policies;
    while (policy) {
        pubsub_channel_policy_t* next_policy = policy->next;
        free(policy->name);
        free(policy);
        policy = next_policy;
    }
    pubsub->channel_policies = NULL;
    pthread_rwlock_unlock(&pubsub->lock);
    pthread_rwlock_destroy(&pubsub->lock);
    if (pubsub->log) qihse_event_stream_destroy(pubsub->log);
    pthread_mutex_destroy(&pubsub->log_lock);
    free(pubsub);
}

void qihse_resp_pubsub_set_policy(qihse_resp_pubsub_t* pubsub, uint16_t classification, uint16_t sci) {
    if (!pubsub) return;
    pthread_rwlock_wrlock(&pubsub->lock);
    pubsub->classification = classification;
    pubsub->sci = sci;
    pthread_rwlock_unlock(&pubsub->lock);
}

bool qihse_resp_pubsub_channel_allowed(const qihse_resp_pubsub_t* pubsub, qihse_user_t* user) {
    if (!pubsub) return false;
    uint16_t classification;
    uint16_t sci;
    pthread_rwlock_rdlock((pthread_rwlock_t*)&pubsub->lock);
    classification = pubsub->classification;
    sci = pubsub->sci;
    pthread_rwlock_unlock((pthread_rwlock_t*)&pubsub->lock);
    if (!user) return classification == 0 && sci == 0;
    return qihse_auth_can_access(user, classification, sci);
}

void qihse_resp_pubsub_set_channel_policy(qihse_resp_pubsub_t* pubsub,
                                          const char* channel, size_t channel_len,
                                          uint16_t classification, uint16_t sci,
                                          bool publish_system_only) {
    if (!pubsub || !channel || channel_len == 0) return;
    pthread_rwlock_wrlock(&pubsub->lock);
    for (pubsub_channel_policy_t* p = pubsub->channel_policies; p; p = p->next) {
        if (p->len == channel_len && memcmp(p->name, channel, channel_len) == 0) {
            p->classification = classification;
            p->sci = sci;
            p->publish_system_only = publish_system_only;
            pthread_rwlock_unlock(&pubsub->lock);
            return;
        }
    }
    pubsub_channel_policy_t* p = calloc(1, sizeof(*p));
    if (!p) {
        pthread_rwlock_unlock(&pubsub->lock);
        return;
    }
    p->name = malloc(channel_len + 1u);
    if (!p->name) {
        free(p);
        pthread_rwlock_unlock(&pubsub->lock);
        return;
    }
    memcpy(p->name, channel, channel_len);
    p->name[channel_len] = '\0';
    p->len = channel_len;
    p->classification = classification;
    p->sci = sci;
    p->publish_system_only = publish_system_only;
    p->next = pubsub->channel_policies;
    pubsub->channel_policies = p;
    pthread_rwlock_unlock(&pubsub->lock);
}

bool qihse_resp_pubsub_channel_access(const qihse_resp_pubsub_t* pubsub, qihse_user_t* user,
                                      const char* channel, size_t channel_len,
                                      bool publishing) {
    if (!pubsub) return false;
    uint16_t classification;
    uint16_t sci;
    bool system_only = false;
    bool specific = false;
    pthread_rwlock_rdlock((pthread_rwlock_t*)&pubsub->lock);
    for (pubsub_channel_policy_t* p = pubsub->channel_policies; p; p = p->next) {
        if (p->len == channel_len && memcmp(p->name, channel, channel_len) == 0) {
            classification = p->classification;
            sci = p->sci;
            system_only = p->publish_system_only;
            specific = true;
            break;
        }
    }
    if (!specific) {
        classification = pubsub->classification;
        sci = pubsub->sci;
    }
    pthread_rwlock_unlock((pthread_rwlock_t*)&pubsub->lock);
    if (!user) return classification == 0 && sci == 0 && !system_only;
    if (publishing && system_only && qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM) {
        return false;
    }
    return qihse_auth_can_access(user, classification, sci);
}

static pubsub_channel_t* pubsub_find_channel(pubsub_channel_t* head, const char* name, size_t len) {
    for (pubsub_channel_t* channel = head; channel; channel = channel->next) {
        if (channel->len == len && memcmp(channel->name, name, len) == 0) return channel;
    }
    return NULL;
}

static pubsub_pattern_t* pubsub_find_pattern(pubsub_pattern_t* head, const char* pattern, size_t len) {
    for (pubsub_pattern_t* node = head; node; node = node->next) {
        if (strlen(node->pattern) == len && memcmp(node->pattern, pattern, len) == 0) return node;
    }
    return NULL;
}

static bool pubsub_client_list_contains(pubsub_client_t* head, void* context) {
    for (pubsub_client_t* client = head; client; client = client->next) {
        if (client->context == context) return true;
    }
    return false;
}

static bool pubsub_add_client(pubsub_client_t** head, void* context, qihse_resp_pubsub_delivery_fn delivery) {
    pubsub_client_t* client = malloc(sizeof(*client));
    if (!client) return false;
    client->context = context;
    client->delivery = delivery;
    client->next = *head;
    *head = client;
    return true;
}

bool qihse_resp_pubsub_subscribe(qihse_resp_pubsub_t* pubsub, void* client,
                                 qihse_resp_pubsub_delivery_fn delivery,
                                 const char* channel, size_t channel_len) {
    if (!pubsub || !client || !delivery || !channel || channel_len == 0) return false;
    pthread_rwlock_wrlock(&pubsub->lock);
    pubsub_channel_t* node = pubsub_find_channel(pubsub->channels, channel, channel_len);
    if (!node) {
        node = calloc(1, sizeof(*node));
        node->name = malloc(channel_len + 1u);
        if (!node || !node->name) {
            free(node);
            pthread_rwlock_unlock(&pubsub->lock);
            return false;
        }
        memcpy(node->name, channel, channel_len);
        node->name[channel_len] = '\0';
        node->len = channel_len;
        node->next = pubsub->channels;
        pubsub->channels = node;
    }
    bool result = true;
    if (!pubsub_client_list_contains(node->clients, client)) {
        result = pubsub_add_client(&node->clients, client, delivery);
    }
    pthread_rwlock_unlock(&pubsub->lock);
    return result;
}

bool qihse_resp_pubsub_unsubscribe(qihse_resp_pubsub_t* pubsub, void* client,
                                   const char* channel, size_t channel_len) {
    if (!pubsub || !client || !channel || channel_len == 0) return false;
    bool removed = false;
    pthread_rwlock_wrlock(&pubsub->lock);
    pubsub_channel_t** cursor = &pubsub->channels;
    while (*cursor) {
        pubsub_channel_t* node = *cursor;
        if (node->len == channel_len && memcmp(node->name, channel, channel_len) == 0) {
            pubsub_client_t** client_cursor = &node->clients;
            while (*client_cursor) {
                if ((*client_cursor)->context == client) {
                    pubsub_client_t* dead = *client_cursor;
                    *client_cursor = dead->next;
                    free(dead);
                    removed = true;
                    break;
                }
                client_cursor = &(*client_cursor)->next;
            }
            if (!node->clients) {
                *cursor = node->next;
                free(node->name);
                free(node);
            }
            break;
        }
        cursor = &node->next;
    }
    pthread_rwlock_unlock(&pubsub->lock);
    return removed;
}

bool qihse_resp_pubsub_psubscribe(qihse_resp_pubsub_t* pubsub, void* client,
                                  qihse_resp_pubsub_delivery_fn delivery,
                                  const char* pattern, size_t pattern_len) {
    if (!pubsub || !client || !delivery || !pattern || pattern_len == 0) return false;
    pthread_rwlock_wrlock(&pubsub->lock);
    pubsub_pattern_t* node = pubsub_find_pattern(pubsub->patterns, pattern, pattern_len);
    if (!node) {
        node = calloc(1, sizeof(*node));
        node->pattern = malloc(pattern_len + 1u);
        if (!node || !node->pattern) {
            free(node);
            pthread_rwlock_unlock(&pubsub->lock);
            return false;
        }
        memcpy(node->pattern, pattern, pattern_len);
        node->pattern[pattern_len] = '\0';
        node->next = pubsub->patterns;
        pubsub->patterns = node;
    }
    bool result = true;
    if (!pubsub_client_list_contains(node->clients, client)) {
        result = pubsub_add_client(&node->clients, client, delivery);
    }
    pthread_rwlock_unlock(&pubsub->lock);
    return result;
}

bool qihse_resp_pubsub_punsubscribe(qihse_resp_pubsub_t* pubsub, void* client,
                                    const char* pattern, size_t pattern_len) {
    if (!pubsub || !client || !pattern || pattern_len == 0) return false;
    bool removed = false;
    pthread_rwlock_wrlock(&pubsub->lock);
    pubsub_pattern_t** cursor = &pubsub->patterns;
    while (*cursor) {
        pubsub_pattern_t* node = *cursor;
        if (strlen(node->pattern) == pattern_len && memcmp(node->pattern, pattern, pattern_len) == 0) {
            pubsub_client_t** client_cursor = &node->clients;
            while (*client_cursor) {
                if ((*client_cursor)->context == client) {
                    pubsub_client_t* dead = *client_cursor;
                    *client_cursor = dead->next;
                    free(dead);
                    removed = true;
                    break;
                }
                client_cursor = &(*client_cursor)->next;
            }
            if (!node->clients) {
                *cursor = node->next;
                free(node->pattern);
                free(node);
            }
            break;
        }
        cursor = &node->next;
    }
    pthread_rwlock_unlock(&pubsub->lock);
    return removed;
}

void qihse_resp_pubsub_detach_client(qihse_resp_pubsub_t* pubsub, void* client) {
    if (!pubsub || !client) return;
    pthread_rwlock_wrlock(&pubsub->lock);
    pubsub_channel_t** channel_cursor = &pubsub->channels;
    while (*channel_cursor) {
        pubsub_channel_t* node = *channel_cursor;
        pubsub_client_t** client_cursor = &node->clients;
        while (*client_cursor) {
            if ((*client_cursor)->context == client) {
                pubsub_client_t* dead = *client_cursor;
                *client_cursor = dead->next;
                free(dead);
            } else {
                client_cursor = &(*client_cursor)->next;
            }
        }
        if (!node->clients) {
            *channel_cursor = node->next;
            free(node->name);
            free(node);
        } else {
            channel_cursor = &node->next;
        }
    }
    pubsub_pattern_t** pattern_cursor = &pubsub->patterns;
    while (*pattern_cursor) {
        pubsub_pattern_t* node = *pattern_cursor;
        pubsub_client_t** client_cursor = &node->clients;
        while (*client_cursor) {
            if ((*client_cursor)->context == client) {
                pubsub_client_t* dead = *client_cursor;
                *client_cursor = dead->next;
                free(dead);
            } else {
                client_cursor = &(*client_cursor)->next;
            }
        }
        if (!node->clients) {
            *pattern_cursor = node->next;
            free(node->pattern);
            free(node);
        } else {
            pattern_cursor = &node->next;
        }
    }
    pthread_rwlock_unlock(&pubsub->lock);
}

static bool pubsub_append_log(qihse_resp_pubsub_t* pubsub,
                              const char* channel, size_t channel_len,
                              const char* message, size_t message_len) {
    if (!pubsub->log) return true; /* in-memory mode: nothing to persist */
    if (channel_len > UINT32_MAX / 2u || message_len > UINT32_MAX / 2u) return false;
    size_t payload_size = sizeof(uint32_t) + channel_len + message_len;
    uint8_t* payload = malloc(payload_size);
    if (!payload) return false;
    uint32_t encoded_len = (uint32_t)channel_len;
    memcpy(payload, &encoded_len, sizeof(encoded_len));
    memcpy(payload + sizeof(encoded_len), channel, channel_len);
    memcpy(payload + sizeof(encoded_len) + channel_len, message, message_len);
    pthread_mutex_lock(&pubsub->log_lock);
    bool stored = qihse_event_stream_append(pubsub->log, QIHSE_PUBSUB_LOG_TOPIC, payload, payload_size);
    pthread_mutex_unlock(&pubsub->log_lock);
    free(payload);
    return stored;
}

uint64_t qihse_resp_pubsub_publish(qihse_resp_pubsub_t* pubsub, qihse_user_t* publisher,
                                   const char* channel, size_t channel_len,
                                   const char* message, size_t message_len) {
    (void)publisher; /* clearance already enforced by caller via channel_allowed() */
    if (!pubsub || !channel || channel_len == 0 || !message) return 0;
    pubsub_append_log(pubsub, channel, channel_len, message, message_len);
    char glob_buffer[QIHSE_PUBSUB_FNMATCH_MAX];
    const char* glob_channel = NULL;
    if (channel_len < sizeof(glob_buffer)) {
        memcpy(glob_buffer, channel, channel_len);
        glob_buffer[channel_len] = '\0';
        glob_channel = glob_buffer;
    }
    uint64_t receivers = 0;
    pthread_rwlock_rdlock(&pubsub->lock);
    pubsub_channel_t* node = pubsub_find_channel(pubsub->channels, channel, channel_len);
    for (pubsub_client_t* client = node ? node->clients : NULL; client; client = client->next) {
        if (client->delivery(client->context, false, NULL, 0, channel, channel_len, message, message_len)) {
            receivers++;
        }
    }
    for (pubsub_pattern_t* pattern = pubsub->patterns; pattern; pattern = pattern->next) {
        if (!glob_channel) break;
        for (pubsub_client_t* client = pattern->clients; client; client = client->next) {
            if (fnmatch(pattern->pattern, glob_channel, 0) != 0) continue;
            size_t pattern_len = strlen(pattern->pattern);
            if (client->delivery(client->context, true, pattern->pattern, pattern_len,
                                 channel, channel_len, message, message_len)) {
                receivers++;
            }
        }
    }
    pthread_rwlock_unlock(&pubsub->lock);
    __atomic_add_fetch(&pubsub->messages_published, 1u, __ATOMIC_RELAXED);
    return receivers;
}

qihse_event_stream_t* qihse_resp_pubsub_log(const qihse_resp_pubsub_t* pubsub) {
    return pubsub ? pubsub->log : NULL;
}

size_t qihse_resp_pubsub_channel_subscribers(const qihse_resp_pubsub_t* pubsub,
                                             const char* channel, size_t channel_len) {
    if (!pubsub || !channel || channel_len == 0) return 0;
    size_t count = 0;
    pthread_rwlock_rdlock((pthread_rwlock_t*)&pubsub->lock);
    pubsub_channel_t* node = pubsub_find_channel(pubsub->channels, channel, channel_len);
    for (pubsub_client_t* client = node ? node->clients : NULL; client; client = client->next) count++;
    pthread_rwlock_unlock((pthread_rwlock_t*)&pubsub->lock);
    return count;
}

size_t qihse_resp_pubsub_pattern_subscribers(const qihse_resp_pubsub_t* pubsub, const char* pattern, size_t pattern_len) {
    if (!pubsub || !pattern || pattern_len == 0) return 0;
    size_t count = 0;
    pthread_rwlock_rdlock((pthread_rwlock_t*)&pubsub->lock);
    pubsub_pattern_t* node = pubsub_find_pattern(pubsub->patterns, pattern, pattern_len);
    for (pubsub_client_t* client = node ? node->clients : NULL; client; client = client->next) count++;
    pthread_rwlock_unlock((pthread_rwlock_t*)&pubsub->lock);
    return count;
}

size_t qihse_resp_pubsub_pattern_subscription_count(const qihse_resp_pubsub_t* pubsub) {
    if (!pubsub) return 0;
    size_t count = 0;
    pthread_rwlock_rdlock((pthread_rwlock_t*)&pubsub->lock);
    for (pubsub_pattern_t* pattern = pubsub->patterns; pattern; pattern = pattern->next) {
        for (pubsub_client_t* client = pattern->clients; client; client = client->next) count++;
    }
    pthread_rwlock_unlock((pthread_rwlock_t*)&pubsub->lock);
    return count;
}

size_t qihse_resp_pubsub_channel_count(const qihse_resp_pubsub_t* pubsub, const char* glob) {
    if (!pubsub) return 0;
    size_t count = 0;
    pthread_rwlock_rdlock((pthread_rwlock_t*)&pubsub->lock);
    for (pubsub_channel_t* node = pubsub->channels; node; node = node->next) {
        if (glob && fnmatch(glob, node->name, 0) != 0) continue;
        count++;
    }
    pthread_rwlock_unlock((pthread_rwlock_t*)&pubsub->lock);
    return count;
}

size_t qihse_resp_pubsub_channels(const qihse_resp_pubsub_t* pubsub, const char* glob,
                                  char** names, size_t cap) {
    if (!pubsub || !names || cap == 0) return 0;
    size_t written = 0;
    pthread_rwlock_rdlock((pthread_rwlock_t*)&pubsub->lock);
    for (pubsub_channel_t* node = pubsub->channels; node && written < cap; node = node->next) {
        if (glob && fnmatch(glob, node->name, 0) != 0) continue;
        names[written] = strdup(node->name);
        if (names[written]) written++;
    }
    pthread_rwlock_unlock((pthread_rwlock_t*)&pubsub->lock);
    return written;
}
