#ifndef QIHSE_RESP_PUBSUB_H
#define QIHSE_RESP_PUBSUB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_auth.h"
#include "qihse_event_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qihse_resp_pubsub qihse_resp_pubsub_t;

/* Delivery callback: invoked once per matching subscription while the broker
 * registry read lock is held. Must not call back into the broker and must not
 * block indefinitely. Returns false if the message could not be delivered
 * (e.g. dead socket); failed deliveries are not counted as receivers. */
typedef bool (*qihse_resp_pubsub_delivery_fn)(
    void* client_context,
    bool pattern,
    const char* pattern_value, size_t pattern_len,
    const char* channel, size_t channel_len,
    const char* message, size_t message_len);

/* log_directory: when non-NULL, every PUBLISH is appended to a durable
 * qihse_event_stream_t under that directory (topic "resp.pubsub") so messages
 * are replayable by other subsystems (UWP STREAM target, CDC). NULL keeps the
 * broker in-memory only. */
qihse_resp_pubsub_t* qihse_resp_pubsub_create(const char* log_directory);
void qihse_resp_pubsub_destroy(qihse_resp_pubsub_t* pubsub);

/* Channel security policy: every channel carries this (classification, SCI)
 * tag. SUBSCRIBE and PUBLISH require the caller's clearance to dominate it.
 * Default policy is (0, 0) — unclassified. */
void qihse_resp_pubsub_set_policy(qihse_resp_pubsub_t* pubsub, uint16_t classification, uint16_t sci);
bool qihse_resp_pubsub_channel_allowed(const qihse_resp_pubsub_t* pubsub, qihse_user_t* user);

bool qihse_resp_pubsub_subscribe(qihse_resp_pubsub_t* pubsub, void* client,
                                 qihse_resp_pubsub_delivery_fn delivery,
                                 const char* channel, size_t channel_len);
bool qihse_resp_pubsub_unsubscribe(qihse_resp_pubsub_t* pubsub, void* client,
                                   const char* channel, size_t channel_len);
bool qihse_resp_pubsub_psubscribe(qihse_resp_pubsub_t* pubsub, void* client,
                                  qihse_resp_pubsub_delivery_fn delivery,
                                  const char* pattern, size_t pattern_len);
bool qihse_resp_pubsub_punsubscribe(qihse_resp_pubsub_t* pubsub, void* client,
                                    const char* pattern, size_t pattern_len);
/* Remove every subscription held by client. Must be called before the
 * client's session storage is freed. */
void qihse_resp_pubsub_detach_client(qihse_resp_pubsub_t* pubsub, void* client);

/* Returns the number of local subscribers the message was delivered to. */
uint64_t qihse_resp_pubsub_publish(qihse_resp_pubsub_t* pubsub, qihse_user_t* publisher,
                                   const char* channel, size_t channel_len,
                                   const char* message, size_t message_len);

qihse_event_stream_t* qihse_resp_pubsub_log(const qihse_resp_pubsub_t* pubsub);

size_t qihse_resp_pubsub_channel_subscribers(const qihse_resp_pubsub_t* pubsub,
                                             const char* channel, size_t channel_len);
size_t qihse_resp_pubsub_pattern_subscribers(const qihse_resp_pubsub_t* pubsub,
                                             const char* pattern, size_t pattern_len);
size_t qihse_resp_pubsub_pattern_subscription_count(const qihse_resp_pubsub_t* pubsub);
/* Fill names with up to cap channel names that have at least one subscriber
 * (optionally filtered by fnmatch glob). Returns the number written. */
size_t qihse_resp_pubsub_channels(const qihse_resp_pubsub_t* pubsub, const char* glob,
                                  char** names, size_t cap);
/* Number of channels with at least one subscriber (optionally fnmatch-filtered). */
size_t qihse_resp_pubsub_channel_count(const qihse_resp_pubsub_t* pubsub, const char* glob);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_RESP_PUBSUB_H */
