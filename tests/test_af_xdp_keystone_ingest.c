#define _GNU_SOURCE

#include <assert.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qihse_af_xdp.h"
#include "qihse_auth.h"
#include "qihse_cluster_slot.h"
#include "qihse_keystone.h"
#include "qihse_kv_store.h"

static qihse_user_t *g_operator = NULL;
static qihse_user_t *g_guest = NULL;

static uint32_t build_tcp_frame(uint8_t *buf, uint32_t bufsize,
                                const char *payload, uint32_t payload_len) {
    uint32_t header_len = (uint32_t)(sizeof(struct ether_header) +
                                     sizeof(struct ip) + sizeof(struct tcphdr));
    assert(buf && payload && bufsize >= header_len + payload_len);
    memset(buf, 0, header_len);

    struct ether_header *eth = (struct ether_header *)buf;
    eth->ether_type = htons(ETHERTYPE_IP);

    struct ip *iph = (struct ip *)(buf + sizeof(struct ether_header));
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_src.s_addr = htonl(0x0a0000c9u);
    iph->ip_dst.s_addr = htonl(0x0a000002u);

    struct tcphdr *tcph = (struct tcphdr *)(buf + sizeof(struct ether_header) +
                                            sizeof(struct ip));
    tcph->source = htons(49152);
    tcph->dest = htons(6379);
    tcph->doff = 5;

    memcpy(buf + header_len, payload, payload_len);
    return header_len + payload_len;
}

static uint32_t build_udp_frame(uint8_t *buf, uint32_t bufsize,
                                const char *payload, uint32_t payload_len) {
    uint32_t header_len = (uint32_t)(sizeof(struct ether_header) +
                                     sizeof(struct ip) + sizeof(struct udphdr));
    assert(buf && payload && bufsize >= header_len + payload_len);
    memset(buf, 0, header_len);

    struct ether_header *eth = (struct ether_header *)buf;
    eth->ether_type = htons(ETHERTYPE_IP);

    struct ip *iph = (struct ip *)(buf + sizeof(struct ether_header));
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_src.s_addr = htonl(0x7f000001u);
    iph->ip_dst.s_addr = htonl(0x7f000001u);

    struct udphdr *udph = (struct udphdr *)(buf + sizeof(struct ether_header) +
                                            sizeof(struct ip));
    udph->source = htons(16379);
    udph->dest = htons(16379);
    udph->len = htons((uint16_t)(sizeof(struct udphdr) + payload_len));

    memcpy(buf + header_len, payload, payload_len);
    return header_len + payload_len;
}

static uint8_t *alloc_frame(void) {
    void *frame = NULL;
    assert(posix_memalign(&frame, 4096, 4096) == 0);
    memset(frame, 0, 4096);
    return (uint8_t *)frame;
}

static void test_pointer_contract_and_legacy_unclassified(void) {
    uint8_t *frame = alloc_frame();
    const char *dirty = "leak@corp.internal:Hunter2Pass | src=stealer_dump";
    uint32_t flen = build_tcp_frame(frame, 4096, dirty, (uint32_t)strlen(dirty));

    const char *payload = NULL;
    uint32_t payload_len = 0;
    assert(qihse_af_xdp_extract_tcp_payload(frame, flen, &payload, &payload_len,
                                            NULL, NULL, NULL));
    assert((const uint8_t *)payload >= frame);
    assert((const uint8_t *)payload + payload_len <= frame + 4096);

    qihse_kv_store_t *kv = qihse_kv_store_create();
    assert(kv != NULL);

    /* Historical API remains functional for unclassified data only. */
    assert(qihse_af_xdp_ingest_frame_zero_copy(frame, flen, kv, NULL, 0, 0) >= 1u);
    char *value = qihse_kv_get(kv, "leak@corp.internal");
    assert(value && strstr(value, "pass=Hunter2Pass"));
    free(value);

    /* It must fail closed rather than silently downgrading classified data. */
    assert(qihse_af_xdp_ingest_frame_zero_copy(frame, flen, kv, NULL, 1, 0) == 0u);

    qihse_kv_store_destroy(kv);
    free(frame);
}

static void test_classified_principal_enforcement(void) {
    uint8_t *frame = alloc_frame();
    const char *dirty = "classified@gov.example:ClassifiedPass9";
    uint32_t flen = build_tcp_frame(frame, 4096, dirty, (uint32_t)strlen(dirty));
    qihse_kv_store_t *kv = qihse_kv_store_create();
    assert(kv != NULL);

    assert(qihse_af_xdp_ingest_frame_zero_copy_user(
               frame, flen, kv, NULL, 5, 0, g_guest) == 0u);
    assert(qihse_kv_get_user(kv, "classified@gov.example", g_guest) == NULL);

    assert(qihse_af_xdp_ingest_frame_zero_copy_user(
               frame, flen, kv, NULL, 5, 0, g_operator) >= 1u);
    assert(qihse_kv_get_user(kv, "classified@gov.example", g_guest) == NULL);

    char *value = qihse_kv_get_user(kv, "classified@gov.example", g_operator);
    assert(value && strstr(value, "pass=ClassifiedPass9"));
    free(value);

    qihse_kv_store_destroy(kv);
    free(frame);
}

static void test_slot_distribution(void) {
    static const char *creds[] = {
        "alpha@fin.bank.com:FinPass1!",
        "bravo@corp.internal:CorpPass2#",
        "charlie@gov.defense.gov:GovPass3$",
        "delta@infra.cloud.org:InfraPass4%"
    };
    uint8_t *frame = alloc_frame();
    qihse_kv_store_t *kv = qihse_kv_store_create();
    assert(kv != NULL);

    unsigned seen[QIHSE_CLUSTER_SLOT_COUNT] = {0};
    size_t distinct = 0u;
    for (size_t i = 0; i < sizeof(creds) / sizeof(creds[0]); i++) {
        uint32_t flen = build_tcp_frame(frame, 4096, creds[i], (uint32_t)strlen(creds[i]));
        assert(qihse_af_xdp_ingest_frame_zero_copy_user(
                   frame, flen, kv, NULL, 1, 0, g_operator) >= 1u);

        const char *colon = strchr(creds[i], ':');
        assert(colon != NULL);
        size_t email_len = (size_t)(colon - creds[i]);
        char email[256];
        assert(email_len < sizeof(email));
        memcpy(email, creds[i], email_len);
        email[email_len] = '\0';

        char *value = qihse_kv_get_user(kv, email, g_operator);
        assert(value != NULL);
        const char *slot_tag = strstr(value, "slot=");
        assert(slot_tag != NULL);
        unsigned recorded = UINT32_MAX;
        assert(sscanf(slot_tag, "slot=%u", &recorded) == 1);
        assert(recorded < QIHSE_CLUSTER_SLOT_COUNT);
        assert((uint16_t)recorded == qihse_cluster_key_slot(email, email_len));
        if (!seen[recorded]) {
            seen[recorded] = 1u;
            distinct++;
        }
        free(value);
    }
    assert(distinct >= 2u);

    qihse_kv_store_destroy(kv);
    free(frame);
}

static void test_udp_and_batch(void) {
    uint8_t *frame = alloc_frame();
    qihse_kv_store_t *kv = qihse_kv_store_create();
    assert(kv != NULL);

    const char *udp_dirty = "ops@infra.cloud.org:SecretDevPass123";
    uint32_t flen = build_udp_frame(frame, 4096, udp_dirty, (uint32_t)strlen(udp_dirty));
    const void *payload = NULL;
    uint32_t payload_len = 0;
    assert(qihse_af_xdp_extract_udp_payload(frame, flen, &payload, &payload_len,
                                            NULL, NULL, NULL));
    assert((const uint8_t *)payload >= frame);
    assert((const uint8_t *)payload + payload_len <= frame + 4096);
    assert(qihse_af_xdp_ingest_frame_zero_copy_user(
               frame, flen, kv, NULL, 2, 0, g_operator) >= 1u);

    static const char *batch[] = {
        "k1@bank.com:Pass1",
        "k2@corp.com:Pass2 http://c2.stealer.net/gate.php?id=1",
        "k3@gov.org:Pass3 k4@infra.io:Pass4"
    };
    size_t total = 0u;
    for (size_t i = 0; i < sizeof(batch) / sizeof(batch[0]); i++) {
        flen = build_tcp_frame(frame, 4096, batch[i], (uint32_t)strlen(batch[i]));
        total += qihse_af_xdp_ingest_frame_zero_copy_user(
            frame, flen, kv, NULL, 2, 0, g_operator);
    }
    assert(total >= 4u);

    static const char *emails[] = {
        "k1@bank.com", "k2@corp.com", "k3@gov.org", "k4@infra.io"
    };
    for (size_t i = 0; i < sizeof(emails) / sizeof(emails[0]); i++) {
        char *value = qihse_kv_get_user(kv, emails[i], g_operator);
        assert(value != NULL);
        free(value);
    }

    qihse_kv_store_destroy(kv);
    free(frame);
}

static void test_malformed_and_null_safe(void) {
    qihse_kv_store_t *kv = qihse_kv_store_create();
    assert(kv != NULL);
    uint8_t bad[64] = {0};
    ((struct ether_header *)bad)->ether_type = htons(0x0806);

    assert(qihse_af_xdp_ingest_frame_zero_copy_user(
               bad, sizeof(bad), kv, NULL, 1, 0, g_operator) == 0u);
    assert(qihse_af_xdp_ingest_frame_zero_copy_user(
               bad, 10, kv, NULL, 1, 0, g_operator) == 0u);
    assert(qihse_af_xdp_ingest_frame_zero_copy_user(
               NULL, 0, kv, NULL, 1, 0, g_operator) == 0u);
    assert(qihse_af_xdp_ingest_frame_zero_copy_user(
               bad, sizeof(bad), NULL, NULL, 1, 0, g_operator) == 0u);
    assert(qihse_af_xdp_ingest_keystone_user(
               NULL, kv, NULL, 1, 0, g_operator) == 0u);
    assert(qihse_af_xdp_ingest_keystone_user(
               NULL, NULL, NULL, 1, 0, g_operator) == 0u);

    qihse_kv_store_destroy(kv);
}

int main(void) {
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("AFXDP-Security-Pass1!"));
    g_operator = qihse_auth_get_user(0);
    assert(g_operator != NULL);
    g_guest = qihse_auth_create_user(g_operator, 73, QIHSE_ROLE_GUEST, 0, 0,
                                     "AFXDP-Guest-Pass1!", false);
    assert(g_guest != NULL);

    test_pointer_contract_and_legacy_unclassified();
    test_classified_principal_enforcement();
    test_slot_distribution();
    test_udp_and_batch();
    test_malformed_and_null_safe();

    puts("All AF_XDP zero-copy Keystone authorization tests PASSED");
    return 0;
}
