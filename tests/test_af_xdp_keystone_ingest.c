/*
 * Idea 3 — AF_XDP Kernel-Bypass Zero-Copy Log Ingestion Pipeline.
 *
 * Verifies that qihse_af_xdp_ingest_frame_zero_copy() and the AF_XDP RX-ring
 * path wire incoming packet UMEM buffers directly into
 * qihse_keystone_ingest_dirty_logs() without userspace copies, and that
 * extracted artifacts are distributed across the 16,384 CRC16 cluster hash
 * slots.
 *
 * No real AF_XDP socket is required: the zero-copy frame ingest helper accepts
 * a raw Ethernet frame living in a caller-owned buffer that emulates a UMEM
 * frame. The TCP/UDP payload pointer returned by the zero-copy parsers must
 * stay inside that buffer (no memcpy), and Keystone must scan it in place.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include "qihse_af_xdp.h"
#include "qihse_kv_store.h"
#include "qihse_keystone.h"
#include "qihse_cluster_slot.h"
#include "qihse_crc16.h"

/* ------------------------------------------------------------------ *
 * Helpers to build raw Ethernet/IPv4/TCP and Ethernet/IPv4/UDP frames
 * directly inside a caller-owned buffer that emulates a UMEM frame.
 * ------------------------------------------------------------------ */
static uint32_t build_tcp_frame(uint8_t *buf, uint32_t bufsize,
                                const char *payload, uint32_t payload_len) {
    assert(bufsize >= sizeof(struct ether_header) + sizeof(struct ip) +
                       sizeof(struct tcphdr) + payload_len);

    memset(buf, 0, sizeof(struct ether_header) + sizeof(struct ip) +
                   sizeof(struct tcphdr));

    struct ether_header *eth = (struct ether_header *)buf;
    eth->ether_type = htons(ETHERTYPE_IP);

    struct ip *iph = (struct ip *)(buf + sizeof(struct ether_header));
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_src.s_addr = htonl(0x0A0000C9); /* 10.0.0.201 */
    iph->ip_dst.s_addr = htonl(0x0A000002); /* 10.0.0.2   */

    struct tcphdr *tcph = (struct tcphdr *)(buf + sizeof(struct ether_header) +
                                            sizeof(struct ip));
    tcph->source = htons(49152);
    tcph->dest = htons(6379);
    tcph->doff = 5;

    uint32_t off = sizeof(struct ether_header) + sizeof(struct ip) +
                   sizeof(struct tcphdr);
    memcpy(buf + off, payload, payload_len);
    return off + payload_len;
}

static uint32_t build_udp_frame(uint8_t *buf, uint32_t bufsize,
                                const char *payload, uint32_t payload_len) {
    assert(bufsize >= sizeof(struct ether_header) + sizeof(struct ip) +
                       sizeof(struct udphdr) + payload_len);

    memset(buf, 0, sizeof(struct ether_header) + sizeof(struct ip) +
                   sizeof(struct udphdr));

    struct ether_header *eth = (struct ether_header *)buf;
    eth->ether_type = htons(ETHERTYPE_IP);

    struct ip *iph = (struct ip *)(buf + sizeof(struct ether_header));
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_src.s_addr = htonl(0x7F000001); /* 127.0.0.1 */
    iph->ip_dst.s_addr = htonl(0x7F000001);

    struct udphdr *udph = (struct udphdr *)(buf + sizeof(struct ether_header) +
                                            sizeof(struct ip));
    udph->source = htons(16379);
    udph->dest = htons(16379);
    udph->len = htons((uint16_t)(sizeof(struct udphdr) + payload_len));

    uint32_t off = sizeof(struct ether_header) + sizeof(struct ip) +
                   sizeof(struct udphdr);
    memcpy(buf + off, payload, payload_len);
    return off + payload_len;
}

/* ------------------------------------------------------------------ *
 * Test 1: Zero-copy contract — the payload pointer handed to Keystone
 * must lie inside the UMEM-emulating buffer; no memcpy is performed.
 * ------------------------------------------------------------------ */
static void test_zero_copy_pointer_contract(void) {
    printf("Testing AF_XDP zero-copy pointer contract (payload stays in UMEM)...\n");

    /* Use a posix_memalign'd region to emulate a real UMEM frame so the
     * pointer arithmetic mirrors the production path. */
    void *umem_frame = NULL;
    assert(posix_memalign(&umem_frame, 4096, 4096) == 0);
    uint8_t *frame = (uint8_t *)umem_frame;

    const char *dirty =
        "leak@corp.internal:Hunter2Pass | src=stealer_dump";
    uint32_t flen = build_tcp_frame(frame, 4096, dirty, (uint32_t)strlen(dirty));

    /* Capture the payload pointer that the extractor produces and prove it
     * lives inside the UMEM-emulating frame buffer. */
    const char *payload = NULL;
    uint32_t payload_len = 0;
    bool ok = qihse_af_xdp_extract_tcp_payload(frame, flen,
                                               &payload, &payload_len,
                                               NULL, NULL, NULL);
    assert(ok);
    assert((const uint8_t *)payload >= frame &&
           (const uint8_t *)payload + payload_len <= frame + 4096);
    printf("  -> TCP payload @ %p inside UMEM frame [%p, %p) — zero-copy confirmed\n",
           (const void *)payload, (const void *)frame,
           (const void *)(frame + 4096));

    qihse_kv_store_t *kv = qihse_kv_store_create();
    assert(kv != NULL);

    size_t n = qihse_af_xdp_ingest_frame_zero_copy(frame, flen, kv, NULL, 1, 0);
    assert(n >= 1);
    printf("  -> Ingested %zu artifact(s) directly from UMEM frame\n", n);

    char *val = qihse_kv_get(kv, "leak@corp.internal");
    assert(val != NULL);
    assert(strstr(val, "pass=Hunter2Pass") != NULL);
    assert(strstr(val, "slot=") != NULL);
    printf("  -> KV record: %s\n", val);
    free(val);

    qihse_kv_store_destroy(kv);
    free(umem_frame);
}

/* ------------------------------------------------------------------ *
 * Test 2: Distribution across the 16,384 CRC16 cluster hash slots.
 * Ingest a batch of distinct email artifacts and confirm every record
 * lands in a slot < 16384 and that the slot recorded in the KV value
 * matches an independent qihse_cluster_key_slot() computation.
 * ------------------------------------------------------------------ */
static void test_slot_distribution_16384(void) {
    printf("Testing artifact distribution across 16,384 cluster hash slots...\n");

    void *umem_frame = NULL;
    assert(posix_memalign(&umem_frame, 4096, 4096) == 0);
    uint8_t *frame = (uint8_t *)umem_frame;

    qihse_kv_store_t *kv = qihse_kv_store_create();
    assert(kv != NULL);

    /* A diverse set of email:password pairs that should hash to many
     * different CRC16 slots across the 16,384-slot space. */
    const char *creds[] = {
        "alpha@fin.bank.com:FinPass1!",
        "bravo@corp.internal:CorpPass2#",
        "charlie@gov.defense.gov:GovPass3$",
        "delta@infra.cloud.org:InfraPass4%",
        "echo@consumer.shop:ConsPass5^",
        "foxtrot@eu.bank.net:EurPass6&",
        "golf@asia.corp.io:AsiaPass7*",
        "hotel@state.gov.us:StatePass8(",
        "india@telecom.net:TelPass9)",
        "juliet@health.med:HealthPass0_"
    };
    const size_t n_creds = sizeof(creds) / sizeof(creds[0]);

    size_t total = 0;
    int distinct_slots[16384];
    memset(distinct_slots, 0, sizeof(distinct_slots));
    int used_slot_count = 0;

    for (size_t i = 0; i < n_creds; i++) {
        /* Build a fresh dirty-log payload around each credential. */
        char payload[512];
        int written = snprintf(payload, sizeof(payload),
                                "DUMP line %zu victim=%s source=af_xdp_umem",
                                i, creds[i]);
        assert(written > 0 && written < (int)sizeof(payload));

        uint32_t flen = build_tcp_frame(frame, 4096, payload, (uint32_t)strlen(payload));
        size_t n = qihse_af_xdp_ingest_frame_zero_copy(frame, flen, kv, NULL, 1, 0);
        assert(n >= 1);
        total += n;
    }
    assert(total >= n_creds);
    printf("  -> Ingested %zu artifacts from %zu TCP frames\n", total, n_creds);

    /* Verify each credential was indexed and that the slot recorded in the
     * KV value matches an independent CRC16 slot computation, and is < 16384. */
    for (size_t i = 0; i < n_creds; i++) {
        /* Extract just the email portion (lowercased) — Keystone lowercases
         * the key before slotting. */
        char email[256];
        const char *colon = strchr(creds[i], ':');
        assert(colon != NULL);
        size_t elen = (size_t)(colon - creds[i]);
        assert(elen < sizeof(email));
        memcpy(email, creds[i], elen);
        email[elen] = '\0';
        for (size_t c = 0; c < elen; c++) {
            if (email[c] >= 'A' && email[c] <= 'Z') email[c] = (char)(email[c] - 'A' + 'a');
        }

        char *val = qihse_kv_get(kv, email);
        assert(val != NULL);

        const char *slot_tag = strstr(val, "slot=");
        assert(slot_tag != NULL);
        unsigned recorded_slot = 0;
        int parsed = sscanf(slot_tag, "slot=%u", &recorded_slot);
        assert(parsed == 1);
        assert(recorded_slot < QIHSE_CLUSTER_SLOT_COUNT);

        uint16_t expected = qihse_cluster_key_slot(email, strlen(email));
        assert((uint16_t)recorded_slot == expected);

        if (!distinct_slots[recorded_slot]) {
            distinct_slots[recorded_slot] = 1;
            used_slot_count++;
        }
        free(val);
    }

    printf("  -> %d distinct CRC16 slots used across %zu artifacts (all < %u)\n",
           used_slot_count, n_creds, QIHSE_CLUSTER_SLOT_COUNT);
    assert(used_slot_count >= 2); /* sanity: not all collapsed to one slot */

    qihse_kv_store_destroy(kv);
    free(umem_frame);
}

/* ------------------------------------------------------------------ *
 * Test 3: UDP frame ingestion path (Cluster Bus carrying dirty-log
 * shards). Verifies the UDP fallback in the zero-copy ingest helper.
 * ------------------------------------------------------------------ */
static void test_udp_zero_copy_ingest(void) {
    printf("Testing AF_XDP UDP zero-copy ingestion into Keystone...\n");

    void *umem_frame = NULL;
    assert(posix_memalign(&umem_frame, 4096, 4096) == 0);
    uint8_t *frame = (uint8_t *)umem_frame;

    const char *udp_dirty = "ops@infra.cloud.org:SecretDevPass123";
    uint32_t flen = build_udp_frame(frame, 4096, udp_dirty, (uint32_t)strlen(udp_dirty));

    /* Confirm UDP payload pointer stays inside the UMEM-emulating frame. */
    const void *payload = NULL;
    uint32_t payload_len = 0;
    bool ok = qihse_af_xdp_extract_udp_payload(frame, flen,
                                               &payload, &payload_len,
                                               NULL, NULL, NULL);
    assert(ok);
    assert((const uint8_t *)payload >= frame &&
           (const uint8_t *)payload + payload_len <= frame + 4096);

    qihse_kv_store_t *kv = qihse_kv_store_create();
    assert(kv != NULL);

    size_t n = qihse_af_xdp_ingest_frame_zero_copy(frame, flen, kv, NULL, 1, 0);
    assert(n >= 1);
    printf("  -> UDP frame ingested %zu artifact(s)\n", n);

    char *val = qihse_kv_get(kv, "ops@infra.cloud.org");
    assert(val != NULL);
    assert(strstr(val, "pass=SecretDevPass123") != NULL);
    free(val);

    qihse_kv_store_destroy(kv);
    free(umem_frame);
}

/* ------------------------------------------------------------------ *
 * Test 4: Non-IP / malformed frames must be silently skipped and
 * produce zero artifacts, never crashing the ingest pipeline.
 * ------------------------------------------------------------------ */
static void test_malformed_frame_safe_skip(void) {
    printf("Testing AF_XDP malformed-frame safe skip...\n");

    qihse_kv_store_t *kv = qihse_kv_store_create();
    assert(kv != NULL);

    /* ARP-ish frame (ether_type != IPv4) */
    uint8_t bad[64];
    memset(bad, 0, sizeof(bad));
    struct ether_header *eth = (struct ether_header *)bad;
    eth->ether_type = htons(0x0806); /* ARP */
    size_t n = qihse_af_xdp_ingest_frame_zero_copy(bad, sizeof(bad), kv, NULL, 1, 0);
    assert(n == 0);

    /* Tiny truncated frame */
    n = qihse_af_xdp_ingest_frame_zero_copy(bad, 10, kv, NULL, 1, 0);
    assert(n == 0);

    /* NULL inputs */
    n = qihse_af_xdp_ingest_frame_zero_copy(NULL, 0, kv, NULL, 1, 0);
    assert(n == 0);
    n = qihse_af_xdp_ingest_frame_zero_copy(bad, sizeof(bad), NULL, NULL, 1, 0);
    assert(n == 0);

    printf("  -> Malformed and NULL inputs safely returned 0 artifacts\n");

    qihse_kv_store_destroy(kv);
}

/* ------------------------------------------------------------------ *
 * Test 5: Multi-frame batch ingestion accumulates artifacts across
 * frames and the total matches the sum of per-frame counts.
 * ------------------------------------------------------------------ */
static void test_batch_accumulation(void) {
    printf("Testing multi-frame batch accumulation...\n");

    void *umem_frame = NULL;
    assert(posix_memalign(&umem_frame, 4096, 4096) == 0);
    uint8_t *frame = (uint8_t *)umem_frame;

    qihse_kv_store_t *kv = qihse_kv_store_create();
    assert(kv != NULL);

    const char *batch[] = {
        "k1@bank.com:Pass1",
        "k2@corp.com:Pass2 http://c2.stealer.net/gate.php?id=1",
        "k3@gov.org:Pass3 k4@infra.io:Pass4"
    };
    const size_t n_batch = sizeof(batch) / sizeof(batch[0]);

    size_t per_frame_sum = 0;
    for (size_t i = 0; i < n_batch; i++) {
        uint32_t flen = build_tcp_frame(frame, 4096, batch[i], (uint32_t)strlen(batch[i]));
        size_t n = qihse_af_xdp_ingest_frame_zero_copy(frame, flen, kv, NULL, 1, 0);
        assert(n >= 1);
        per_frame_sum += n;
    }
    assert(per_frame_sum >= 4); /* at least 4 distinct emails + 1 URL */

    /* Confirm all four emails are present in the KV store. */
    const char *emails[] = { "k1@bank.com", "k2@corp.com", "k3@gov.org", "k4@infra.io" };
    for (size_t i = 0; i < 4; i++) {
        char *v = qihse_kv_get(kv, emails[i]);
        assert(v != NULL);
        free(v);
    }
    printf("  -> Batch ingested %zu artifacts across %zu frames\n",
           per_frame_sum, n_batch);

    qihse_kv_store_destroy(kv);
    free(umem_frame);
}

/* ------------------------------------------------------------------ *
 * Test 6: The full RX-ring poll path (qihse_af_xdp_ingest_keystone)
 * degrades gracefully when no AF_XDP context is available (e.g. in
 * unprivileged CI). It must return 0 without crashing.
 * ------------------------------------------------------------------ */
static void test_ingest_keystone_null_safe(void) {
    printf("Testing qihse_af_xdp_ingest_keystone NULL-safety...\n");
    qihse_kv_store_t *kv = qihse_kv_store_create();
    assert(kv != NULL);

    assert(qihse_af_xdp_ingest_keystone(NULL, kv, NULL, 1, 0) == 0);
    assert(qihse_af_xdp_ingest_keystone(NULL, NULL, NULL, 1, 0) == 0);

    qihse_kv_store_destroy(kv);
    printf("  -> NULL ctx handled gracefully (returned 0)\n");
}

int main(void) {
    printf("==============================================================\n");
    printf("  QIHSE AF_XDP Zero-Copy Keystone Ingestion Pipeline Tests   \n");
    printf("==============================================================\n");

    test_zero_copy_pointer_contract();
    test_slot_distribution_16384();
    test_udp_zero_copy_ingest();
    test_malformed_frame_safe_skip();
    test_batch_accumulation();
    test_ingest_keystone_null_safe();

    printf("\nAll AF_XDP Zero-Copy Keystone Ingestion Tests PASSED!\n");
    return 0;
}
