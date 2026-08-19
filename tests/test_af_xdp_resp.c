#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include "qihse_af_xdp.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#include "qihse_crc16.h"

static void test_extract_tcp_resp_frame() {
    printf("Testing AF_XDP TCP RESP frame extraction...\n");

    uint8_t packet[256];
    memset(packet, 0, sizeof(packet));

    struct ether_header *eth = (struct ether_header *)packet;
    eth->ether_type = htons(ETHERTYPE_IP);

    struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_src.s_addr = htonl(0x0A000001); // 10.0.0.1
    iph->ip_dst.s_addr = htonl(0x0A000002); // 10.0.0.2

    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    tcph->source = htons(49152);
    tcph->dest = htons(6379);
    tcph->doff = 5;

    const char *resp_payload = "*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n";
    size_t payload_len = strlen(resp_payload);
    memcpy(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr), resp_payload, payload_len);

    uint32_t total_len = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + payload_len;

    const char *extracted_payload = NULL;
    uint32_t extracted_len = 0;
    uint32_t src_ip = 0;
    uint16_t src_port = 0, dst_port = 0;

    bool ok = qihse_af_xdp_extract_tcp_payload(
        packet, total_len,
        &extracted_payload, &extracted_len,
        &src_ip, &src_port, &dst_port
    );

    assert(ok);
    assert(extracted_len == payload_len);
    assert(memcmp(extracted_payload, resp_payload, payload_len) == 0);
    assert(src_ip == 0x0A000001);
    assert(src_port == 49152);
    assert(dst_port == 6379);

    printf("  -> TCP payload extraction OK (dst_port=6379, len=%u)\n", extracted_len);
}

static void test_extract_udp_cluster_bus_frame() {
    printf("Testing AF_XDP UDP Cluster Bus frame extraction...\n");

    uint8_t packet[256];
    memset(packet, 0, sizeof(packet));

    struct ether_header *eth = (struct ether_header *)packet;
    eth->ether_type = htons(ETHERTYPE_IP);

    struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_src.s_addr = htonl(0x7F000001); // 127.0.0.1
    iph->ip_dst.s_addr = htonl(0x7F000001);

    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    udph->source = htons(16379);
    udph->dest = htons(16379);
    udph->len = htons(sizeof(struct udphdr) + 16);

    const char *bus_payload = "QIHSE_HEARTBEAT";
    memcpy(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr), bus_payload, 15);

    uint32_t total_len = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + 15;

    const void *extracted_payload = NULL;
    uint32_t extracted_len = 0;
    uint32_t src_ip = 0;
    uint16_t src_port = 0, dst_port = 0;

    bool ok = qihse_af_xdp_extract_udp_payload(
        packet, total_len,
        &extracted_payload, &extracted_len,
        &src_ip, &src_port, &dst_port
    );

    assert(ok);
    assert(extracted_len == 15);
    assert(memcmp(extracted_payload, bus_payload, 15) == 0);
    assert(dst_port == 16379);

    printf("  -> UDP Cluster Bus extraction OK (dst_port=16379, len=%u)\n", extracted_len);
}

static void test_af_xdp_kv_ingress() {
    printf("Testing AF_XDP frame to Black Hole KV Store execution...\n");

    qihse_kv_store_t *store = qihse_kv_store_create();
    assert(store != NULL);

    // Simulate decoded command execution from AF_XDP frame
    const char *key = "xdp_metric_key";
    const char *val = "xdp_fast_val";

    uint16_t slot = qihse_cluster_key_slot(key, strlen(key));
    assert(slot < QIHSE_CLUSTER_SLOT_COUNT);

    bool set_ok = qihse_kv_set(store, key, val, 0, 0);
    assert(set_ok);

    char *ret = qihse_kv_get_user(store, key, NULL);
    assert(ret != NULL);
    assert(strcmp(ret, val) == 0);
    free(ret);

    qihse_kv_store_destroy(store);
    printf("  -> Ingress execution into KV store OK (slot=%u)\n", (unsigned)slot);
}

int main() {
    printf("====================================================\n");
    printf("  QIHSE eBPF / AF_XDP Kernel-Bypass Ingress Tests   \n");
    printf("====================================================\n");

    test_extract_tcp_resp_frame();
    test_extract_udp_cluster_bus_frame();
    test_af_xdp_kv_ingress();

    printf("\nAll AF_XDP Kernel-Bypass Ingress Tests PASSED!\n");
    return 0;
}
