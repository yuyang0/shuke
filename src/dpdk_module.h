#ifndef __DPDK_MODULE_H__
#define __DPDK_MODULE_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>
#include <rte_timer.h>
#include <rte_kni.h>

#ifdef IP_FRAG
#include <rte_ip_frag.h>
#endif

#define MAX_PKT_BURST     32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */


struct mbuf_table {
    uint16_t len;
    struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct numaNode_s;

typedef struct lcore_conf {
    uint16_t lcore_id;

    /*
     * one port one rx queue and one tx queue
     * rx queue id is equal to tx queue id
     */
    uint16_t nr_ports;
    uint16_t port_id_list[RTE_MAX_ETHPORTS];
    uint16_t queue_id_list[RTE_MAX_ETHPORTS];

    struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
    struct mbuf_table kni_tx_mbufs[RTE_MAX_ETHPORTS];

    struct numaNode_s *node;
    uint16_t ipv4_packet_id;
    // used to implement time function
    uint64_t tsc_hz;
    uint64_t start_tsc;
    uint64_t start_us;

#ifdef IP_FRAG
    struct rte_ip_frag_tbl *frag_tbl;
    struct rte_ip_frag_death_row death_row;
#endif

    // statistics
    int64_t nr_req;                   // number of processed requests
    int64_t nr_dropped;

    int64_t received_req;
} __rte_cache_aligned lcore_conf_t;

struct hw_features {
    uint8_t rx_csum;
    uint8_t tx_csum_ip;
    uint8_t tx_csum_l4;
};

typedef struct port_info {
    // ethernet address for this port
    struct ether_addr eth_addr;
    // ethernet address(string format)
    char eth_addr_s[ETHER_ADDR_FMT_SIZE];
    uint8_t port_id;

    int nr_lcore;
    int *lcore_list;

    uint32_t ipv4_addr;
    struct hw_features hw_features;
} __rte_cache_aligned port_info_t;

void init_dpdk_eal();
int init_dpdk_module(void);
int start_dpdk_threads(void);
int cleanup_dpdk_module(void);

uint64_t rte_tsc_ustime();
uint64_t rte_tsc_mstime();
uint64_t rte_tsc_time();

struct rte_mbuf *get_mbuf();
/*----------------------------------------------
 *     kni
 *---------------------------------------------*/
void sk_init_kni_module(struct rte_mempool *mbuf_pool);
void init_kni_module(void);
int cleanup_kni_module();
int kni_ifconfig_all();
bool is_all_veth_up();
int kni_send_single_packet(lcore_conf_t *qconf, struct rte_mbuf *m, uint8_t port);

void
sk_kni_process(lcore_conf_t *qconf, uint8_t port_id, uint16_t queue_id, struct rte_mbuf **pkts_burst, unsigned count);

#ifdef SK_TEST
void initTestDpdkEal();
#endif

#endif  /* __DPDK_MODULE_H__ */
