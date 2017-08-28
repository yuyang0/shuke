/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define RTE_LOGTYPE_DPDK RTE_LOGTYPE_USER1

#define MAX_PKT_BURST     32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define MAX_RX_QUEUE_PER_LCORE 16

#define NB_SOCKETS        8

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	  3

#define KNI_MBUF_MAX 2048
#define KNI_QUEUE_SIZE 2048

#ifdef IP_FRAG
#define	DEFAULT_FLOW_TTL	MS_PER_S
#define	DEFAULT_FLOW_NUM	0x1000

#define SK_MAX(x1, x2) (x1) > (x2)? (x1): (x2)

#define	MAX_PACKET_FRAG RTE_LIBRTE_IP_FRAG_MAX_FRAG
#define MBUF_TABLE_SIZE  (2 * SK_MAX(MAX_PKT_BURST, MAX_PACKET_FRAG))

/* Should be power of two. */
#define	IP_FRAG_TBL_BUCKET_ENTRIES	16
#endif

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

typedef struct port_info {
    // ethernet address for this port
    struct ether_addr eth_addr;
    // ethernet address(string format)
    char eth_addr_s[ETHER_ADDR_FMT_SIZE];
    uint8_t port_id;

    int nr_lcore;
    int *lcore_list;

    uint32_t ipv4_addr;
} __rte_cache_aligned port_info_t;

extern struct rte_eth_conf default_port_conf;

void initDpdkEal();
int initDpdkModule(void);
int startDpdkThreads(void);
int cleanupDpdkModule(void);

uint64_t rte_tsc_ustime();
uint64_t rte_tsc_mstime();
uint64_t rte_tsc_time();

/*----------------------------------------------
 *     kni
 *---------------------------------------------*/
void sk_init_kni_module(struct rte_mempool *mbuf_pool);
void init_kni_module(void);
int cleanup_kni_module();
int kni_ifconfig_all();

int kni_send_single_packet(lcore_conf_t *qconf, struct rte_mbuf *m, uint8_t port);

void
sk_kni_process(lcore_conf_t *qconf, uint8_t port_id, uint16_t queue_id, struct rte_mbuf **pkts_burst, unsigned count);

#ifdef SK_TEST
void initTestDpdkEal();
#endif

#endif  /* __DPDK_MODULE_H__ */
