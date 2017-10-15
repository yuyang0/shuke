//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-02
//
#include <rte_arp.h>

#include "dpdk_module.h"
#include "shuke.h"
#include "utils.h"

#define RTE_LOGTYPE_DPDK RTE_LOGTYPE_USER1

#define NB_SOCKETS        8

#define MAX_JUMBO_PKT_LEN  9600
#define MEMPOOL_CACHE_SIZE 256

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	  3

#define KNI_MBUF_MAX 2048
#define KNI_QUEUE_SIZE 2048

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

/* Static global variables used within this file. */
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

static struct rte_mempool * pktmbuf_pool[NB_SOCKETS];

#ifdef IP_FRAG
#define	DEFAULT_FLOW_TTL	MS_PER_S
#define	DEFAULT_FLOW_NUM	0x1000

#define	MAX_PACKET_FRAG RTE_LIBRTE_IP_FRAG_MAX_FRAG
#define MBUF_TABLE_SIZE  (2 * RTE_MAX(MAX_PKT_BURST, MAX_PACKET_FRAG))

/* Should be power of two. */
#define	IP_FRAG_TBL_BUCKET_ENTRIES	16

#define IP_FRAG_NB_MBUF 8192
/*
 * Default byte size for the IPv6 Maximum Transfer Unit (MTU).
 * This value includes the size of IPv6 header.
 */
#define	IPV4_MTU_DEFAULT	ETHER_MTU
#define	IPV6_MTU_DEFAULT	ETHER_MTU

static struct rte_mempool *socket_direct_pool[RTE_MAX_NUMA_NODES];
static struct rte_mempool *socket_indirect_pool[RTE_MAX_NUMA_NODES];
#endif

#if RTE_LOG_DEBUG <= SK_LOG_DP_LEVEL
static void log_packet(struct rte_mbuf *m) {
    char buf[4096];
    int offset = 0;
    int n;
    uint16_t ether_type;
    uint8_t ipproto;
    char *l3_h = NULL;
    struct ether_hdr *eth_h;
    struct ipv4_hdr *ipv4_h = NULL;
    struct ipv6_hdr *ipv6_h = NULL;
    struct udp_hdr  *udp_h = NULL;
    struct tcp_hdr  *tcp_h = NULL;
    char ip_src_str[INET6_ADDRSTRLEN];
    char ip_dst_str[INET6_ADDRSTRLEN];

    eth_h = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ether_format_addr(buf+offset, ETHER_ADDR_FMT_SIZE, &eth_h->s_addr);
    offset += ETHER_ADDR_FMT_SIZE-1;

    strcpy(buf+offset, " -> ");
    offset += strlen(" -> ");

    ether_format_addr(buf+offset, ETHER_ADDR_FMT_SIZE, &eth_h->d_addr);
    offset += ETHER_ADDR_FMT_SIZE-1;

    strcpy(buf+offset, "\n");
    offset += strlen("\n");

    ether_type = rte_be_to_cpu_16(eth_h->ether_type);

    l3_h = (char *)(eth_h + 1);

    switch (ether_type) {
    case ETHER_TYPE_ARP:
        return;
    case ETHER_TYPE_IPv4:
        ipv4_h = (struct ipv4_hdr *)l3_h;
        ipproto = ipv4_h->next_proto_id;
        inet_ntop(AF_INET, &(ipv4_h->src_addr), ip_src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipv4_h->dst_addr), ip_dst_str, INET6_ADDRSTRLEN);
        n = snprintf(buf+offset, 4096-offset,
                     "  IPV4 %s -> %s (ttl %d, id %d, tlen: %d, offset %d, flags(%s%s))\n",
                     ip_src_str, ip_dst_str, ipv4_h->time_to_live,
                     rte_be_to_cpu_16(ipv4_h->packet_id),
                     rte_be_to_cpu_16(ipv4_h->total_length),
                     (rte_be_to_cpu_16(ipv4_h->fragment_offset) & \
                      IPV4_HDR_OFFSET_MASK) * IPV4_HDR_OFFSET_UNITS,
                     (rte_be_to_cpu_16(ipv4_h->fragment_offset) & IPV4_HDR_DF_FLAG)? "DF":"",
                     (rte_be_to_cpu_16(ipv4_h->fragment_offset) & IPV4_HDR_MF_FLAG)? "MF":"");
        offset += n;
        break;
    case ETHER_TYPE_IPv6:
        ipv6_h = (struct ipv6_hdr *)l3_h;
        ipproto = ipv6_h->proto;

        inet_ntop(AF_INET6, &(ipv6_h->src_addr), ip_src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ipv6_h->dst_addr), ip_dst_str, INET6_ADDRSTRLEN);
        n = snprintf(buf+offset, 4096-offset,
                     "  IPV6 %s -> %s (ttl %d)\n",
                     ip_src_str, ip_dst_str, ipv6_h->hop_limits);
        offset += n;
        break;
    default:
        return;
    }
    switch (ipproto) {
    case IPPROTO_UDP:
        udp_h = (struct udp_hdr *) (l3_h + m->l3_len);
        snprintf(buf+offset, 4096-offset, "    UDP %d -> %d\n",
                 rte_be_to_cpu_16(udp_h->src_port),
                 rte_be_to_cpu_16(udp_h->dst_port));
        break;
    case IPPROTO_TCP:
        tcp_h = (struct tcp_hdr *) (l3_h + m->l3_len);
        snprintf(buf+offset, 4096-offset, "    TCP %d -> %d\n",
                 rte_be_to_cpu_16(tcp_h->src_port),
                 rte_be_to_cpu_16(tcp_h->dst_port));
    default:
        return;
    }
    LOG_RAW(DEBUG, DPDK, "%s", buf);
}
#else
#define log_packet(m)
#endif

static void
init_per_lcore() {
    lcore_conf_t *qconf;
    unsigned lcore_id = rte_lcore_id();
    qconf = &sk.lcore_conf[lcore_id];
    qconf->tsc_hz = rte_get_tsc_hz();
    qconf->start_us = (uint64_t )ustime();
    qconf->start_tsc = rte_rdtsc();
}

static int
init_mem(unsigned nb_mbuf)
{
    int socketid;
    unsigned lcore_id;
    char s[64];

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        if (sk.numa_on)
            socketid = rte_lcore_to_socket_id(lcore_id);
        else
            socketid = 0;

        if (socketid >= NB_SOCKETS) {
            rte_exit(EXIT_FAILURE,
                     "Socket %d of lcore %u is out of range %d\n",
                     socketid, lcore_id, NB_SOCKETS);
        }

        if (pktmbuf_pool[socketid] == NULL) {
            snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
            pktmbuf_pool[socketid] =
                rte_pktmbuf_pool_create(s, nb_mbuf,
                                        MEMPOOL_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
            if (pktmbuf_pool[socketid] == NULL)
                rte_exit(EXIT_FAILURE,
                         "Cannot init mbuf pool on socket %d\n",
                         socketid);
            else
                LOG_INFO(DPDK, "Allocated mbuf pool on socket %d.", socketid);

        }

#ifdef IP_FRAG
        struct rte_mempool *mp;

        if (socket_direct_pool[socketid] == NULL) {
            LOG_INFO(DPDK, "Creating direct mempool on socket %i\n",
                    socketid);
            snprintf(s, sizeof(s), "pool_direct_%i", socketid);

            mp = rte_pktmbuf_pool_create(s, IP_FRAG_NB_MBUF, 32,
                                         0, RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
            if (mp == NULL) {
                LOG_ERR(DPDK, "Cannot create direct mempool\n");
                return -1;
            }
            socket_direct_pool[socketid] = mp;
        }

        if (socket_indirect_pool[socketid] == NULL) {
            LOG_INFO(DPDK, "Creating indirect mempool on socket %i\n",
                    socketid);
            snprintf(s, sizeof(s), "pool_indirect_%i", socketid);

            mp = rte_pktmbuf_pool_create(s, IP_FRAG_NB_MBUF, 32, 0, 0,
                                         socketid);
            if (mp == NULL) {
                LOG_ERR(DPDK, "Cannot create indirect mempool\n");
                return -1;
            }
            socket_indirect_pool[socketid] = mp;
        }
#endif

    }
    return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    LOG_RAW(INFO, DPDK, "\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        if (sk.force_quit)
            return;
        all_ports_up = 1;
        for (portid = 0; portid < port_num; portid++) {
            if (sk.force_quit)
                return;
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    LOG_RAW(INFO, DPDK,
                            "Port %d Link Up - speed %u "
                            "Mbps - %s\n", (uint8_t)portid,
                            (unsigned)link.link_speed,
                            (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                            ("full-duplex") : ("half-duplex\n"));
                else
                    LOG_RAW(INFO, DPDK, "Port %d Link Down\n", (uint8_t)portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            LOG_RAW(INFO, DPDK, ".");
            fflush(sk.log_fp);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            LOG_RAW(INFO, DPDK, "done\n");
        }
    }
}

/* Send burst of packets on an output interface */
static inline int
send_burst(lcore_conf_t *qconf, uint16_t n, uint8_t port)
{
    struct rte_mbuf **m_table;
    int ret;
    uint16_t queueid;

    queueid = qconf->queue_id_list[port];
    m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

    ret = rte_eth_tx_burst(port, queueid, m_table, n);
    LOG_DEBUG(DPDK, "burst send %d packets", ret);
    if (unlikely(ret < n)) {
        do {
            rte_pktmbuf_free(m_table[ret]);
        } while (++ret < n);
    }

    return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
static inline int
send_single_packet(lcore_conf_t *qconf,
                   struct rte_mbuf *m, uint8_t port)
{
    uint16_t len;

    len = qconf->tx_mbufs[port].len;
    qconf->tx_mbufs[port].m_table[len] = m;
    len++;

    /* enough pkts to be sent */
    if (unlikely(len == MAX_PKT_BURST)) {
        send_burst(qconf, MAX_PKT_BURST, port);
        len = 0;
    }

    qconf->tx_mbufs[port].len = len;
    return 0;
}

static uint16_t
get_udptcp_checksum(void *l3_hdr, void *l4_hdr, bool is_ipv4)
{
    if (is_ipv4)
        return rte_ipv4_udptcp_cksum(l3_hdr, l4_hdr);
    else /* assume ethertype == ETHER_TYPE_IPv6 */
        return rte_ipv6_udptcp_cksum(l3_hdr, l4_hdr);
}

static uint16_t
get_psd_sum(void *l3_hdr, bool is_ipv4, uint64_t ol_flags)
{
    if (is_ipv4)
        return rte_ipv4_phdr_cksum(l3_hdr, ol_flags);
    else /* assume ethertype == ETHER_TYPE_IPv6 */
        return rte_ipv6_phdr_cksum(l3_hdr, ol_flags);
}

// return 1 if the cksum is correct, otherwise return 0
static int
verify_cksum(struct rte_mbuf *m) {
    int ok = 1, bad = 0;

    // check l3 cksum
    switch (m->ol_flags & PKT_RX_IP_CKSUM_MASK) {
    case PKT_RX_IP_CKSUM_BAD:
        return bad;
    case PKT_RX_IP_CKSUM_UNKNOWN:
        // should verify the l3 cksum by software
        break;
    case PKT_RX_IP_CKSUM_NONE:
        /* the application can process the packet but must not verify the */
        /* checksum by sw. It has to take care to recalculate the cksum */
        /* if the packet is transmitted (either by sw or using tx offload) */
        break;
    default:
        break;
    }
    // check l4 cksum
    switch (m->ol_flags & PKT_RX_L4_CKSUM_MASK) {
    case PKT_RX_L4_CKSUM_BAD:
        return bad;
    case PKT_RX_L4_CKSUM_UNKNOWN:
        // should verify the l4 cksum by software
        break;
    case PKT_RX_L4_CKSUM_NONE:
        break;
    default:
        break;
    }
    return ok;
}

/*----------------------------------------------------------------------------*/
#ifdef IP_FRAG
static int
setup_ip_frag_tbl()
{
    lcore_conf_t *qconf;
    uint32_t max_flow_num = DEFAULT_FLOW_NUM;
    uint32_t max_flow_ttl = DEFAULT_FLOW_TTL;
    int socket;
    uint64_t frag_cycles;

    frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S *
        max_flow_ttl;

    for (int i = 0; i < sk.nr_lcore_ids; ++i) {
        int lcore_id = sk.lcore_ids[i];
        qconf = &sk.lcore_conf[lcore_id];
        socket = rte_lcore_to_socket_id(lcore_id);
        if (socket == SOCKET_ID_ANY) socket = 0;

        if ((qconf->frag_tbl = rte_ip_frag_table_create(max_flow_num,
                                                        IP_FRAG_TBL_BUCKET_ENTRIES,
                                                        max_flow_num, frag_cycles,
                                                        socket)) == NULL)
        {
            RTE_LOG(ERR, DPDK, "ip_frag_tbl_create(%u) on "
                    "lcore: %u failed\n",
                    max_flow_num, lcore_id);
            return -1;
        }
    }
    return 0;
}

struct rte_mbuf *
ipv4_reassemble(lcore_conf_t *qconf, struct rte_mbuf *m,
                struct ether_hdr **eth_hdr_pp,
                struct ipv4_hdr **ip_hdr_pp)
{
    struct ipv4_hdr *ip_hdr = *ip_hdr_pp;
    struct rte_ip_frag_tbl *tbl;
    struct rte_ip_frag_death_row *dr;

		/* if it is a fragmented packet, then try to reassemble. */
		if (rte_ipv4_frag_pkt_is_fragmented(ip_hdr)) {
        struct rte_mbuf *mo;

        tbl = qconf->frag_tbl;
        dr = &qconf->death_row;

        /* process this fragment. */
        mo = rte_ipv4_frag_reassemble_packet(tbl, dr, m, rte_rdtsc(), ip_hdr);
        if (mo == NULL)
            /* no packet to send out. */
            return NULL;

        /* we have our packet reassembled. */
        if (mo != m) {
            m = mo;
            *eth_hdr_pp = rte_pktmbuf_mtod(m, struct ether_hdr *);
            *ip_hdr_pp = (struct ipv4_hdr *)(*eth_hdr_pp + 1);
        }
	 }
    return m;
}

struct rte_mbuf *
ipv6_reassemble(lcore_conf_t *qconf, struct rte_mbuf *m,
                struct ether_hdr **eth_hdr_pp,
                struct ipv6_hdr **ip_hdr_pp)
{
    struct ether_hdr *eth_hdr = *eth_hdr_pp;
    struct ipv6_hdr *ip_hdr = *ip_hdr_pp;
    struct rte_ip_frag_tbl *tbl;
    struct rte_ip_frag_death_row *dr;
    struct ipv6_extension_fragment *frag_hdr;

		frag_hdr = rte_ipv6_frag_get_ipv6_fragment_header(ip_hdr);

		if (frag_hdr != NULL) {
        struct rte_mbuf *mo;

        tbl = qconf->frag_tbl;
        dr = &qconf->death_row;

        /* prepare mbuf: setup l2_len/l3_len. */
        m->l2_len = sizeof(*eth_hdr);
        m->l3_len = sizeof(*ip_hdr) + sizeof(*frag_hdr);

        mo = rte_ipv6_frag_reassemble_packet(tbl, dr, m, rte_rdtsc(), ip_hdr, frag_hdr);
        if (mo == NULL)
            return NULL;

        if (mo != m) {
            m = mo;
            *eth_hdr_pp = rte_pktmbuf_mtod(m, struct ether_hdr *);
            *ip_hdr_pp = (struct ipv6_hdr *)(eth_hdr + 1);
        }
    }
    return m;
}

/*
 * when you call this function, you must be sure that the packet size is bigger than MTU
 */
void
ip_fragmentation(lcore_conf_t *qconf, struct rte_mbuf *m,
                 port_info_t *pinfo, bool is_ipv4) {
    struct ether_hdr * origin_eth_h = rte_pktmbuf_mtod(m, struct ether_hdr *);
    uint8_t port = (uint8_t)pinfo->port_id;
    struct rte_mbuf *new_m;
    uint16_t len;
    int len2;
    struct rte_mempool *direct_pool = socket_direct_pool[qconf->node->numa_id];
    struct rte_mempool *indirect_pool = socket_indirect_pool[qconf->node->numa_id];

    len = qconf->tx_mbufs[port].len;
    LOG_DEBUG(DPDK, "ip fragmentation %d", m->pkt_len);

    rte_pktmbuf_adj(m, (uint16_t)sizeof(struct ether_hdr));

    if (is_ipv4) {
        len2 = rte_ipv4_fragment_packet(m,
                                        &qconf->tx_mbufs[port].m_table[len],
                                        (uint16_t)(MBUF_TABLE_SIZE - len),
                                        IPV4_MTU_DEFAULT,
                                        direct_pool, indirect_pool);
        /* If we fail to fragment the packet */
        if (unlikely (len2 < 0))
            goto end;
    } else {
        len2 = rte_ipv6_fragment_packet(m,
                                        &qconf->tx_mbufs[port].m_table[len],
                                        (uint16_t)(MBUF_TABLE_SIZE - len),
                                        IPV6_MTU_DEFAULT,
                                        direct_pool, indirect_pool);
        /* If we fail to fragment the packet */
        if (unlikely (len2 < 0))
            goto end;
    }

    LOG_DEBUG(DPDK, "response splits to %d fragments.", len2);

    for (int i = len; i < len + len2; i ++) {
        new_m = qconf->tx_mbufs[port].m_table[i];
        struct ether_hdr *eth_hdr = (struct ether_hdr *)
            rte_pktmbuf_prepend(new_m, (uint16_t)sizeof(struct ether_hdr));
        if (eth_hdr == NULL) {
            rte_panic("No headroom in mbuf.\n");
        }
        rte_memcpy(eth_hdr, origin_eth_h, sizeof(struct ether_hdr));
        new_m->l2_len = sizeof(struct ether_hdr);

        if (is_ipv4) {
            if (pinfo->hw_features.tx_csum_ip) {
                new_m->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM);
            } else {
                struct ipv4_hdr *ipv4_h = (struct ipv4_hdr*)(eth_hdr+1);
                new_m->ol_flags &= (~(PKT_TX_IPV4 | PKT_TX_IP_CKSUM));
                ipv4_h->hdr_checksum = 0;
                ipv4_h->hdr_checksum = rte_ipv4_cksum(ipv4_h);
            }
        }

        log_packet(new_m);
    }
    len += len2;
    if (likely(len < MAX_PKT_BURST)) {
        qconf->tx_mbufs[port].len = (uint16_t)len;
        return;
    }

    /* Transmit packets */
    send_burst(qconf, (uint16_t)len, port);
    qconf->tx_mbufs[port].len = 0;
end:
    /* Free input packet */
    rte_pktmbuf_free(m);
}
#endif

int sk_handle_arp_request(struct rte_mbuf *m, int portid) {
    struct ether_hdr *eth_h;
    struct arp_hdr *arp_h;
    port_info_t *pinfo = sk.port_info[portid];

    eth_h = rte_pktmbuf_mtod(m, struct ether_hdr *);
    arp_h = (struct arp_hdr*)(eth_h + 1);

    uint16_t arp_op_type = rte_be_to_cpu_16(arp_h->arp_op);
    if (arp_op_type == ARP_OP_REQUEST) {
        if (memcmp(&arp_h->arp_data.arp_tip, &pinfo->ipv4_addr, 4) == 0) {
            LOG_DEBUG(DPDK, "got arp request for port %d.", portid);
            arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);

            struct arp_ipv4 *arp_data = &arp_h->arp_data;
            arp_data->arp_tip = arp_data->arp_sip;
            ether_addr_copy(&arp_data->arp_sha, &arp_data->arp_tha);

            arp_data->arp_sip = pinfo->ipv4_addr;
            ether_addr_copy(&pinfo->eth_addr, &arp_data->arp_sha);

            ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
            ether_addr_copy(&pinfo->eth_addr, &eth_h->s_addr);
            return OK_CODE;
        }
    }
    return ERR_CODE;
}

static inline __attribute__((always_inline)) void
__handle_packet(struct rte_mbuf *m, uint8_t portid,
                 lcore_conf_t *qconf)
{
    port_info_t *pinfo = sk.port_info[portid];
    if (pinfo->hw_features.rx_csum && !verify_cksum(m)) {
        LOG_DEBUG(DPDK, "invalid cksum");
        goto invalid;
    }

    uint16_t ether_type;
    uint8_t ipproto;
    uint32_t ipv4_addr;
    uint16_t udp_port;
    char *l3_h = NULL;
    struct ether_hdr *eth_h;
    struct ipv4_hdr *ipv4_h = NULL;
    struct ipv6_hdr *ipv6_h = NULL;
    struct udp_hdr  *udp_h = NULL;
    struct tcp_hdr  *tcp_h = NULL;
#ifdef IP_FRAG
    int mtu;
#endif
    bool is_ipv4 = false;
    struct ether_addr eth_addr;
    char ipv6_addr[16];
    char *udp_data;
    size_t udp_data_len;
    int n, total_h_len;
    void *src_addr = NULL;

    eth_h = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ether_type = rte_be_to_cpu_16(eth_h->ether_type);
    l3_h = (char *)(eth_h+1);
    m->l2_len = sizeof(struct ether_hdr);

    switch (ether_type) {
        case ETHER_TYPE_ARP:
            LOG_DEBUG(DPDK, "port %d got a arp packet.", portid);
            if (sk_handle_arp_request(m, portid) == OK_CODE) {
                send_single_packet(qconf, m, portid);
                return;
            }
            if (!sk.only_udp) kni_send_single_packet(qconf, m ,portid);
            else rte_pktmbuf_free(m);
            return;
        case ETHER_TYPE_IPv4:
            is_ipv4 = true;
            ipv4_h = (struct ipv4_hdr *)l3_h;
            if (! pinfo->hw_features.rx_csum) {
                // using software to verify cksum
                if (rte_ipv4_cksum(ipv4_h) != 0xFFFF) {
                    LOG_DEBUG(DPDK, "wrong ipv4 checksum, drop it.");
                    goto invalid;
                }
            }
            m->l3_len = (ipv4_h->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
#ifdef IP_FRAG
            m = ipv4_reassemble(qconf, m, &eth_h, &ipv4_h);
            if (!m) return;
            mtu = IPV4_MTU_DEFAULT;
#endif
            src_addr = &(ipv4_h->src_addr);
            ipproto = ipv4_h->next_proto_id;
            break;
        case ETHER_TYPE_IPv6:
            ipv6_h = (struct ipv6_hdr *)l3_h;
            m->l3_len = sizeof(*ipv6_h);
#ifdef IP_FRAG
            m = ipv6_reassemble(qconf, m, &eth_h, &ipv6_h);
            if (!m) return;
            mtu = IPV6_MTU_DEFAULT;
#endif
            m->ol_flags |= PKT_TX_IPV6;
            src_addr = ipv6_h->src_addr;
            ipproto = ipv6_h->proto;
            break;
        default:
            LOG_DEBUG(DPDK, "invalid l3 proto");
            goto invalid;
    }
    switch (ipproto) {
        case IPPROTO_UDP:
            udp_h = (struct udp_hdr *) (l3_h + m->l3_len);
            if (! pinfo->hw_features.rx_csum) {
                // using software to verify cksum
                if (get_udptcp_checksum(l3_h, udp_h, is_ipv4) != 0xFFFF) {
                    LOG_DEBUG(DPDK, "wrong udp checksum, drop it.");
                    goto invalid;
                }
            }
            // check the udp port
            if (rte_be_to_cpu_16(udp_h->dst_port) != sk.port) {
                LOG_DEBUG(DPDK, "invalid udp port");
                goto invalid;
            }
            break;
        case IPPROTO_TCP:
            if(sk.only_udp) goto invalid;

            tcp_h = (struct tcp_hdr *) (l3_h + m->l3_len);
            if (! pinfo->hw_features.rx_csum) {
                // using software to verify cksum
                if (get_udptcp_checksum(l3_h, tcp_h, is_ipv4) != 0xFFFF) {
                    LOG_DEBUG(DPDK, "wrong udp checksum, drop it.");
                    goto invalid;
                }
            }
            // check the tcp port
            if (rte_be_to_cpu_16(tcp_h->dst_port) != sk.port) {
                LOG_DEBUG(DPDK, "invalid tcp port");
                goto invalid;
            }
            LOG_DEBUG(DPDK, "port %d got a tcp packet.", portid);
            kni_send_single_packet(qconf, m ,portid);
            return;
        default:
            LOG_DEBUG(DPDK, "invalid l4 proto");
            goto invalid;
    }

    m->l4_len = sizeof(struct udp_hdr);

    udp_data = (void *) (udp_h + 1);
    udp_data_len = (size_t )(rte_be_to_cpu_16(udp_h->dgram_len) - 8);
    char *data_end = rte_pktmbuf_mtod(m, char*) + rte_pktmbuf_data_len(m);
    // move data end to the start of udp data.
    rte_pktmbuf_trim(m, (uint16_t)(data_end - udp_data));

    n = processUDPDnsQuery(udp_data, udp_data_len, udp_data,
                           rte_pktmbuf_tailroom(m), src_addr, udp_h->src_port,
                           is_ipv4, qconf->node, qconf->lcore_id);
    if(n == ERR_CODE) goto dropped;

    // ethernet frame should at least contain 64 bytes(include 4 byte CRC)
    total_h_len = (int)(m->l2_len + m->l3_len + m->l4_len);
    if (n + total_h_len < 60) n = 60 - total_h_len;
    rte_pktmbuf_append(m, (uint16_t)n);
    LOG_DEBUG(DPDK, "pkt_len: %u, udp len: %zu, port: %d",
              rte_pktmbuf_pkt_len(m), udp_data_len, rte_be_to_cpu_16(udp_h->src_port));

    ++qconf->nr_req;

    ether_addr_copy(&eth_h->s_addr, &eth_addr);
    ether_addr_copy(&eth_h->d_addr, &eth_h->s_addr);
    ether_addr_copy(&eth_addr, &eth_h->d_addr);

    if (is_ipv4) {
        ipv4_h->time_to_live = 64;
        ipv4_h->packet_id = rte_cpu_to_be_16(qconf->ipv4_packet_id);
        qconf->ipv4_packet_id += sk.nr_lcore_ids;

        ipv4_addr = ipv4_h->src_addr;
        ipv4_h->src_addr = ipv4_h->dst_addr;
        ipv4_h->dst_addr = ipv4_addr;
        ipv4_h->total_length = rte_cpu_to_be_16(m->l3_len+m->l4_len+n);
        ipv4_h->hdr_checksum = 0;

        if (pinfo->hw_features.tx_csum_ip) {
            m->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM);
        } else {
            ipv4_h->hdr_checksum = rte_ipv4_cksum(ipv4_h);
        }
    } else {
        ipv6_h->hop_limits = 64;
        rte_memcpy(ipv6_addr, ipv6_h->dst_addr, 16);
        rte_memcpy(ipv6_h->dst_addr, ipv6_h->src_addr, 16);
        rte_memcpy(ipv6_h->src_addr, ipv6_addr, 16);
        ipv6_h->payload_len = rte_cpu_to_be_16(m->l3_len+m->l4_len+n);
    }

    udp_port = udp_h->src_port;
    udp_h->src_port = udp_h->dst_port;
    udp_h->dst_port = udp_port;
    udp_h->dgram_len = rte_cpu_to_be_16(m->l4_len + n);
    /* set checksum parameters for HW offload */
    udp_h->dgram_cksum = 0;

    if (pinfo->hw_features.tx_csum_l4) {
        m->ol_flags |= PKT_TX_UDP_CKSUM;
        udp_h->dgram_cksum = get_psd_sum(l3_h, is_ipv4, m->ol_flags);
        LOG_DEBUG(DPDK, "udp psd checksum: 0x%x.", udp_h->dgram_cksum);
    } else {
        udp_h->dgram_cksum = get_udptcp_checksum(l3_h, udp_h, is_ipv4);
        LOG_DEBUG(DPDK, "udp checksum: 0x%x.", udp_h->dgram_cksum);
    }

#ifdef IP_FRAG
    if (likely(mtu + sizeof(struct ether_hdr) >= m->pkt_len)) {
        send_single_packet(qconf, m, portid);
    } else {
        // we must calculate the udp cksum when ip fragmentation is needed.
        udp_h->dgram_cksum = 0;
        udp_h->dgram_cksum = get_udptcp_checksum(l3_h, udp_h, is_ipv4);
        ip_fragmentation(qconf, m, pinfo, is_ipv4);
    }
#else
    send_single_packet(qconf, m, portid);
#endif
    return;

dropped:
    // LOG_DEBUG(DPDK, "drop packet.");
    ++qconf->nr_dropped;
invalid:
    rte_pktmbuf_free(m);
}

static void handle_packets(int nb_rx, struct rte_mbuf **pkts_burst,
                           uint8_t portid, lcore_conf_t *qconf)
{
    int32_t j;

    /* Prefetch first packets */
    for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));

    /*
     * Prefetch and forward already prefetched
     * packets.
     */
    for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[
                                           j + PREFETCH_OFFSET], void *));
        __handle_packet(pkts_burst[j], portid, qconf);
    }

    /* Forward remaining prefetched packets */
    for (; j < nb_rx; j++)
        __handle_packet(pkts_burst[j], portid, qconf);
}

int
launch_one_lcore(__attribute__((unused)) void *dummy)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    unsigned lcore_id = rte_lcore_id();
    lcore_conf_t *qconf = &sk.lcore_conf[lcore_id];
    uint64_t prev_tsc, diff_tsc, cur_tsc;
    int i, nb_rx;
    uint8_t portid, queueid;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
        US_PER_S * BURST_TX_DRAIN_US;

    rcu_register_thread();

    prev_tsc = 0;

    init_per_lcore();

    if (qconf->nr_ports == 0) {
        LOG_INFO(DPDK, "lcore %u has nothing to do.", lcore_id);
        return 0;
    }

    LOG_INFO(DPDK, "entering main loop on lcore %u.", lcore_id);

    for (i = 0; i < qconf->nr_ports; i++) {

        portid = (uint8_t )qconf->port_id_list[i];
        queueid = (uint8_t )qconf->queue_id_list[portid];
        LOG_INFO(DPDK,
                " -- lcoreid=%u portid=%hhu rxqueueid=%hhu.",
                lcore_id, portid, queueid);
    }

    while (!sk.force_quit) {

        cur_tsc = rte_rdtsc();

        /*
         * TX burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            for (i = 0; i < qconf->nr_ports; ++i) {
                portid = (uint8_t )qconf->port_id_list[i];
                if (qconf->tx_mbufs[portid].len > 0) {
                    send_burst(qconf,
                               qconf->tx_mbufs[portid].len,
                               portid);
                    qconf->tx_mbufs[portid].len = 0;
                }
            }

            prev_tsc = cur_tsc;
        }
        /*
         * Read packet from RX queues
         */
        for (i = 0; i < qconf->nr_ports; i++) {

            portid = (uint8_t )qconf->port_id_list[i];
            queueid = (uint8_t )qconf->queue_id_list[portid];

            if (!sk.only_udp) {
                sk_kni_process(qconf, portid, queueid, pkts_burst, MAX_PKT_BURST);
            }

            nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst, MAX_PKT_BURST);
            if (nb_rx == 0)
                continue;
            qconf->received_req += nb_rx;
            // LOG_DEBUG(DPDK, "lcore %d recv port %d, queue %d, nb_rx: %d\n", qconf->lcore_id, portid, queueid, nb_rx);

            handle_packets(nb_rx, pkts_burst, portid, qconf);
        }
    }

    rcu_unregister_thread();
    return 0;
}

void
init_dpdk_eal() {
    int ret;
    char master_lcore_cmd[128];
    char log_cmd[128];
    int log_level = RTE_LOG_INFO;
    if ((int)str2loglevel(sk.logLevelStr) < log_level) {
        log_level = str2loglevel(sk.logLevelStr);
    }
    snprintf(master_lcore_cmd, 128, "--master-lcore=%d", sk.master_lcore_id);
    snprintf(log_cmd, 128, "--log-level=%d", log_level);
    /* initialize the rte env first*/
    char *argv[] = {
            "",
            "-l",
            sk.total_lcore_list,
            "-n",
            sk.mem_channels,
            master_lcore_cmd,
            log_cmd,
            "--proc-type=auto",
            "--"
    };
    const int argc = 9;
    /*
     * reset optind, because rte_eal_init uses getopt.
     */
    optind = 0;
    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    /*
     * since rte_eal_init rewrite the log configuration,
     * so config_log should stay after rte_eal_init.
     */
    config_log();
}

void prepare_eth_port_conf(struct rte_eth_conf *port_conf,
                           struct rte_eth_dev_info *dev_info,
                           port_info_t *pinfo) {
    memset(port_conf, 0, sizeof(*port_conf));

    port_conf->rxmode.mq_mode = ETH_MQ_RX_RSS;
    port_conf->rx_adv_conf.rss_conf.rss_hf = ETH_RSS_PROTO_MASK;
    /* setting the rss key */
    // static const uint8_t key[] = {
    //     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 10 */
    //     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 20 */
    //     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 30 */
    //     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 40 */
    //     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 50 */
    //     0x05, 0x05  /* 60 - 8 */
    // };
    //
    // port_conf->rx_adv_conf.rss_conf.rss_key = (uint8_t *)&key;
    // port_conf->rx_adv_conf.rss_conf.rss_key_len = sizeof(key);

    if (sk.jumbo_on) {
        port_conf->rxmode.jumbo_frame = 1;
        port_conf->rxmode.max_rx_pkt_len = (uint32_t)sk.max_pkt_len;
    }

    /* Set Rx VLAN stripping */
    if (dev_info->rx_offload_capa & DEV_RX_OFFLOAD_VLAN_STRIP) {
        port_conf->rxmode.hw_vlan_strip = 1;
    }

    port_conf->rxmode.hw_strip_crc = 1;
    /* Set Rx checksum checking */
    if ((dev_info->rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM) &&
        (dev_info->rx_offload_capa & DEV_RX_OFFLOAD_UDP_CKSUM) &&
        (dev_info->rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM)) {
        LOG_INFO(DPDK, "PORT %d RX checksum offload supported", pinfo->port_id);
        port_conf->rxmode.hw_ip_checksum = 1;
        pinfo->hw_features.rx_csum = 1;
    }

    if ((dev_info->tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM)) {
        LOG_INFO(DPDK, "PORT %d TX ip checksum offload supported", pinfo->port_id);
        pinfo->hw_features.tx_csum_ip = 1;
    }

    if ((dev_info->tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) &&
        (dev_info->tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM)) {
        LOG_INFO(DPDK, "PORT %d TX TCP&UDP checksum offload supported", pinfo->port_id);
        pinfo->hw_features.tx_csum_l4 = 1;
    }
}

void prepare_eth_rx_tx_conf(struct rte_eth_dev_info *dev_info) {
    dev_info->default_txconf.txq_flags = ETH_TXQ_FLAGS_NOMULTMEMP |
                                        ETH_TXQ_FLAGS_NOREFCOUNT;

    /* Disable features that are not supported by port's HW */
    if (!(dev_info->tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM)) {
        dev_info->default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOXSUMUDP;
    }

    if (!(dev_info->tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM)) {
        dev_info->default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOXSUMTCP;
    }

    if (!(dev_info->tx_offload_capa & DEV_TX_OFFLOAD_VLAN_INSERT)) {
        dev_info->default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOVLANOFFL;
    }

    if (!(dev_info->tx_offload_capa & DEV_TX_OFFLOAD_VLAN_INSERT)) {
        dev_info->default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOVLANOFFL;
    }
}

int
init_dpdk_module() {
    lcore_conf_t *qconf;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf port_conf;
    int ret;
    unsigned nb_dev_ports;
    uint16_t queueid;
    unsigned lcore_id;
    uint32_t nb_tx_queue, nb_lcores;
    uint8_t portid, nb_rx_queue, socketid;

    if (sk.jumbo_on) {
        if ((sk.max_pkt_len < 64) ||
            (sk.max_pkt_len > MAX_JUMBO_PKT_LEN)) {
            rte_exit(EXIT_FAILURE, "Invalid packet length\n");
        }
    }
    nb_dev_ports = rte_eth_dev_count();

    nb_lcores = rte_lcore_count();
    LOG_INFO(DPDK, "found %d cores, master cores: %d, %d",
             nb_lcores, rte_get_master_lcore(), rte_lcore_id());


    /* initialize all ports */
    for (int i = 0; i < sk.nr_ports; i++) {
        portid = (uint8_t )sk.port_ids[i];
        if (portid >= nb_dev_ports) {
            rte_exit(EXIT_FAILURE,
                     "this machine doesn't have port %d\n",
                     portid);
        }
        port_info_t *pinfo = sk.port_info[portid];
        /* init port */
        LOG_INFO(DPDK, "Initializing port %d ... ", portid );

        rte_eth_dev_info_get(portid, &dev_info);

        /*
         * every core should has a rx/tx queue except master core
         */
        nb_rx_queue = (uint8_t )pinfo->nr_lcore;
        nb_tx_queue = (uint32_t )(pinfo->nr_lcore);

        if (nb_rx_queue > dev_info.max_rx_queues) {
            rte_exit(EXIT_FAILURE,
                     "number of rx queue(%d) is bigger than dev's max_rx_queue(%d)\n",
                     nb_rx_queue,
                     dev_info.max_rx_queues);
        }
        if (nb_tx_queue > dev_info.max_tx_queues) {
            rte_exit(EXIT_FAILURE,
                     "number of tx queue(%d) is bigger than dev's max_tx_queue(%d)\n",
                     nb_tx_queue, dev_info.max_tx_queues);
        }

        prepare_eth_port_conf(&port_conf, &dev_info, pinfo);
        prepare_eth_rx_tx_conf(&dev_info);
        LOG_INFO(DPDK, "Creating queues: port=%d nb_rxq=%d nb_txq=%u...",
                 portid, nb_rx_queue, (unsigned)nb_tx_queue );
        ret = rte_eth_dev_configure(portid, nb_rx_queue,
                                    (uint16_t)nb_tx_queue, &port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                     "Cannot configure device: err=%d, port=%d\n",
                     ret, portid);

        rte_eth_macaddr_get(portid, &sk.port_info[portid]->eth_addr);
        ether_format_addr(sk.port_info[portid]->eth_addr_s,
                          ETHER_ADDR_FMT_SIZE,
                          &sk.port_info[portid]->eth_addr);
        LOG_INFO(DPDK, "port %d mac address: %s.", portid,
                 sk.port_info[portid]->eth_addr_s);

        /* init memory */
        unsigned nb_mbuf = RTE_MAX(
            (nb_dev_ports*nb_rx_queue*RTE_TEST_RX_DESC_DEFAULT +
             nb_dev_ports*nb_lcores*MAX_PKT_BURST +
             nb_dev_ports*nb_tx_queue*RTE_TEST_TX_DESC_DEFAULT +
             nb_lcores*MEMPOOL_CACHE_SIZE  +
             nb_dev_ports*KNI_MBUF_MAX     +
             nb_dev_ports*KNI_QUEUE_SIZE),
            (unsigned)8192);
        ret = init_mem(nb_mbuf);

        if (ret < 0)
            rte_exit(EXIT_FAILURE, "init_mem failed\n");

        /* init one RX, TX queue per couple (lcore,port) */
        for (int i = 0; i < sk.nr_lcore_ids; ++i) {
            lcore_id = (unsigned )sk.lcore_ids[i];
            qconf = &sk.lcore_conf[lcore_id];
            queueid = qconf->queue_id_list[portid];
            if (lcore_id == rte_get_master_lcore()) continue;
            assert(rte_lcore_is_enabled(lcore_id));

            if (sk.numa_on)
                socketid =
                    (uint8_t)rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            LOG_INFO(DPDK, "txq=<< lcore:%u, port: %d, queue:%d, socket:%d >>",
                     lcore_id, portid, queueid, socketid);

            // if (default_port_conf.rxmode.jumbo_frame)
            //     txconf->txq_flags = 0;
            ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
                                         socketid, &dev_info.default_txconf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_tx_queue_setup: err=%d, "
                         "port=%d\n", ret, portid);

            LOG_INFO(DPDK, "rxq=<< lcore:%u, port:%d, queue:%d, socket:%d >>",
                     lcore_id, portid, queueid, socketid);
            ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
                                         socketid,
                                         &dev_info.default_rxconf,
                                         pktmbuf_pool[socketid]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_rx_queue_setup: err=%d, port=%d\n",
                         ret, portid);
        }
    }


#ifdef IP_FRAG
    setup_ip_frag_tbl();
#endif

    /* start ports */
    for (portid = 0; portid < nb_dev_ports; portid++) {
        if ((sk.portmask & (1 << portid)) == 0) {
            continue;
        }
        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                     "rte_eth_dev_start: err=%d, port=%d\n",
                     ret, portid);

        /*
         * If enabled, put device in promiscuous mode.
         * This allows IO forwarding mode to forward packets
         * to itself through 2 cross-connected  ports of the
         * target machine.
         */
        if (sk.promiscuous_on)
            rte_eth_promiscuous_enable(portid);
    }

    check_all_ports_link_status((uint8_t)nb_dev_ports, (uint32_t )sk.portmask);

    rte_timer_subsystem_init();
    sk.hz = rte_get_timer_hz();

    init_per_lcore();

    return 0;
}

int start_dpdk_threads(void) {
    int ret = 0;
    for (int i = 0; i < sk.nr_lcore_ids; i++) {
        unsigned lcore_id = (unsigned )sk.lcore_ids[i];
        assert(rte_lcore_is_enabled(lcore_id));

        if (lcore_id == rte_get_master_lcore())
            continue;
        ret = rte_eal_remote_launch(launch_one_lcore, NULL, lcore_id);
        if (ret != 0)
            rte_exit(EXIT_FAILURE, "Failed to start lcore %d, return %d", lcore_id, ret);
    }
    return 0;
}

int cleanup_dpdk_module(void) {
    unsigned nb_ports;
    uint8_t portid;

    rte_eal_mp_wait_lcore();

    nb_ports = rte_eth_dev_count();

    /* stop ports */
    for (portid = 0; portid < nb_ports; portid++) {
        if ((sk.portmask & (1 << portid)) == 0)
            continue;
        LOG_INFO(DPDK, "Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        LOG_INFO(DPDK, "port %d Done.", portid);
    }
    return 0;
}

void
init_kni_module(void) {
    unsigned socket_id = sk.master_numa_id;
    struct rte_mempool *mbuf_pool = pktmbuf_pool[socket_id];
    sk_init_kni_module(mbuf_pool);
}

/*
 * high performance time functions using tsc register.
 * pls note: these function maybe inaccurate in some environments.
 */
uint64_t rte_tsc_ustime() {
    unsigned lcore_id = rte_lcore_id();
    lcore_conf_t *qconf = &sk.lcore_conf[lcore_id];
    const uint64_t cur_tsc = rte_rdtsc();
    return qconf->start_us + (cur_tsc - qconf->start_tsc)*US_PER_S/qconf->tsc_hz;
}

uint64_t rte_tsc_mstime() {
    return rte_tsc_ustime()/1000;
}

uint64_t rte_tsc_time() {
    return rte_tsc_ustime()/US_PER_S;
}

#ifdef SK_TEST
/*
 * init dpdk eal, mainly for test
 */
void initTestDpdkEal() {
    int ret;
    /* initialize the rte env first*/
    char *argv[] = {
            "",
            "-c",
            "0x1",
            "-n",
            "4",
            "--"
    };
    const int argc = 9;
    /*
     * reset optind, because rte_eal_init uses getopt.
     */
    optind = 0;
    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
}
#endif
