//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-02
//

#include "dpdk_module.h"
#include "shuke.h"
#include "utils.h"

#define MAX_LCORE_PARAMS 1024

#define MAX_JUMBO_PKT_LEN  9600
#define MEMPOOL_CACHE_SIZE 256
/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 			8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 			8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 			4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 			36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH			0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH			0  /**< Default values of TX write-back threshold reg. */

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF RTE_MAX(                                  \
        (nb_ports*nb_rx_queue*RTE_TEST_RX_DESC_DEFAULT +	\
         nb_ports*nb_lcores*MAX_PKT_BURST +               \
         nb_ports*n_tx_queue*RTE_TEST_TX_DESC_DEFAULT +		\
         nb_lcores*MEMPOOL_CACHE_SIZE),                   \
        (unsigned)8192)

/* #define NB_MBUF 8192 */

/* Static global variables used within this file. */
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

struct lcore_params {
    uint8_t port_id;
    uint8_t queue_id;
    uint8_t lcore_id;
} __rte_cache_aligned;

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
    {0, 0, 2},
    {0, 1, 2},
    {0, 2, 2},
    {1, 0, 2},
    {1, 1, 2},
    {1, 2, 2},
    {2, 0, 2},
    {3, 0, 3},
    {3, 1, 3},
};

static struct lcore_params * lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params = sizeof(lcore_params_array_default) /
    sizeof(lcore_params_array_default[0]);

struct rte_eth_conf default_port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 1, /**< IP checksum offload enabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 1, /**< CRC stripped by hardware */
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_TCP | ETH_RSS_UDP | ETH_RSS_IP | ETH_RSS_L2_PAYLOAD,
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh = 		RX_PTHRESH, /* RX prefetch threshold reg */
        .hthresh = 		RX_HTHRESH, /* RX host threshold reg */
        .wthresh = 		RX_WTHRESH, /* RX write-back threshold reg */
    },
    .rx_free_thresh = 		32,
};

static const struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = 		TX_PTHRESH, /* TX prefetch threshold reg */
        .hthresh = 		TX_HTHRESH, /* TX host threshold reg */
        .wthresh = 		TX_WTHRESH, /* TX write-back threshold reg */
    },
    .tx_free_thresh = 		0, /* Use PMD default values */
    .tx_rs_thresh = 		0, /* Use PMD default values */
    /*
     * As the example won't handle mult-segments and offload cases,
     * set the flag by default.
     */
    .txq_flags = 			0x0,
};

static struct rte_mempool * pktmbuf_pool[NB_SOCKETS];

static void
init_per_lcore() {
    lcore_conf_t *qconf;
    unsigned lcore_id = rte_lcore_id();
    qconf = &sk.lcore_conf[lcore_id];
    qconf->tsc_hz = rte_get_tsc_hz();
    qconf->start_us = (uint64_t )ustime();
    qconf->start_tsc = rte_rdtsc();
}

static int check_cksum_offload(int portid) {
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get((uint8_t )portid, &dev_info);
    if ((dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) == 0) {
        LOG_WARN(DPDK, "port %d doesn't support ipv4 cksum offload.");
        return -1;
    }
    if ((dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) == 0) {
        LOG_WARN(DPDK, "port %d doesn't support udp cksum offload.");
        return -1;
    }
    return 0;
}

static int
check_lcore_params(void)
{
    uint8_t queue, lcore;
    uint16_t i;
    int socketid;

    for (i = 0; i < nb_lcore_params; ++i) {
        queue = lcore_params[i].queue_id;
        if (queue >= MAX_RX_QUEUE_PER_PORT) {
            LOG_ERR(DPDK, "invalid queue number: %hhu", queue);
            return -1;
        }
        lcore = lcore_params[i].lcore_id;
        if (!rte_lcore_is_enabled(lcore)) {
            LOG_ERR(DPDK, "lcore %hhu is not enabled in lcore mask", lcore);
            return -1;
        }
        if ((socketid = rte_lcore_to_socket_id(lcore) != 0) &&
            (sk.numa_on == false)) {
            LOG_WARNING(DPDK, "lcore %hhu is on socket %d with numa off \n",
                   lcore, socketid);
        }
    }
    return 0;
}

static int
check_port_config(const unsigned nb_ports)
{
    unsigned portid;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        portid = lcore_params[i].port_id;
        if ((sk.portmask & (1 << portid)) == 0) {
            LOG_ERR(DPDK, "port %u is not enabled in port mask", portid);
            return -1;
        }
        if (portid >= nb_ports) {
            LOG_ERR(DPDK, "port %u is not present on the board.", portid);
            return -1;
        }
    }
    return 0;
}

static uint8_t
get_port_n_rx_queues(const uint8_t port)
{
    int queue = -1;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        if (lcore_params[i].port_id == port) {
            if (lcore_params[i].queue_id == queue+1)
                queue = lcore_params[i].queue_id;
            else
                rte_exit(EXIT_FAILURE, "queue ids of the port %d must be"
                         " in sequence and must start with 0\n",
                         lcore_params[i].port_id);
        }
    }
    return (uint8_t)(++queue);
}

static int
init_lcore_rx_queues(void)
{
    uint16_t i, nb_rx_queue;
    uint8_t lcore;

    for (i = 0; i < nb_lcore_params; ++i) {
        lcore = lcore_params[i].lcore_id;
        nb_rx_queue = sk.lcore_conf[lcore].n_rx_queue;
        if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
            LOG_ERR(DPDK, "too many queues (%u) for lcore: %u.",
                   (unsigned)nb_rx_queue + 1, (unsigned)lcore);
            return -1;
        } else {
            sk.lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
                lcore_params[i].port_id;
            sk.lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
                lcore_params[i].queue_id;
            sk.lcore_conf[lcore].n_rx_queue++;
        }
    }
    return 0;
}

static int
parse_config(const char *q_arg)
{
    char s[256];
    const char *p, *p0 = q_arg;
    char *end;
    enum fieldnames {
        FLD_PORT = 0,
        FLD_QUEUE,
        FLD_LCORE,
        _NUM_FLD
    };
    unsigned long int_fld[_NUM_FLD];
    char *str_fld[_NUM_FLD];
    int i;
    unsigned size;

    nb_lcore_params = 0;

    while ((p = strchr(p0,'(')) != NULL) {
        ++p;
        if((p0 = strchr(p,')')) == NULL)
            return -1;

        size = p0 - p;
        if(size >= sizeof(s))
            return -1;

        snprintf(s, sizeof(s), "%.*s", size, p);
        if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
            return -1;
        for (i = 0; i < _NUM_FLD; i++){
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
                return -1;
        }
        if (nb_lcore_params >= MAX_LCORE_PARAMS) {
            LOG_WARN(DPDK, "exceeded max number of lcore params: %hu.",
                   nb_lcore_params);
            return -1;
        }
        lcore_params_array[nb_lcore_params].port_id =
            (uint8_t)int_fld[FLD_PORT];
        lcore_params_array[nb_lcore_params].queue_id =
            (uint8_t)int_fld[FLD_QUEUE];
        lcore_params_array[nb_lcore_params].lcore_id =
            (uint8_t)int_fld[FLD_LCORE];
        ++nb_lcore_params;
    }
    lcore_params = lcore_params_array;
    return 0;
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

    queueid = qconf->tx_queue_id[port];
    m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

    ret = rte_eth_tx_burst(port, queueid, m_table, n);
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

/* Send burst of packets on an output interface */
static inline int
kni_send_burst(lcore_conf_t *qconf, uint16_t n, uint8_t port)
{
    port_kni_conf_t *kconf = sk.kni_conf[port];
    struct rte_mbuf **m_table;
    int ret;

    m_table = (struct rte_mbuf **)qconf->kni_tx_mbufs[port].m_table;
    ret = rte_kni_tx_burst(kconf->kni, m_table, n);
    if (unlikely(ret < n)) {
        do {
            rte_pktmbuf_free(m_table[ret]);
        } while (++ret < n);
    }

    qconf->kni_tx_mbufs[port].len = 0;
    return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
static inline int
kni_send_single_packet(lcore_conf_t *qconf, struct rte_mbuf *m, uint8_t port)
{
    int ret = 0;
    uint16_t len;

    len = qconf->kni_tx_mbufs[port].len;
    qconf->kni_tx_mbufs[port].m_table[len] = m;
    len++;

    /* enough pkts to be sent */
    if (unlikely(len == MAX_PKT_BURST)) {
        kni_send_burst(qconf, MAX_PKT_BURST, port);
        len = 0;
    }

    qconf->kni_tx_mbufs[port].len = len;
    return ret;
}

#ifdef SOFT_CKSUM

static uint16_t
get_udptcp_checksum(void *l3_hdr, void *l4_hdr, bool is_ipv4)
{
    if (is_ipv4)
        return rte_ipv4_udptcp_cksum(l3_hdr, l4_hdr);
    else /* assume ethertype == ETHER_TYPE_IPv6 */
        return rte_ipv6_udptcp_cksum(l3_hdr, l4_hdr);
}
#else

static uint16_t
get_psd_sum(void *l3_hdr, bool is_ipv4, uint64_t ol_flags)
{
    if (is_ipv4)
        return rte_ipv4_phdr_cksum(l3_hdr, ol_flags);
    else /* assume ethertype == ETHER_TYPE_IPv6 */
        return rte_ipv6_phdr_cksum(l3_hdr, ol_flags);
}
#endif

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
    }
    return ok;
}

static inline __attribute__((always_inline)) void
__send_to_kni(lcore_conf_t *qconf, struct rte_mbuf *m, uint8_t portid)
{
    /* Burst tx to kni */
    kni_send_single_packet(qconf, m, portid);
}

static inline __attribute__((always_inline)) void
__handle_packet(struct rte_mbuf *m, uint8_t portid,
                 lcore_conf_t *qconf)
{
    if (!verify_cksum(m)) {
        goto invalid;
    }

    uint16_t ether_type;
    uint8_t ipproto;
    int l2_len;
    uint32_t ipv4_addr;
    uint16_t udp_port;
    char *l3_h = NULL;
    struct ether_hdr *eth_h;
    struct ipv4_hdr *ipv4_h = NULL;
    struct ipv6_hdr *ipv6_h = NULL;
    struct udp_hdr  *udp_h = NULL;
    struct tcp_hdr  *tcp_h = NULL;
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
    l2_len = sizeof(*eth_h);

    //TODO: maybe need  remove VLAN support
    if (unlikely(ether_type == ETHER_TYPE_VLAN)) {
        struct vlan_hdr *vlan_h = (struct vlan_hdr *) ((char *) eth_h + l2_len);
        ether_type = rte_be_to_cpu_16(vlan_h->eth_proto);
        l3_h += sizeof(*vlan_h);
    }

    switch (ether_type) {
        case ETHER_TYPE_ARP:
            LOG_DEBUG(DPDK, "%d got a arp packet.", portid);
            __send_to_kni(qconf, m, portid);
            return;
        case ETHER_TYPE_IPv4:
            is_ipv4 = true;
            ipv4_h = (struct ipv4_hdr *)l3_h;

            m->l3_len = (ipv4_h->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
            src_addr = &(ipv4_h->src_addr);
            ipproto = ipv4_h->next_proto_id;
            break;
        case ETHER_TYPE_IPv6:
            ipv6_h = (struct ipv6_hdr *)l3_h;
            m->l3_len = sizeof(*ipv6_h);
            m->ol_flags |= PKT_TX_IPV6;
            src_addr = ipv6_h->src_addr;
            ipproto = ipv6_h->proto;
            break;
        default:
            goto invalid;
    }
    switch (ipproto) {
        case IPPROTO_UDP:
            udp_h = (struct udp_hdr *) (l3_h + m->l3_len);
            // check the udp port
            if (rte_be_to_cpu_16(udp_h->dst_port) != sk.port) {
                goto invalid;
            }
            break;
        case IPPROTO_TCP:
            tcp_h = (struct tcp_hdr *) (l3_h + m->l3_len);
            // check the tcp port
            if (rte_be_to_cpu_16(tcp_h->dst_port) != sk.port) {
                goto invalid;
            }
            __send_to_kni(qconf, m, portid);
            return;
        default:
            goto invalid;
    }

    m->l2_len = sizeof(struct ether_hdr);
    m->l4_len = sizeof(struct udp_hdr);

    udp_data = (void *) (udp_h + 1);
    udp_data_len = (size_t )(rte_be_to_cpu_16(udp_h->dgram_len) - 8);
    char *data_end = rte_pktmbuf_mtod(m, char*) + rte_pktmbuf_data_len(m);
    // move data end to the start of udp data.
    rte_pktmbuf_trim(m, (uint16_t)(data_end - udp_data));

    n = processUDPDnsQuery(udp_data, udp_data_len, udp_data, rte_pktmbuf_tailroom(m),
                           src_addr, udp_h->src_port, is_ipv4, qconf->node);
    if(n == ERR_CODE) goto invalid;

    ++qconf->nr_req;

    ether_addr_copy(&eth_h->s_addr, &eth_addr);
    ether_addr_copy(&eth_h->d_addr, &eth_h->s_addr);
    ether_addr_copy(&eth_addr, &eth_h->d_addr);

    if (is_ipv4) {
        ipv4_addr = ipv4_h->src_addr;
        ipv4_h->src_addr = ipv4_h->dst_addr;
        ipv4_h->dst_addr = ipv4_addr;
        ipv4_h->total_length = rte_cpu_to_be_16(m->l3_len+m->l4_len+n);
        ipv4_h->hdr_checksum = 0;
#ifdef SOFT_CKSUM
        ipv4_h->hdr_checksum = rte_ipv4_cksum(ipv4_h);
#else
        m->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM);
#endif
    } else {
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
#ifdef SOFT_CKSUM
    udp_h->dgram_cksum = get_udptcp_checksum(l3_h, udp_h, is_ipv4);
#else
    m->ol_flags |= PKT_TX_UDP_CKSUM;
    udp_h->dgram_cksum = get_psd_sum(l3_h, is_ipv4, m->ol_flags);
#endif
    LOG_DEBUG(DPDK, "udp psd checksum: 0x%x.", udp_h->dgram_cksum);
    // ethernet frame should at least contain 64 bytes(include 4 byte CRC)
    total_h_len = (int)(m->l2_len + m->l3_len + m->l4_len);
    if (n + total_h_len < 60) n = 60 - total_h_len;
    rte_pktmbuf_append(m, (uint16_t)n);
    LOG_DEBUG(DPDK, "pkt_len: %u, udp len: %zu, port: %d",
              rte_pktmbuf_pkt_len(m), udp_data_len, rte_be_to_cpu_16(udp_h->src_port));
    send_single_packet(qconf, m, portid);
    return;

invalid:
    // LOG_DEBUG(DPDK, "drop packet.");
    ++qconf->nr_dropped;
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
#ifdef PRINT_QUEUE_STAT
    uint64_t prev_print_tsc =0
    const uint64_t print_interval = (rte_get_tsc_hz() * 2);
#endif
    prev_tsc = 0;

    init_per_lcore();

    if (qconf->n_rx_queue == 0) {
        LOG_INFO(DPDK, "lcore %u has nothing to do.", lcore_id);
        return 0;
    }

    LOG_INFO(DPDK, "entering main loop on lcore %u.", lcore_id);

    for (i = 0; i < qconf->n_rx_queue; i++) {

        portid = qconf->rx_queue_list[i].port_id;
        queueid = qconf->rx_queue_list[i].queue_id;
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
            for (i = 0; i < qconf->n_tx_port; ++i) {
                portid = (uint8_t )qconf->tx_port_id[i];
                if (qconf->tx_mbufs[portid].len > 0) {
                    send_burst(qconf,
                               qconf->tx_mbufs[portid].len,
                               portid);
                    qconf->tx_mbufs[portid].len = 0;
                }
                // TODO: loop on rx port of this lcore
                if (qconf->kni_tx_mbufs[portid].len > 0) {
                    kni_send_burst(qconf,
                                   qconf->kni_tx_mbufs[portid].len,
                                   portid);
                    qconf->kni_tx_mbufs[portid].len = 0;
                }
            }

            prev_tsc = cur_tsc;
        }
#ifdef PRINT_QUEUE_STAT
        if (unlikely(cur_tsc - prev_print_tsc) > print_interval) {
            printf("core %d got %lli packets\n", lcore_id, qconf->received_req);
            prev_print_tsc = cur_tsc;
        }
#endif
        /*
         * Read packet from RX queues
         */
        for (i = 0; i < qconf->n_rx_queue; ++i) {
            portid = qconf->rx_queue_list[i].port_id;
            queueid = qconf->rx_queue_list[i].queue_id;
            nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst, MAX_PKT_BURST);
            if (nb_rx == 0)
                continue;
            qconf->received_req += nb_rx;
            // LOG_INFO(DPDK, "lcore %d receive %d packets", lcore_id, nb_rx);
            handle_packets(nb_rx, pkts_burst, portid, qconf);
        }
    }

    return 0;
}

void
initDpdkEal() {
    int ret;
    char master_lcore_cmd[128];
    char log_cmd[128];
    snprintf(master_lcore_cmd, 128, "--master-lcore=%d", sk.master_lcore_id);
    snprintf(log_cmd, 128, "--log-level=%d", str2loglevel(sk.logLevelStr));
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

int
initDpdkModule() {

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
    // default_port_conf.rx_adv_conf.rss_conf.rss_key = (uint8_t *)&key;
    // default_port_conf.rx_adv_conf.rss_conf.rss_key_len = sizeof(key);

    lcore_conf_t *qconf;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf *txconf;
    int ret;
    unsigned nb_ports;
    uint16_t queueid;
    unsigned lcore_id;
    uint32_t n_tx_queue, nb_lcores;
    uint8_t portid, nb_rx_queue, queue, socketid;

    /* parse application arguments (after the EAL ones) */
    if (sk.jumbo_on) {
        default_port_conf.rxmode.jumbo_frame = 1;
        if ((sk.max_pkt_len < 64) ||
            (sk.max_pkt_len > MAX_JUMBO_PKT_LEN)) {
            LOG_ERR(DPDK, "Invalid packet length\n");
            return -1;
        }
        default_port_conf.rxmode.max_rx_pkt_len = (uint32_t)sk.max_pkt_len;
    }

    parse_config(sk.rx_queue_config);

    if (check_lcore_params() < 0)
        rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

    ret = init_lcore_rx_queues();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

    nb_ports = rte_eth_dev_count();

    if (check_port_config(nb_ports) < 0)
        rte_exit(EXIT_FAILURE, "check_port_config failed\n");

    nb_lcores = rte_lcore_count();
    LOG_INFO(DPDK, "found %d cores, master cores: %d, %d", nb_lcores, rte_get_master_lcore(), rte_lcore_id());


    /* initialize all ports */
    for (int i = 0; i < sk.nr_ports; i++) {
        portid = (uint8_t )sk.port_ids[i];
        /* init port */
        LOG_INFO(DPDK, "Initializing port %d ... ", portid );
        fflush(stdout);

        nb_rx_queue = get_port_n_rx_queues(portid);
        /*
         * every core should has a tx queue except master core
         * every port should preserve a tx queue for kni tx thread
         */
        n_tx_queue = (uint32_t )sk.nr_lcore_ids;
        if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
            n_tx_queue = MAX_TX_QUEUE_PER_PORT;
        LOG_INFO(DPDK, "Creating queues: port=%d nb_rxq=%d nb_txq=%u...",
                 portid, nb_rx_queue, (unsigned)n_tx_queue );
        ret = rte_eth_dev_configure(portid, nb_rx_queue,
                                    (uint16_t)n_tx_queue, &default_port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                     "Cannot configure device: err=%d, port=%d\n",
                     ret, portid);

        if (check_cksum_offload(portid) < 0) {
            rte_exit(EXIT_FAILURE, "port %d doesn't support cksum offload\n", portid);
        }

        rte_eth_macaddr_get(portid, &sk.kni_conf[portid]->eth_addr);
        ether_format_addr(sk.kni_conf[portid]->eth_addr_s, ETHER_ADDR_FMT_SIZE, &sk.kni_conf[portid]->eth_addr);
        LOG_INFO(DPDK, "port %d mac address: %s.", portid, sk.kni_conf[portid]->eth_addr_s);

        /* init memory */
        ret = init_mem(NB_MBUF);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "init_mem failed\n");

        /* init one TX queue per couple (lcore,port) */
        queueid = 0;
        for (int i = 0; i < sk.nr_lcore_ids; ++i) {
            lcore_id = (unsigned )sk.lcore_ids[i];
            if (lcore_id == rte_get_master_lcore()) continue;
            assert(rte_lcore_is_enabled(lcore_id));

            if (sk.numa_on)
                socketid =
                    (uint8_t)rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            LOG_INFO(DPDK, "txq=<< lcore:%u, port: %d, queue:%d, socket:%d >>", lcore_id, portid, queueid, socketid);

            rte_eth_dev_info_get(portid, &dev_info);
            txconf = &dev_info.default_txconf;
            if (default_port_conf.rxmode.jumbo_frame)
                txconf->txq_flags = 0;
            ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
                                         socketid, txconf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_tx_queue_setup: err=%d, "
                         "port=%d\n", ret, portid);

            qconf = &sk.lcore_conf[lcore_id];
            qconf->tx_queue_id[portid] = queueid;
            queueid++;

            qconf->tx_port_id[qconf->n_tx_port] = portid;
            qconf->n_tx_port++;
        }
    }

    for (int i = 0; i < sk.nr_lcore_ids; ++i) {
        lcore_id = (unsigned )sk.lcore_ids[i];
        if (lcore_id == rte_get_master_lcore()) continue;
        assert(rte_lcore_is_enabled(lcore_id));

        qconf = &sk.lcore_conf[lcore_id];
        LOG_INFO(DPDK, "Initializing rx queues on lcore %u ... ", lcore_id );
        fflush(stdout);
        /* init RX queues */
        for(queue = 0; queue < qconf->n_rx_queue; ++queue) {
            portid = qconf->rx_queue_list[queue].port_id;
            queueid = qconf->rx_queue_list[queue].queue_id;

            if (sk.numa_on)
                socketid =
                    (uint8_t)rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            LOG_INFO(DPDK, "   rxq=<< lcore:%u, port:%d, queue:%d, socket:%d >>", lcore_id, portid, queueid, socketid);

            ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
                                         socketid,
                                         &rx_conf,
                                         pktmbuf_pool[socketid]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_rx_queue_setup: err=%d, port=%d\n",
                         ret, portid);
        }
    }

    kni_init_tx_queue();

    /* start ports */
    for (portid = 0; portid < nb_ports; portid++) {
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

    for (int i = 0; i < sk.nr_lcore_ids; ++i) {
        lcore_id = (unsigned )sk.lcore_ids[i];
        if (lcore_id == rte_get_master_lcore()) continue;
        assert(rte_lcore_is_enabled(lcore_id));

        qconf = &sk.lcore_conf[lcore_id];
        for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
            portid = qconf->rx_queue_list[queue].port_id;
            queueid = qconf->rx_queue_list[queue].queue_id;
        }
    }

    check_all_ports_link_status((uint8_t)nb_ports, sk.portmask);

    rte_timer_subsystem_init();
    sk.hz = rte_get_timer_hz();

    init_per_lcore();

    return 0;
}

int startDpdkThreads(void) {
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

int cleanupDpdkModule(void) {
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

/*
 * high performance time functions using tsc register.
 * pls note: these function may not accurate in some environments.
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
