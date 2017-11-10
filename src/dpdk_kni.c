//
// Created by yangyu on 17-6-15.
//

#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "shuke.h"

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

typedef struct {
    struct rte_kni *kni;

    /* number of pkts received from NIC, and sent to KNI */
    uint64_t rx_packets;
    /* number of pkts received from NIC, but failed to send to KNI */
    uint64_t rx_dropped;
    /* number of pkts received from KNI, and sent to NIC */
    uint64_t tx_packets;
    /* number of pkts received from KNI, but failed to send to NIC */
    uint64_t tx_dropped;

    char veth_name[RTE_KNI_NAMESIZE];
} sk_kni_conf_t;

/* kni device statistics array */
static sk_kni_conf_t *kni_conf_list[RTE_MAX_ETHPORTS];

static int kni_change_mtu(uint8_t port_id, unsigned new_mtu);
static int kni_config_network_interface(uint8_t port_id, uint8_t if_up);

static int
kni_ifconfig(int portid, char *ipaddr) {
    sk_kni_conf_t *kconf = kni_conf_list[portid];
    port_info_t *pinfo = sk.port_info[portid];
    char *ifname = kconf->veth_name;
    struct ifreq ifr;
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    int sockfd;                     /* socket fd we use to manipulate stuff with */

    int ret;

    /* Create a channel to the NET kernel. */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* set interface name */
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    /* configure mac address */
    memcpy(ifr.ifr_hwaddr.sa_data, pinfo->eth_addr.addr_bytes, ETHER_ADDR_LEN);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    ret = ioctl(sockfd, SIOCSIFHWADDR, &ifr);
    if (ret < 0) {
        LOG_ERROR(KNI, "set mac address error %s\n", strerror(errno));
        exit(-1);
    }
    /* config ipv4 address */
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ipaddr, &addr->sin_addr);
    ret = ioctl(sockfd, SIOCSIFADDR, &ifr);
    if (ret < 0) {
        LOG_ERROR(KNI, "set ipv4 address error %s\n", strerror(errno));
        exit(-1);
    }
    /* get flags */
    ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
    if (ret < 0) {
        LOG_ERROR(KNI, "get flags error %s\n", strerror(errno));
        exit(-1);
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    /* set flags */
    ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
    if (ret < 0) {
        LOG_ERROR(KNI, "set flags error %s\n", strerror(errno));
        exit(-1);
    }
    close(sockfd);
    return OK_CODE;
}

int kni_ifconfig_all()
{
    for (int i = 0; i < sk.nr_ports; ++i) {
        int portid = sk.port_ids[i];
        kni_ifconfig(portid, sk.bindaddr[i]);
    }
    return OK_CODE;
}

/*
 * check if all kni virtual interfaces are up.
 */
bool is_all_veth_up() {
    for (int i = 0; i < sk.nr_ports; ++i) {
        int portid = sk.port_ids[i];
        sk_kni_conf_t *kconf = kni_conf_list[portid];
        char *ifname = kconf->veth_name;

        struct ifreq ifr;
        int sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, ifname);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
            LOG_WARN(KNI, "SIOCGIFFLAGS %s", strerror(errno));
        }
        close(sock);
        if((ifr.ifr_flags & IFF_UP) == 0) {
            LOG_DEBUG(KNI, "%s is not up.", ifname);
            return false;
        }
    }
    return true;
}

/* Callback for request of changing MTU */
static int
kni_change_mtu(uint8_t port_id, unsigned new_mtu)
{
    (void)port_id, (void)new_mtu;
    return 0;
}

/* Callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint8_t port_id, uint8_t if_up)
{
    int ret = 0;

    if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
        LOG_ERR(KNI, "Invalid port id %d\n", port_id);
        return -EINVAL;
    }

    LOG_INFO(KNI, "Configure network interface of %d %s.",
            port_id, if_up ? "up" : "down");

    return ret;
}

static int
kni_alloc(uint8_t port_id, struct rte_mempool *mbuf_pool)
{
    sk_kni_conf_t *kconf = kni_conf_list[port_id];
    struct rte_kni *kni;

    struct rte_kni_ops ops;
    struct rte_eth_dev_info dev_info;
    struct rte_kni_conf conf;

    assert(port_id < RTE_MAX_ETHPORTS);

    /* Clear conf at first */
    memset(&conf, 0, sizeof(conf));
    strncpy(conf.name, kconf->veth_name, RTE_KNI_NAMESIZE);
    conf.core_id = (uint32_t )sk.master_lcore_id;
    conf.force_bind = 1;
    conf.group_id = (uint16_t)port_id;

    uint16_t mtu;
    rte_eth_dev_get_mtu(port_id, &mtu);
    conf.mbuf_size = mtu + KNI_ENET_HEADER_SIZE + KNI_ENET_FCS_SIZE;
    /*
     * The first KNI device associated to a port
     * is the master, for multiple kernel thread
     * environment.
     */

    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);
    conf.addr = dev_info.pci_dev->addr;
    conf.id = dev_info.pci_dev->id;

    memset(&ops, 0, sizeof(ops));
    ops.port_id = port_id;
    ops.change_mtu = kni_change_mtu;
    ops.config_network_if = kni_config_network_interface;

    kni = rte_kni_alloc(mbuf_pool, &conf, &ops);

    if (!kni)
        rte_exit(EXIT_FAILURE, "Fail to create kni for "
                "port: %d\n", port_id);
    kconf->kni = kni;

    return 0;
}

/* Send burst of packets on an output interface */
static inline int
kni_send_burst(lcore_conf_t *qconf, uint16_t n, uint8_t port)
{

    sk_kni_conf_t *kconf = kni_conf_list[port];
    struct rte_mbuf **m_table;
    int nb_kni_tx = 0;

    m_table = (struct rte_mbuf **)qconf->kni_tx_mbufs[port].m_table;
    nb_kni_tx = rte_kni_tx_burst(kconf->kni, m_table, n);
    if (unlikely(nb_kni_tx < n)) {
        for (int i = nb_kni_tx; i < n; ++i) {
            rte_pktmbuf_free(m_table[i]);
        }
    }

    qconf->kni_tx_mbufs[port].len = 0;
    return nb_kni_tx;
}

/* Enqueue a single packet, and send burst if queue is filled */
int
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

static int
kni_process_tx(lcore_conf_t *qconf, uint8_t port_id)
{
    sk_kni_conf_t *kconf = kni_conf_list[port_id];
    /* read packet from kni ring(phy port) and transmit to kni */
    uint16_t nb_tx=0;
    int nb_kni_tx=0;
    nb_tx = qconf->kni_tx_mbufs[port_id].len;
    if (nb_tx > 0) {
        nb_kni_tx = kni_send_burst(qconf,
                                   qconf->kni_tx_mbufs[port_id].len,
                                   port_id);
        qconf->kni_tx_mbufs[port_id].len = 0;
        if(nb_kni_tx < nb_tx) {
            kconf->rx_dropped += (nb_tx - nb_kni_tx);
        }
        kconf->rx_packets += nb_kni_tx;

        LOG_DEBUG(KNI, "port %d got %d packets and send %d packets to kni.", port_id, nb_tx, nb_kni_tx);
    }
    rte_kni_handle_request(kconf->kni);
    return 0;
}

static int
kni_process_rx(uint8_t port_id, uint16_t queue_id,
               struct rte_mbuf **pkts_burst, unsigned count)
{
    sk_kni_conf_t *kconf = kni_conf_list[port_id];
    uint16_t nb_kni_rx, nb_rx;

    /* read packet from kni, and transmit to phy port */
    nb_kni_rx = rte_kni_rx_burst(kconf->kni, pkts_burst, count);

    if (nb_kni_rx > 0) {
        nb_rx = rte_eth_tx_burst(port_id, queue_id, pkts_burst, nb_kni_rx);
        LOG_DEBUG(KNI, "recieve %d packets from KNI and send %d packet to port %d, queue %d.", nb_kni_rx, nb_rx, port_id, queue_id);
        if (nb_rx < nb_kni_rx) {
            uint16_t i;
            for(i = nb_rx; i < nb_kni_rx; ++i)
                rte_pktmbuf_free(pkts_burst[i]);

            kconf->tx_dropped += (nb_kni_rx - nb_rx);
        }

        kconf->tx_packets += nb_rx;
    }
    return 0;
}

void
sk_kni_process(lcore_conf_t *qconf, uint8_t port_id, uint16_t queue_id, struct rte_mbuf **pkts_burst, unsigned count)
{
    kni_process_tx(qconf, port_id);
    kni_process_rx(port_id, queue_id, pkts_burst, count);
}

/* Initialize KNI subsystem */
void
sk_init_kni_module(struct rte_mempool *mbuf_pool)
{
    rte_kni_init(rte_eth_dev_count());
    for (int i = 0; i < sk.nr_ports; ++i) {
        int portid = sk.port_ids[i];
        assert(kni_conf_list[portid] == NULL);
        kni_conf_list[portid] = rte_zmalloc("kni:conf",
                                            sizeof(sk_kni_conf_t),
                                            RTE_CACHE_LINE_SIZE);
        sk_kni_conf_t *kconf = kni_conf_list[portid];
        snprintf(kconf->veth_name, RTE_KNI_NAMESIZE, "vEth%u", portid);
        kni_alloc(portid, mbuf_pool);

        char ring_name[RTE_KNI_NAMESIZE];
        snprintf((char*)ring_name, RTE_KNI_NAMESIZE, "kni_ring_%u", portid);
    }
}

int
cleanup_kni_module()
{
    sk_kni_conf_t *kconf;
    /* Release resources */
    for (int i = 0; i < sk.nr_ports; i++) {
        int portid = sk.port_ids[i];
        kconf = kni_conf_list[portid];
        if (rte_kni_release(kconf->kni))
            LOG_ERR(KNI, "Fail to release kni\n");
    }
#ifdef RTE_LIBRTE_XEN_DOM0
    rte_kni_close();
#endif

    // rte_eth_dev_stop(port_id);
    return 0;
}
