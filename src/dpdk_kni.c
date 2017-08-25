//
// Created by yangyu on 17-6-15.
//

#ifndef ONLY_UDP

#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "shuke.h"

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

typedef struct {
    struct rte_kni *kni;
    struct rte_ring *kni_rp;

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
kni_ifconfig(char *ifname, char *ipaddr) {

    struct ifreq ifr;
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    int sockfd;                     /* socket fd we use to manipulate stuff with */
    // int selector;

    int ret;

    /* Create a channel to the NET kernel. */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* get interface name */
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ipaddr, &addr->sin_addr);

    ret = ioctl(sockfd, SIOCSIFADDR, &ifr);
    if (ret < 0) {
        LOG_ERROR(KNI, "set address error %s\n", strerror(errno));
        exit(-1);
    }
    ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);

    if (ret < 0) {
        LOG_ERROR(KNI, "get flags error %s\n", strerror(errno));
        exit(-1);
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    // ifr.ifr_flags &= ~selector;  // unset something

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
        sk_kni_conf_t *kconf = kni_conf_list[portid];
        kni_ifconfig(kconf->veth_name, sk.bindaddr[i]);
    }
    return OK_CODE;
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

static int
kni_process_tx(uint8_t port_id, uint16_t queue_id,
               struct rte_mbuf **pkts_burst, unsigned count)
{
    (void)queue_id;
    sk_kni_conf_t *kconf = kni_conf_list[port_id];
    /* read packet from kni ring(phy port) and transmit to kni */
    uint16_t nb_tx, nb_kni_tx;
    nb_tx = rte_ring_dequeue_burst(kconf->kni_rp, (void **)pkts_burst, count, NULL);

    /* NB.
     * if nb_tx is 0,it must call rte_kni_tx_burst
     * must Call regularly rte_kni_tx_burst(kni, NULL, 0).
     * detail https://embedded.communities.intel.com/thread/6668
     */
    nb_kni_tx = rte_kni_tx_burst(kconf->kni, pkts_burst, nb_tx);
    rte_kni_handle_request(kconf->kni);
    if(nb_kni_tx < nb_tx) {
        uint16_t i;
        for(i = nb_kni_tx; i < nb_tx; ++i)
            rte_pktmbuf_free(pkts_burst[i]);

        kconf->rx_dropped += (nb_tx - nb_kni_tx);
    }

    kconf->rx_packets += nb_kni_tx;
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
sk_kni_process(uint8_t port_id, uint16_t queue_id,
               struct rte_mbuf **pkts_burst, unsigned count)
{
    kni_process_tx(port_id, queue_id, pkts_burst, count);
    kni_process_rx(port_id, queue_id, pkts_burst, count);
}

/* enqueue the packet, and own it */
int sk_kni_enqueue(uint8_t portid, struct rte_mbuf *pkt)
{
    sk_kni_conf_t *kconf = kni_conf_list[portid];
    int ret = rte_ring_enqueue(kconf->kni_rp, pkt);
    if (ret < 0)
        rte_pktmbuf_free(pkt);

    return 0;
}

/* Initialize KNI subsystem */
void
sk_init_kni_module(unsigned socket_id, struct rte_mempool *mbuf_pool)
{
    rte_kni_init(sk.nr_ports);
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

        kconf->kni_rp = rte_ring_create(ring_name, KNI_QUEUE_SIZE,
                                        socket_id, RING_F_SC_DEQ);
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

#endif
