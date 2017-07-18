//
// Created by yangyu on 17-3-13.
//
#include "fmacros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "zmalloc.h"
#include "ae.h"
// #include "protocol.h"

#define B_OK    0
#define B_ERR  -1

#define DNS_HDR_SIZE 12

// limit
#define MAX_LABEL_LEN   (63)
#define MAX_DOMAIN_LEN  (255)
#define MAX_UDP_SIZE    (512)

//0 is q,1 is r
#define QR_Q (0)
#define QR_R (1)
#define GET_QR(flag) ((flag & 0x8000) / 0x8000)
#define SET_QR_R(flag) (flag |= 0x8000)
#define SET_QR_Q(flag) (flag &= 0x7fff)
#define GET_OPCODE(flag) ((flag & 0x7800) >> 11)
#define GET_AA(flag) ((flag & 0x0400) / 0x0400)
#define SET_AA(flag) (flag |= 0x0400)
#define GET_TC(flag) ((flag & 0x0200) / 0x0200)
#define SET_TC(flag) (flag |= 0x0200)
#define GET_RD(flag) ((flag & 0x0100) / 0x0100)
#define SET_RD(flag) (flag |= 0x0100)
#define SET_RA(flag) (flag |= 0x0080)
#define GET_ERROR(flag) (flag & 0x7)
#define SET_ERROR(flag,errcode) ((flag) = (((flag) & 0xfff0) + errcode))
#define IS_PTR(os) (os >= 0xc000 && os <= 0xcfff)       //in reply msg
#define GET_OFFSET(offset) (offset & 0x3fff)    //the 2 higher bits set to 0
#define SET_OFFSET(offset) (offset |= 0xc000)
#define IS_EDNS0(flag) (flag > 0x4000 && flag < 0x4fff)

enum {
    DNS_CLASS_IN = 1
};

typedef enum dns_rr_type {
    DNS_TYPE_ANY = 255,   /**< any                                */
    DNS_TYPE_A	= 1,    /**< Host address (A) record.		    */
    DNS_TYPE_NS	= 2,    /**< Authoritative name server (NS)	    */
    DNS_TYPE_CNAME	= 5,	/**< Canonical name (CNAME) record.	    */
    DNS_TYPE_SOA	= 6,    /**< Marks start of zone authority.	    */
    DNS_TYPE_PTR	= 12,	/**< Domain name pointer.		    */
    DNS_TYPE_MX	= 15,	/**< Mail exchange record.		    */
    DNS_TYPE_TXT	= 16,	/**< Text string.			    */
    DNS_TYPE_KEY	= 25,	/**< Key.				    */
    DNS_TYPE_AAAA	= 28,	/**< IPv6 address.			    */
    DNS_TYPE_SRV	= 33,	/**< Server selection (SRV) record.	    */

    DNS_TYPE_OPT	= 41,	/**< DNS options - contains EDNS metadata.  */
    DNS_TYPE_DS	= 43,	/**< DNS Delegation Signer (DS)		    */
    DNS_TYPE_SSHFP	= 44,	/**< DNS SSH Key Fingerprint		    */
    DNS_TYPE_IPSECKEY= 45,	/**< DNS IPSEC Key.			    */
    DNS_TYPE_RRSIG	= 46,	/**< DNS Resource Record signature.	    */
    DNS_TYPE_NSEC	= 47,	/**< DNS Next Secure Name.		    */
    DNS_TYPE_DNSKEY	= 48	/**< DNSSEC Key.			    */
} dns_rr_type;

struct dnsHeader_s {
    uint16_t xid;
    uint16_t flag;
    uint16_t nQd;
    uint16_t nAnRR;
    uint16_t nNsRR;   // only contains NS records
    uint16_t nArRR;
}__attribute__((__packed__));

typedef struct dnsHeader_s dnsHeader_t;
typedef struct {
    char *host;
    int port;
    char *dns_type_str;
    uint16_t dns_type;
    char *name;
    int nr_clients;
    int requests;
    bool quiet;

    char *title;
    aeEventLoop *el;

    int nr_finished_req;
    int nr_issued_req;
    long long nr_send_bytes;
    long long nr_recv_bytes;

    long long start;
    long long totlatency;
    long long *latency;

    char *udp_packet;
    size_t udp_packet_sz;

    char addr[INET6_ADDRSTRLEN];
    char addrlen;
} settings_t;

static settings_t config;

typedef struct {
    aeEventLoop *el;
    int fd;
    long long start;
} udpClient;

int anetNonBlock(int fd);

void dump16be(uint16_t v, char *buf) {
#if (BYTE_ORDER == LITTLE_ENDIAN)
    char *x = (char *)&v, t;
    t = x[0];
    x[0] = x[1];
    x[1] = t;
#endif
    char *p = (char *)(&v);
    memcpy(buf, p, 2);
}

int strToDNSType(const char *ss) {
    if (strcasecmp(ss, "A") == 0) return DNS_TYPE_A;
    else if (strcasecmp(ss, "AAAA") == 0) return DNS_TYPE_AAAA;
    else if (strcasecmp(ss, "NS") == 0) return DNS_TYPE_NS;
    else if (strcasecmp(ss, "CNAME") == 0) return DNS_TYPE_CNAME;
    else if (strcasecmp(ss, "MX") == 0) return DNS_TYPE_MX;
    else if (strcasecmp(ss, "SOA") == 0) return DNS_TYPE_SOA;
    else if (strcasecmp(ss, "TXT") == 0) return DNS_TYPE_TXT;
    else if (strcasecmp(ss, "SRV") == 0) return DNS_TYPE_SRV;
    else if (strcasecmp(ss, "PTR") == 0) return DNS_TYPE_PTR;
    return B_ERR;
}

int dumpDNSHeader(char *buf, size_t size, uint16_t xid, uint16_t flag,
                  uint16_t nQd, uint16_t nAn, uint16_t nNs, uint16_t nAr)
{
    if (size < DNS_HDR_SIZE) {
        return B_ERR;
    }
    // ignore the byte order of xid.
    memcpy(buf, &xid, 2);
    buf += 2;
    dump16be(flag, buf);
    buf += 2;
    dump16be(nQd, buf);
    buf += 2;
    dump16be(nAn, buf);
    buf += 2;
    dump16be(nNs, buf);
    buf += 2;
    dump16be(nAr, buf);
    return DNS_HDR_SIZE;
}

static inline int dnsHeader_dump(dnsHeader_t *hdr, char *buf, size_t size) {
    return dumpDNSHeader(buf, size, hdr->xid, hdr->flag, hdr->nQd, hdr->nAnRR, hdr->nNsRR, hdr->nArRR);
}

int dumpDnsQuestion(char *buf, size_t size, char *name, uint16_t qType, uint16_t qClass) {
    char *p = buf;
    size_t nameLen = strlen(name) + 1;
    if (size < nameLen+4) {
        return B_ERR;
    }
    memcpy(p, name, nameLen);
    p += nameLen;
    dump16be(qType, p);
    p += 2;
    dump16be(qClass, p);
    return (int) (nameLen + 4);
}

udpClient *createUdpClient(aeEventLoop *el) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (anetNonBlock(fd) != B_OK) {
        close(fd);
        return NULL;
    }
    udpClient *c = zmalloc(sizeof(*c));
    c->fd =fd;
    c->el = el;
    return c;
}

void freeUdpClient(udpClient *c) {
    aeDeleteFileEvent(c->el, c->fd, AE_READABLE | AE_WRITABLE);
    close(c->fd);
}

static void usage() {
    printf("-i <addr>          remote hostname or ip \n"
           "-p <port>          remote port(default: 53)\n"
           "-r <requests>      number of requests(default: 100000) \n"
           "-n <name>          query name\n"
           "-t <dns type>      dns type \n"
           "-c <concurrency>   number of clients(default 50) \n"
           "-q                 quiet \n"
           "-h                 print this help and exit\n");
}

static void parseOptions(int argc, char *argv[]) {
    char buf[4096];
    int c;

    config.port = 53;
    config.nr_clients = 50;
    config.requests = 100000;
    config.quiet = false;

    while ((c = getopt(argc, argv, "r:i:p:t:n:c:qh")) != -1) {
        switch(c) {
        case 'i':
            config.host = zstrdup(optarg);
            break;
        case 'p':
            config.port = atoi(optarg);
            break;
        case 'h':
            usage();
            break;
        case 'q':
            config.quiet = true;
            break;
        case 't':
            config.dns_type_str = zstrdup(optarg);
            break;
        case 'n':
            config.name = zstrdup(optarg);
            break;
        case 'r':
            config.requests = atoi(optarg);
            break;
        case 'c':
            config.nr_clients = atoi(optarg);
            break;
        }
    }
    if (!config.host) {
        fprintf(stderr, "Error: you must specify the host\n");
        exit(1);
    }
    if (!config.name) {
        fprintf(stderr, "Error: you must specify the name\n");
        exit(1);
    }
    if (!config.dns_type_str) {
        fprintf(stderr, "Error: you must specify the dns type.\n");
        exit(1);
    }
    int type = strToDNSType(config.dns_type_str);
    if (type == B_ERR) {
        fprintf(stderr, "Error: invalid dns type(%s)\n", config.dns_type_str);
        exit(1);
    }
    config.dns_type = (uint16_t)type;

    config.latency = zmalloc(sizeof(long long) * config.requests);
    snprintf(buf, 4096, "<%s @%s>", config.name, config.dns_type_str);
    config.title = zstrdup(buf);
    // initialize the address.
    struct sockaddr_in *addr = (struct sockaddr_in *) (config.addr);
    config.addrlen = sizeof(*addr);

    bzero(addr, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(config.port);
    inet_pton(AF_INET, config.host, &(addr->sin_addr));
}

bool endswith(const char *str, const char *suffix) {
    const char *p = str + (strlen(str) - strlen(suffix));
    if (p < str) return false;
    return strcmp(p, suffix) == 0;
}

static long long ustime(void) {
    struct timeval tv;
    long long ust;

    gettimeofday(&tv, NULL);
    ust = ((long)tv.tv_sec)*1000000;
    ust += tv.tv_usec;
    return ust;
}

static long long mstime(void) {
    struct timeval tv;
    long long mst;

    gettimeofday(&tv, NULL);
    mst = ((long long)tv.tv_sec)*1000;
    mst += tv.tv_usec/1000;
    return mst;
}

int anetSetBlock(int fd, int non_block) {
    int flags;

    /* Set the socket blocking (if non_block is zero) or non-blocking.
     * Note that fcntl(2) for F_GETFL and F_SETFL can't be
     * interrupted by a signal. */
    if ((flags = fcntl(fd, F_GETFL)) == -1) {
        fprintf(stderr, "fcntl(F_GETFL): %s", strerror(errno));
        return B_ERR;
    }

    if (non_block)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) == -1) {
        fprintf(stderr, "fcntl(F_SETFL,O_NONBLOCK): %s", strerror(errno));
        return B_ERR;
    }
    return B_OK;
}

int anetNonBlock(int fd) {
    return anetSetBlock(fd,1);
}

static int dot2lenlabel(char *human, char *label) {
    char *dest = label;
    if (dest == NULL) dest = human;
    size_t totallen = strlen(human);
    *(dest + totallen) = 0;
    char *prev = human + totallen - 1;
    char *src = human + totallen - 2;
    dest = dest + totallen - 1;

    for (; src >= human; src--, dest--) {
        if (*src == '.') {
            *dest = (uint8_t) (prev - src - 1);
            prev = src;
        } else {
            *dest = *src;
        }
    }
    *dest = (uint8_t) (prev - src - 1);
    return 0;
}

static int showThroughput(struct aeEventLoop *el, long long id, void *clientData) {
    ((void) el); ((void) id); ((void) clientData);

    float dt = (float)(mstime()-config.start)/1000.0;
    float rps = (float)config.nr_finished_req/dt;
    float rx = (float)config.nr_recv_bytes/(dt*1024.0);
    float tx = (float)config.nr_send_bytes/(dt*1024.0);
    printf("%s: %.2f   RX: %.2f kb/s  TX: %.2f kb/s \r", config.title, rps, rx, tx);
    fflush(stdout);
    return 250; /* every 250ms */
}

static void initPacket() {
    char buf[4096];
    char name[MAX_DOMAIN_LEN+2];
    char *start = buf;
    dnsHeader_t hdr = {0, 0, 1, 0, 0, 0};
    SET_RD(hdr.flag);

    strncpy(name, config.name, MAX_DOMAIN_LEN);
    if (endswith(name, ".") == false) {
        strncat(name, ".", 2);
    }
    dot2lenlabel(name, NULL);

    dnsHeader_dump(&hdr, start, DNS_HDR_SIZE);
    start += DNS_HDR_SIZE;
    int n = dumpDnsQuestion(start, 4096-DNS_HDR_SIZE, name, config.dns_type, DNS_CLASS_IN);

    config.udp_packet_sz = n + DNS_HDR_SIZE;
    config.udp_packet = zmemdup(buf, config.udp_packet_sz);
}

static void udpWriteCb(struct aeEventLoop *el, int fd, void *privdata, int mask);

static void udpReadCb(struct aeEventLoop *el, int fd, void *privdata, int mask) {
    ((void) mask);
    // fprintf(stderr, "read event\n");

    char data[8192];
    udpClient *c = privdata;

    ssize_t n = recvfrom(fd, data, 8192, 0, NULL, NULL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        fprintf(stderr, "Can't receive udp message: %s", strerror(errno));
        freeUdpClient(c);
        return;
    }
    config.nr_recv_bytes += n;

    config.latency[config.nr_finished_req++] = ustime() - c->start;
    if (config.nr_finished_req >= config.requests) {
        freeUdpClient(c);
        aeStop(el);
        return;
    }
    aeDeleteFileEvent(el, fd, AE_READABLE);
    aeCreateFileEvent(el, fd, AE_WRITABLE, udpWriteCb, c);
}

static void udpWriteCb(struct aeEventLoop *el, int fd, void *privdata, int mask) {
    ((void) mask);

    // fprintf(stderr, "write event\n");
    udpClient *c = privdata;
    uint16_t *xid = (uint16_t *) (config.udp_packet);
    (*xid)++;
    c->start = ustime();

    if (config.nr_issued_req >= config.requests) {
        aeDeleteFileEvent(el, fd, AE_WRITABLE);
        return;
    }

    ssize_t n = sendto(fd, config.udp_packet, config.udp_packet_sz, 0, (struct sockaddr*)(config.addr), config.addrlen);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        // when get an error, we just print error message and skip this context.
        fprintf(stderr, "Can't send udp message to server: %s", strerror(errno));
        freeUdpClient(c);
        return;
    }
    config.nr_issued_req++;
    config.nr_send_bytes += (config.udp_packet_sz);

    aeDeleteFileEvent(el, fd, AE_WRITABLE);
    aeCreateFileEvent(el, fd, AE_READABLE, udpReadCb, c);
}

static int compareLatency(const void *a, const void *b) {
    return (*(long long*)a)-(*(long long*)b);
}

static void showLatencyReport(void) {
    int i, curlat = 0;
    float perc, reqpersec, rx, tx;

    reqpersec = (float)config.nr_finished_req/((float)config.totlatency/1000);
    tx = (float)config.nr_send_bytes/1024.0;
    rx = (float)config.nr_recv_bytes/1024.0;
    // clear the first line
    char buf[80];
    memset(buf, ' ', 80);
    buf[79] = 0;
    printf("%s\r", buf);
    fflush(stdout);

    if (!config.quiet) {
        printf("====== %s ======\n", config.title);
        printf("  %d requests completed in %.2f seconds\n", config.nr_finished_req,
               (float)config.totlatency/1000);
        printf("  %d parallel clients\n", config.nr_clients);
        printf("\n");

        qsort(config.latency,config.requests,sizeof(long long),compareLatency);
        for (i = 0; i < config.requests; i++) {
            if (config.latency[i]/1000 != curlat || i == (config.requests-1)) {
                curlat = config.latency[i]/1000;
                perc = ((float)(i+1)*100)/config.requests;
                printf("%.2f%% <= %d milliseconds\n", perc, curlat);
            }
        }
        printf("%.2f requests per second\n", reqpersec);
        printf("RX bytes (%.2f kb)  TX bytes (%.2f kb)\n\n", rx, tx);
    } else {
        printf("%s: %.2f requests per second\n", config.title, reqpersec);
        printf("RX bytes (%.2f kb)  TX bytes (%.2f kb)\n\n", rx, tx);
    }
}

int main(int argc, char *argv[]) {
    memset(&config, 0, sizeof(config));
    parseOptions(argc, argv);
    initPacket();

    config.el = aeCreateEventLoop(128, true);
    aeCreateTimeEvent(config.el, 1, showThroughput, NULL, NULL);

    for (int i = 0; i < config.nr_clients; ++i) {
        udpClient *c = createUdpClient(config.el);
        if (c == NULL) {
            fprintf(stderr, "Can't create udp client");
            abort();
        }
        aeCreateFileEvent(config.el, c->fd, AE_WRITABLE, udpWriteCb, c);
    }
    config.start = mstime();
    aeMain(config.el);
    config.totlatency = mstime() - config.start;
    showLatencyReport();
    return 0;
}
