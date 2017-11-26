//
// Created by yangyu on 17-2-16.
//

#ifndef __DS_H
#define __DS_H
#include <stdint.h>
#include <netinet/in.h>

#include <urcu.h>		/* RCU flavor */
#include <urcu/rculfhash.h>	/* RCU Lock-free hash table */
#include <urcu/compiler.h>	/* For CAA_ARRAY_SIZE */

#include <rte_rwlock.h>
#include <rte_atomic.h>

#include "sds.h"
#include "dict.h"
#include "rbtree.h"
#include "defines.h"
#include "str.h"
#include "protocol.h"
#include "edns.h"
#include "zone.h"

#define IP_STR_LEN  INET6_ADDRSTRLEN


#define AR_INFO_SIZE   64
#define CPS_INFO_SIZE  64

struct numaNode_s;

// this struct is used to track the compress information in the response.
typedef struct {
    char *name;
    int offset;
    int uncompress_len;
} compressInfo;

// used to do additional section processing.
typedef struct {
    char *name;
    // offset of the name in the buffer, used to compress the name.
    int offset;
} arInfo;

/*
 * indicate the place where the memory of response stays
 */
enum ctxRespType {
    RESP_STACK,
    RESP_HEAP,
    RESP_MBUF,
};

typedef struct {
    union {
        struct sockaddr_in6 sin6;
        struct sockaddr_in  sin;
        struct sockaddr     sa;
    };
    socklen_t len;
} genericAddr_t;

struct clientInfo {
    genericAddr_t dns_source;       // address of last source DNS cache/forwarder
    genericAddr_t edns_client;      // edns-client-subnet address portion
    unsigned edns_client_mask; // edns-client-subnet mask portion
};

struct context {
    // information relate to response
    enum ctxRespType resp_type;
    struct rte_mbuf *m;
    /*
     * current chuck of response.
     * TCP response only has one chunk
     * UDP response may contain multiple chunks, every segment of mbuf is a chunk
     */
    char *chunk;
    int chunk_len;
    // current write position of this chunk
    int cur;

    struct  numaNode_s *node;
    int lcore_id;
    struct _zone *z;
    // information parsed from dns query packet.
    dnsHeader_t hdr;
    // information of question.
    // name just points to the recv buffer, so never free this pointer
    char *name;
    size_t nameLen;

    uint16_t qType;
    uint16_t qClass;

    // EDNS(0) related fields
    bool hasEdns;
    bool hasClientSubnetOpt;
    uint16_t max_resp_size;

    struct clientInfo cinfo;

    // the OPT RR for response
    uint8_t opt_rr[11+24];
    uint16_t opt_rr_len;

    size_t ari_sz;
    size_t cps_sz;
    arInfo ari[AR_INFO_SIZE];
    compressInfo cps[CPS_INFO_SIZE];
};

typedef enum {
    DECODE_IGNORE  = -4, // totally invalid packet (len < header len or unparseable question, and we do not respond)
    DECODE_FORMERR = -3, // slightly better but still invalid input, we return FORMERR
    DECODE_BADVERS = -2, // EDNS version higher than ours (0)
    DECODE_NOTIMP  = -1, // non-QUERY opcode or [AI]XFER, we return NOTIMP
    DECODE_OK      =  0, // normal and valid
} decodeRcode;

bool isSupportDnsType(uint16_t type);
int checkLenLabel(char *name, size_t max);
char *abs2relative(char *name, char *origin);

int strToDNSType(const char *ss);
char *DNSTypeToStr(int ty);

int parseDNSHeader(char *buf, size_t size, uint16_t *xid, uint16_t *flag,
                   uint16_t *nQd, uint16_t *nAn, uint16_t *nNs, uint16_t *nAr);
int dumpDNSHeader(char *buf, size_t size, uint16_t xid, uint16_t flag,
                  uint16_t nQd, uint16_t nAn, uint16_t nNs, uint16_t nAr);

static inline int dnsHeader_load(char *buf, size_t size, dnsHeader_t *hdr) {
    return parseDNSHeader(buf, size, &(hdr->xid), &(hdr->flag), &(hdr->nQd),
                          &(hdr->nAnRR), &(hdr->nNsRR), &(hdr->nArRR));
}
static inline int dnsHeader_dump(dnsHeader_t *hdr, char *buf, size_t size) {
    return dumpDNSHeader(buf, size, hdr->xid, hdr->flag, hdr->nQd, hdr->nAnRR, hdr->nNsRR, hdr->nArRR);
}

int parseDnsQuestion(char *buf, size_t size, char **name, uint16_t *qType, uint16_t *qClass);
decodeRcode decodeQuery(char *buf, size_t sz, struct context *ctx);
int dumpDnsResp(struct context *ctx, dnsDictValue *dv, zone *z);
int dumpDnsError(struct context *ctx, int err);

int contextMakeRoomForResp(struct context *ctx, int addlen);

int RRSetCompressPack(struct context *ctx, RRSet *rs, size_t nameOffset);

sds sdscatpack(sds s, char const *fmt, ...);
#if defined(SK_TEST)
int zoneParserTest(int argc, char *argv[]);
int dsTest(int argc, char *argv[]);
#endif

#endif //CDNS_DS_H
