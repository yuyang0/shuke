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
    edns_t edns;
    struct clientSubnetOpt subnet_opt;

    size_t ari_sz;
    size_t cps_sz;
    arInfo ari[AR_INFO_SIZE];
    compressInfo cps[CPS_INFO_SIZE];
};

int contextMakeRoomForResp(struct context *ctx, int addlen);

int RRSetCompressPack(struct context *ctx, RRSet *rs, size_t nameOffset);

sds sdscatpack(sds s, char const *fmt, ...);
#if defined(SK_TEST)
int zoneParserTest(int argc, char *argv[]);
int dsTest(int argc, char *argv[]);
#endif

#endif //CDNS_DS_H
