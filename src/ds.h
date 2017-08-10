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

#define DS_OK     0
#define DS_ERR   -1
#define DS_EOF    1

#define PARSER_OK    0
#define PARSER_ERR  -1

#define IP_STR_LEN  INET6_ADDRSTRLEN

struct numaNode_s;

struct context {
    struct  numaNode_s *node;
    int lcore_id;
    struct _zone *z;
    // information parsed from dns query packet.
    dnsHeader_t hdr;
    // information of question.
    // name just points to the recv buffer, so never free this pointer
    char *name;
    size_t nameLen;
    // when finished use dname, you need call resetDname to free the memory.
    // dname_t dname;

    uint16_t qType;
    uint16_t qClass;

    char *resp;
    size_t totallen;
    int cur;
};

typedef struct {
    int err;
    char errstr[ERR_STR_LEN];

    char *data[64];
    char **tokens;
    int ntokens;
    int start_idx;

    uint16_t type;

    uint32_t ttl;
    // the relative name (len label format)
    char name[MAX_DOMAIN_LEN+2];
    // the dot origin this RR belongs to.
    char dotOrigin[MAX_DOMAIN_LEN+2];
} RRParser;

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
  a collection of RR whose name and type are same.
  every RR has the following format.

  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                 rdlength                      |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                 rdata(var)                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  rdlength is encoded in big endian.
  NOTICE: SOA and CNAME don't allow multiple records for same name.
*/
typedef struct {
    int socket_id;

    uint16_t num;          // the number of RR
    uint16_t type;         // RRSet type
    unsigned int free;     //
    unsigned int len;      // the bytes of data(actually used size)
    uint32_t ttl;          // every RR in RRSet has same ttl

    size_t *offsets;       // offset array, mainly for round rabin
    int z_rr_idx;          // round rabin index position in zone

    char data[];
} RRSet;

// CNAME record sets cannot coexist with other record sets with the same name
#define SUPPORT_TYPE_NUM    (9)
struct _typeValue
{
    RRSet *A;
    RRSet *NS;
    RRSet *CNAME;
    RRSet *SOA;
    RRSet *MX;
    RRSet *TXT;
    RRSet *AAAA;
    RRSet *SRV;
    RRSet *PTR;
};

typedef struct _dnsDictValue {
    union {
        struct _typeValue tv;
        RRSet *rsArr[SUPPORT_TYPE_NUM];
    }v;
} dnsDictValue;

typedef struct _zone {
    int socket_id;
    char *origin;          // in <len label> format
    char *dotOrigin;       // in <label dot> format
    size_t originLen;
    uint32_t default_ttl;  // $TTL directive
    // the key is the relative name(len label),
    // if the key is origin, then use @
    // the value is dnsDictValue instance
    dict *d;

    // just two pointer to the RRSet object stored in dict,
    // never free these two pointer.
    RRSet *soa;
    RRSet *ns;

    // some information of SOA record.
    uint32_t sn;
    int32_t refresh;
    int32_t retry;
    int32_t expiry;
    int32_t nx;

    /*
     * round rabin information for RRSet
     * in order to avoid atomic operation, we prepare a per-core rr_idx for every rrset object.
     */
    int start_core_idx;  // start core of the numa node this zone belongs to
    /*
     * the memory layout is
     * -----------------------------------------------
     * |  |  |  |  |  |  |      |      |      |      |
     * -----------------------------------------------
     * the first half is an offset array, every offset should point to the rr_idx array,
     * every core in the numa node this zone belongs to should have an element in this array,
     * in order to decrease the array size, we store the start core idx,
     * so when you fetch the rr_idx array, you should use lcore_id-start_core_idx as the array index.
     *
     * the second half is the real rr_idx array, every rrset has a z_rr_idx field, use this field
     * to get the rr_idx for this rrset.
     */
    uint32_t *rr_offset_array;
    size_t rr_mem_size;

    // timestamp when this zone needs reload
    long refresh_ts;
    struct rb_node rbnode;
    struct cds_lfht_node htnode;
    struct rcu_head rcu_head;
} zone;

typedef struct _zoneDict {
    int socket_id;
    // the key is the origin of the zone(len label format)
    // the value is zone instance.
    struct cds_lfht *ht;
} zoneDict;

#define zoneDictRLock(zd) rcu_read_lock()
#define zoneDictRUnlock(zd) rcu_read_unlock()
#define zoneDictWLock(zd) rcu_read_lock()
#define zoneDictWUnlock(zd) rcu_read_unlock()

RRSet *RRSetCreate(uint16_t type, int socket_id);
RRSet *RRSetDup(RRSet *rs, int socket_id);
void RRSetUpdateOffsets(RRSet *rs);
RRSet* RRSetCat(RRSet *rs, char *buf, size_t len);
RRSet *RRSetRemoveFreeSpace(RRSet *rs);

int RRSetCompressPack(struct context *ctx, RRSet *rs, size_t nameOffset,
                      compressInfo *cps, size_t *cps_sz, size_t cps_sz_max,
                      arInfo *ari, size_t *ar_sz, size_t ar_sz_max);
sds RRSetToStr(RRSet *rs);

void RRSetDestroy(RRSet *rs);

RRSet *dnsDictValueGet(dnsDictValue *dv, int type);
void dnsDictValueSet(dnsDictValue *dv, RRSet *rs);
dnsDictValue *dnsDictValueCreate(int socket_id);
dnsDictValue *dnsDictValueDup(dnsDictValue *dv, int socket_id);
void dnsDictValueDestroy(dnsDictValue *val, int socket_id);

zone *zoneCreate(char *origin, int socket_id);
zone *zoneCopy(zone *z, int socket_id);
void zoneDestroy(zone *zn);
dnsDictValue *zoneFetchValueAbs(zone *z, void *key, size_t keyLen);
dnsDictValue *zoneFetchValueRelative(zone *z, void *key);
RRSet *zoneFetchTypeVal(zone *z, void *key, uint16_t type);
int zoneReplace(zone *z, void *key, dnsDictValue *val);
int zoneReplaceTypeVal(zone *z, char *key, RRSet *rs);
sds zoneToStr(zone *z);

/*----------------------------------------------
 *     zone dict declaration
 *---------------------------------------------*/
int zoneDictHtMatch(struct cds_lfht_node *ht_node, const void *_key);
void zoneDictFreeCallback(struct rcu_head *head);

unsigned int zoneDictHash(char *buf, size_t len);
zoneDict *zoneDictCreate(int socket_id);

void zoneDictDestroy(zoneDict *zd);
zone *zoneDictFetchVal(zoneDict *zd, char *key);

zone *zoneDictGetZone(zoneDict *zd, char *name);

int zoneDictReplace(zoneDict *zd, zone *z);
int zoneDictAdd(zoneDict *zd, zone *z);

int zoneDictDelete(zoneDict *zd, char *origin);
int zoneDictEmpty(zoneDict *zd);
size_t zoneDictGetNumZones(zoneDict *zd);
int zoneDictExistZone(zoneDict *zd, char *origin);
sds zoneDictToStr(zoneDict *zd);

// parser
RRParser *RRParserCreate(char *name, uint32_t ttl, char *dotOrigin);
void RRParserDestroy(RRParser *psr);
int RRParserSetDotOrigin(RRParser *psr, char *dotOrigin);
int RRParserFeed(RRParser *psr, char *ss, char *name, zone *z);
int RRParserFeedRdata(RRParser *psr, char *rdata, char *name, uint32_t ttl, char *type, zone *z);

int parseSOASn(char *errstr, char *soa, unsigned long *sn);
int abs2lenRelative(char domain[], char *dotOrigin);
int loadZoneFromStr(char *errstr, int socket_id, char *zbuf, zone **zpp);
int loadZoneFromFile(int socket_id, const char *fname, zone **zpp);

sds sdscatpack(sds s, char const *fmt, ...);
static inline bool isAbsDotDomain(char *ss) {
    return endswith(ss, ".");
}

extern dictType dnsDictType;
extern const struct cds_lfht_mm_type cds_lfht_mm_socket;

#if defined(SK_TEST)
int zoneParserTest(int argc, char *argv[]);
int dsTest(int argc, char *argv[]);
#endif

#endif //CDNS_DS_H
