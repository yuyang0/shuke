//
// Created by yangyu on 17-2-16.
//

#ifndef __DS_H
#define __DS_H
#include <stdint.h>
#include <netinet/in.h>

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
    unsigned int len;      // the bytes of data
    uint32_t ttl;          // every RR in RRSet has same ttl

    size_t *offsets;       // offset array, mainly for round rabin
    rte_atomic32_t rr_idx;         // last round rabin index

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

    // timestamp when this zone needs reload
    long refresh_ts;
    struct rb_node node;
} zone;

typedef struct _zoneDict {
    int socket_id;
    rte_rwlock_t lock;
    // the key is the origin of the zone(len label format)
    // the value is zone instance.
    dict *d;
} zoneDict;

#define zoneDictRLock(zd) rte_rwlock_read_lock(&((zd)->lock))
#define zoneDictRUnlock(zd) rte_rwlock_read_unlock(&((zd)->lock))
#define zoneDictWLock(zd) rte_rwlock_write_lock(&((zd)->lock))
#define zoneDictWUnlock(zd) rte_rwlock_write_unlock(&((zd)->lock))
#define zoneDictInitLock(zd) rte_rwlock_init(&((zd)->lock))
#define zoneDictDestroyLock(zd)

RRSet *RRSetCreate(uint16_t type, int socket_id);
RRSet *RRSetDup(RRSet *rs, int socket_id);
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
void zoneUpdateRRSetOffsets(zone *z);
dnsDictValue *zoneFetchValueAbs(zone *z, void *key, size_t keyLen);
dnsDictValue *zoneFetchValueRelative(zone *z, void *key);
RRSet *zoneFetchTypeVal(zone *z, void *key, uint16_t type);
int zoneReplace(zone *z, void *key, dnsDictValue *val);
int zoneReplaceTypeVal(zone *z, char *key, RRSet *rs);
sds zoneToStr(zone *z);

zoneDict *zoneDictCreate(int socket_id);
zoneDict *zoneDictCopy(zoneDict *zd, int socket_id);
void zoneDictDestroy(zoneDict *zd);
zone *zoneDictFetchVal(zoneDict *zd, char *key);

zone *zoneDictGetZone(zoneDict *zd, char *name);

int zoneDictReplace(zoneDict *zd, zone *z);
int zoneDictAdd(zoneDict *zd, zone *z);

int zoneDictDelete(zoneDict *zd, char *origin);
int zoneDictEmpty(zoneDict *zd);
size_t zoneDictGetNumZones(zoneDict *zd, int lock);
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
int loadZoneFromStr(char *errstr, char *zbuf, zone **zpp);
int loadZoneFromFile(const char *fname, zone **zpp);

sds sdscatpack(sds s, char const *fmt, ...);
static inline bool isAbsDotDomain(char *ss) {
    return endswith(ss, ".");
}

extern dictType dnsDictType;
extern dictType zoneDictType;

#if defined(SK_TEST)
int zoneParserTest(int argc, char *argv[]);
int dsTest(int argc, char *argv[]);
#endif

#endif //CDNS_DS_H
