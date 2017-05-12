//
// Created by yangyu on 17-2-16.
//

#ifndef CDNS_DS_H
#define CDNS_DS_H
#include <stdint.h>

#include <rte_spinlock.h>
#include <rte_atomic.h>

#include "sds.h"
#include "dict.h"
#include "defines.h"

#define DS_OK     0
#define DS_ERR   -1
#define DS_EOF    1

#define PARSER_OK    0
#define PARSER_ERR  -1


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
    rte_atomic32_t refcnt;
    char *origin;          // in <len label> format
    char *dotOrigin;       // in <label dot> format
    uint32_t default_ttl;  // $TTL directive
    // the key is the relative name(len label),
    // if the key is origin, then use @
    // the value is dnsDictValue instance
    dict *d;

    // just two pointer to the RRSet object stored in dict,
    // never free these two pointer.
    RRSet *soa;
    RRSet *ns;

    // timestamp of last reload of this zone, need sync
    long ts;
    // some information of SOA record.
    uint32_t sn;
    int32_t refresh;
    int32_t retry;
    int32_t expiry;
    int32_t nx;
} zone;

#define zoneIncRef(z) rte_atomic32_inc(&(z->refcnt))
#define zoneDecRef(z) do {\
if (rte_atomic32_dec_and_test(&(z->refcnt))) zoneDestroy(z); \
} while(0)

typedef struct _zoneDict {
    rte_spinlock_t lock;
    // the key is the origin of the zone(len label format)
    // the value is zone instance.
    dict *d;
} zoneDict;

#define zoneDictLock(zd) rte_spinlock_lock(&((zd)->lock))
#define zoneDictUnlock(zd) rte_spinlock_unlock(&((zd)->lock))
#define zoneDictInitLock(zd) rte_spinlock_init(&((zd)->lock))
#define zoneDictDestroyLock(zd)

RRSet *RRSetCreate(uint16_t type);
RRSet *RRSetDup(RRSet *rs);
RRSet* RRSetCat(RRSet *rs, char *buf, size_t len);
RRSet *RRSetRemoveFreeSpace(RRSet *rs);
int RRSetCompressPack(struct context *ctx, RRSet *rs, size_t nameOffset, compressInfo *cps, size_t *cps_sz,
                      size_t cps_sz_max, arInfo *ari, size_t *ar_sz, size_t ar_sz_max);
sds RRSetToStr(RRSet *rs);

void RRSetDestroy(RRSet *rs);

RRSet *dnsDictValueGet(dnsDictValue *dv, int type);
void dnsDictValueSet(dnsDictValue *dv, RRSet *rs);
dnsDictValue *dnsDictValueCreate();
void dnsDictValueDestroy(dnsDictValue *val);

zone *zoneCreate(char *origin);
void zoneDestroy(zone *zn);
void zoneUpdateRRSetOffsets(zone *z);
dnsDictValue *zoneFetchValue(zone *z, void *key);
RRSet *zoneFetchTypeVal(zone *z, void *key, uint16_t type);
int zoneReplace(zone *z, void *key, dnsDictValue *val);
int zoneReplaceTypeVal(zone *z, char *key, RRSet *rs);
sds zoneToStr(zone *z);

zoneDict *zoneDictCreate();
void zoneDictDestroy(zoneDict *zd);
zone *zoneDictFetchVal(zoneDict *zd, char *key);
zone *zoneDictGetZone(zoneDict *zd, char *name);
int zoneDictReplace(zoneDict *zd, zone *z);
int zoneDictAdd(zoneDict *zd, zone *z);
int zoneDictDelete(zoneDict *zd, char *origin);
int zoneDictEmpty(zoneDict *zd);
size_t zoneDictGetNumZones(zoneDict *zd);
zone *zoneDictGetRandomZone(zoneDict *zd, int lock);
sds zoneDictToStr(zoneDict *zd);

// parser
RRParser *RRParserCreate(char *name, uint32_t ttl, char *dotOrigin);
void RRParserDestroy(RRParser *psr);
int RRParserSetDotOrigin(RRParser *psr, char *dotOrigin);
int RRParserFeed(RRParser *psr, char *ss, char *name, zone *z);

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

#if defined(CDNS_TEST)
int zoneParserTest(int argc, char *argv[]);
int dsTest(int argc, char *argv[]);
#endif

#endif //CDNS_DS_H
