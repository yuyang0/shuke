//
// Created by yangyu on 17-11-24.
//

#ifndef SHUKE_ZONE_H
#define SHUKE_ZONE_H

#include <stdio.h>
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
typedef struct _RRSet{
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
#define SUPPORT_TYPE_NUM    (8)
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
    // RRSet *PTR;
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

    // timestamp when this zone needs reload
    long refresh_ts;
    struct rb_node rbnode;
    struct cds_lfht_node htnode;
    struct rcu_head rcu_head;
} zone;

RRSet *RRSetCreate(uint16_t type, int socket_id);
RRSet *RRSetDup(RRSet *rs, int socket_id);
void RRSetUpdateOffsets(RRSet *rs);
RRSet* RRSetCat(RRSet *rs, char *buf, size_t len);
RRSet *RRSetRemoveFreeSpace(RRSet *rs);
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

extern dictType dnsDictType;
extern const struct cds_lfht_mm_type cds_lfht_mm_socket;

#endif //SHUKE_ZONE_H
