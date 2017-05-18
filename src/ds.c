//
// Created by yangyu on 17-2-16.
//
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include "endianconv.h"
#include "zmalloc.h"
#include "sds.h"
#include "str.h"
#include "dict.h"
#include "protocol.h"
#include "log.h"
#include "utils.h"
#include "ds.h"

#define RRSET_MAX_PREALLOC (1024*1024)

dnsDictValue *dnsDictValueCreate(void) {
    dnsDictValue *dv = zcalloc(sizeof(*dv));
    return dv;
}

void dnsDictValueDestroy(dnsDictValue *dv) {
    if (dv == NULL) return;
    for (int i = 0; i < SUPPORT_TYPE_NUM; ++i) {
        RRSet *rs = dv->v.rsArr[i];
        RRSetDestroy(rs);
    }
    zfree(dv);
}

RRSet *dnsDictValueGet(dnsDictValue *dv, int type) {
    switch (type) {
        case DNS_TYPE_A:
            return dv->v.tv.A;
        case DNS_TYPE_NS:
            return dv->v.tv.NS;
        case DNS_TYPE_CNAME:
            return dv->v.tv.CNAME;
        case DNS_TYPE_SOA:
            return dv->v.tv.SOA;
        case DNS_TYPE_MX:
            return dv->v.tv.MX;
        case DNS_TYPE_TXT:
            return dv->v.tv.TXT;
        case DNS_TYPE_AAAA:
            return dv->v.tv.AAAA;
        case DNS_TYPE_SRV:
            return dv->v.tv.SRV;
        case DNS_TYPE_PTR:
            return dv->v.tv.PTR;
        default:
            LOG_FATAL(USER1, "invalid RR type");
    }
}

void dnsDictValueSet(dnsDictValue *dv, RRSet *rs) {
    if (rs == NULL) return;

    switch (rs->type) {
        case DNS_TYPE_A:
            dv->v.tv.A = rs;
            break;
        case DNS_TYPE_NS:
            dv->v.tv.NS = rs;
            break;
        case DNS_TYPE_CNAME:
            dv->v.tv.CNAME= rs;
            break;
        case DNS_TYPE_SOA:
            dv->v.tv.SOA = rs;
            break;
        case DNS_TYPE_MX:
            dv->v.tv.MX = rs;
            break;
        case DNS_TYPE_TXT:
            dv->v.tv.TXT = rs;
            break;
        case DNS_TYPE_AAAA:
            dv->v.tv.AAAA = rs;
            break;
        case DNS_TYPE_SRV:
            dv->v.tv.SRV = rs;
            break;
        case DNS_TYPE_PTR:
            dv->v.tv.PTR = rs;
            break;
        default:
            LOG_FATAL(USER1, "invalid RR type");
    }
}

/*----------------------------------------------
 *     RRSet definition
 *---------------------------------------------*/
RRSet *RRSetCreate(uint16_t type) {
    RRSet *rs = zcalloc(sizeof(*rs));
    rs->type = type;
    return rs;
}

RRSet *RRSetDup(RRSet *rs) {
    size_t sz = sizeof(*rs) + rs->len + rs->free;
    RRSet *new = zmalloc(sz);
    memcpy(new, rs, sz);
    return new;
}

void RRSetUpdateOffsets(RRSet *rs) {
    if (rs == NULL) return;

    int i;
    size_t offset = 0;
    uint16_t rdlength;
    char *ptr = rs->data;

    if (rs->offsets == NULL) {
        rs->offsets = zmalloc(rs->num * sizeof(size_t));
    } else {
        rs->offsets = zrealloc(rs->offsets, rs->num * sizeof(size_t));
    }
    for (i = 0; i < rs->num; ++i) {
        rs->offsets[i] = offset;
        rdlength = load16be(ptr);
        ptr += (2 + rdlength);
        offset += (2 + rdlength);
    }
}

RRSet* RRSetMakeRoomFor(RRSet *rs, size_t addlen) {
    RRSet *new_rs;
    size_t free = rs->free;
    size_t len, newlen;

    if (free >= addlen) return rs;
    len = rs->len;
    newlen = (len+addlen);
    if (newlen < RRSET_MAX_PREALLOC)
        newlen *= 2;
    else
        newlen += RRSET_MAX_PREALLOC;
    new_rs = zrealloc(rs, sizeof(*rs)+newlen);

    new_rs->free = newlen - len;
    return new_rs;
}

RRSet *RRSetRemoveFreeSpace(RRSet *rs) {
    if (rs->free == 0) return rs;
    RRSet *new = zrealloc(rs, sizeof(*rs)+rs->len);
    new->free = 0;
    return new;
}

RRSet *RRSetCat(RRSet *rs, char *buf, size_t len) {
    RRSet *new = RRSetMakeRoomFor(rs, len);
    memcpy(new->data+new->len, buf, len);
    new->num++;
    new->len += len;
    new->free -= len;
    return new;
}

static int getCommonSuffixOffset(compressInfo *cps, char *name2, size_t *offset1, size_t *offset2) {
    char *name1 = cps->name;
    size_t uncompress_len = cps->uncompress_len;
    char *ptr;
    char *end1 = name1 + strlen(name1);
    char *end2 = name2 + strlen(name2);

    for (; end1 > name1 && end2 > name2; end1--, end2--) {
        if (*end1 != *end2) {
            end1++;
            end2++;
            break;
        }
    }
    if (*end2 == 0) return DS_ERR;
    // make end1, end2 point to the start position of a label.
    ptr = name2;
    for(; ; ) {
        if (ptr >= end2) {
            end1 += (ptr - end2);
            end2 = ptr;
            break;
        }
        if (*ptr == 0) {
            break;
        }
        int len = *ptr;
        ptr += (len+1);
    }
    if (*end2 == 0) return DS_ERR;

    *offset1 = end1 - name1;
    *offset2 = end2 - name2;
    if (*offset1 > uncompress_len) {
        return DS_ERR;
    }
    return DS_OK;
}

int dumpCompressedName(struct context *ctx, char *name, compressInfo *cps, size_t *cps_sz, size_t cps_sz_max) {
    int cur = ctx->cur;
    size_t offset1=0, offset2=0;
    size_t best_offset1 = 256;
    size_t best_offset2 = 256;
    int best_idx = -1;
    for (size_t i = 0; i < *cps_sz; ++i) {
        if (getCommonSuffixOffset(cps+i, name, &offset1, &offset2) != DS_OK) continue;
        if (offset2 < best_offset2) {
            best_offset1 = offset1;
            best_offset2 = offset2;
            best_idx = (int)i;
        }
    }
    // add an entry to compress info array.
    if (best_offset2 > 0 && (*cps_sz < cps_sz_max)) {
        compressInfo temp = {name, cur, best_offset2};
        cps[*cps_sz] = temp;
        (*cps_sz)++;
    }

    if (best_offset2 < 256) {

        size_t nameOffset = cps[best_idx].offset + best_offset1;
        nameOffset |= 0xC000;

        cur = snpack(ctx->resp, cur, ctx->totallen, "m>h", name, best_offset2, (uint16_t)nameOffset);
    } else {
        cur = snpack(ctx->resp, cur, ctx->totallen, "m", name, strlen(name)+1);
    }
    if (cur == ERR_CODE) return DS_ERR;
    ctx->cur = cur;
    return cur;
}

/*!
 * dump the RRSet object to sds
 *
 * @param ctx:  context object, used to store the dumped bytes
 * @param rs:  the RRSet object needs to be dumped
 * @param nameOffset: the offset of the name in sds, used to compress the name
 * @param cps: the compress information of s
 * @param cps_sz: the current size of compress info array
 * @param ari: this array store the information needs to do additional section process
 * @param ar_sz: the size of `ari`.
 * @return the new sds bytes.
 */
int RRSetCompressPack(struct context *ctx, RRSet *rs, size_t nameOffset,
                      compressInfo *cps, size_t *cps_sz, size_t cps_sz_max,
                      arInfo *ari, size_t *ar_sz, size_t ar_sz_max)
{
    char *resp = ctx->resp;
    size_t totallen = ctx->totallen;
    int cur = ctx->cur;

    char *name;
    char *rdata;
    int32_t start_idx = 0;
    uint16_t dnsNameOffset = (uint16_t)(nameOffset | 0xC000);
    int len_offset;

    // support round robin
    if (rs->num > 1) {
        start_idx = rte_atomic32_add_return(&(rs->rr_idx), 1) % rs->num;
        LOG_DEBUG(USER1, "rr idx: %d", rs->rr_idx);
    }
    for (int i = 0; i < rs->num; ++i) {
        int idx = (i + start_idx) % rs->num;
        rdata = rs->data + (rs->offsets[idx]);

        uint16_t rdlength = load16be(rdata);

        cur = snpack(resp, cur, totallen, ">hhhi", dnsNameOffset, rs->type, DNS_CLASS_IN, rs->ttl);
        if (cur == ERR_CODE) return DS_ERR;

        // compress the domain name in NS and MX record.
        switch (rs->type) {
            case DNS_TYPE_CNAME:
            case DNS_TYPE_NS:
                name = rdata + 2;
                len_offset = cur;
                cur = snpack(resp, cur, totallen, "m", rdata, 2);
                if (cur == ERR_CODE) return DS_ERR;
                ctx->cur = cur;

                cur = dumpCompressedName(ctx, name, cps, cps_sz, cps_sz_max);
                if (cur == DS_ERR) return DS_ERR;

                dump16be((uint16_t)(cur-len_offset-2), resp+len_offset);
                if (ari && (*ar_sz < ar_sz_max)) {
                    arInfo ai_temp = {name, len_offset+2};
                    ari[*ar_sz] = ai_temp;
                    (*ar_sz)++;
                }
                break;
            case DNS_TYPE_MX:
                name = rdata + 4;
                len_offset = cur;
                cur = snpack(resp, cur, totallen, "m", rdata, 4);
                if (cur == ERR_CODE) return DS_ERR;
                ctx->cur = cur;

                cur = dumpCompressedName(ctx, name, cps, cps_sz, cps_sz_max);
                if (cur == DS_ERR) return DS_ERR;

                dump16be((uint16_t)(cur-len_offset-2), resp+len_offset);
                if (ari && (*ar_sz < ar_sz_max)) {
                    arInfo ai_temp = {name, len_offset+4};
                    ari[*ar_sz] = ai_temp;
                    (*ar_sz)++;
                }
                break;
            case DNS_TYPE_SRV:
                // don't compress the target field, but need add compress info for the remain records.
                name = rdata + 8;
                len_offset = cur;
                if (*cps_sz < cps_sz_max) {
                    compressInfo temp = {name, cur+8, rdlength-6};
                    cps[*cps_sz] = temp;
                    (*cps_sz)++;
                }

                cur = snpack(resp, cur, totallen, "m", rdata, rdlength+2);
                if (cur == ERR_CODE) return DS_ERR;

                if (ari && (*ar_sz < ar_sz_max)) {
                    arInfo ai_temp = {name, len_offset+8};
                    ari[*ar_sz] = ai_temp;
                    (*ar_sz)++;
                }
                break;
            default:
                cur = snpack(resp, cur, totallen, "m", rdata, rdlength+2);
                if (cur == ERR_CODE) return DS_ERR;
        }
    }
    ctx->cur = cur;
    return cur;
}

void RRSetDestroy(RRSet *rs) {
    if (rs == NULL) return;
    zfree(rs->offsets);
    zfree(rs);
}

sds RRSetToStr(RRSet *rs) {
    sds s = sdsempty();
    if (rs == NULL) return s;

    int i;
    char *data = rs->data;
    uint16_t rdlength;
    char human[256] = {0};

    switch (rs->type) {
        case DNS_TYPE_A:
            for (i = 0; i < rs->num; ++i) {
                rdlength = load16be(data);
                assert(rdlength == 4);
                inet_ntop(AF_INET, data+2, human, 255);
                s = sdscatprintf(s, " %d IN A %s\n", rs->ttl, human);
                data += (2 + rdlength);
            }
            break;
        case DNS_TYPE_AAAA:
            for (i = 0; i < rs->num; ++i) {
                rdlength = load16be(data);
                assert(rdlength == 16);
                inet_ntop(AF_INET6, data+2, human, 255);
                s = sdscatprintf(s, " %d IN AAAA %s\n", rs->ttl, human);
                data += (2 + rdlength);
            }
            break;
        case DNS_TYPE_NS:
            for (i = 0; i < rs->num; ++i) {
                rdlength = load16be(data);
                assert(rdlength <= 255);

                len2dotlabel(data+2, human);
                s = sdscatprintf(s, " %d IN NS %s\n", rs->ttl, human);
                data += (2 + rdlength);
            }
            break;
        case DNS_TYPE_CNAME:
            rdlength = load16be(data);
            assert((rdlength < 255) && (rs->num == 1));

            len2dotlabel(data+2, human);
            s = sdscatprintf(s, " %d IN CNAME %s\n", rs->ttl, human);
            break;
        case DNS_TYPE_SOA:
        {
            rdlength = load16be(data);
            data += 2;
            char ns[256];
            char email[256];

            len2dotlabel(data, ns);
            data += (strlen(ns) + 1);
            len2dotlabel(data, email);
            data += (strlen(email) + 1);

            uint32_t sn = load32be(data);
            data += 4;
            int32_t refresh = load32be(data);
            data += 4;
            int32_t retry = load32be(data);
            data += 4;
            int32_t expiry = load32be(data);
            data += 4;
            int32_t nx = load32be(data);
            data += 4;

            s = sdscatprintf(s, " %d IN SOA %s %s %d %d %d %d %d\n",
                         rs->ttl, ns, email, sn, refresh, retry, expiry, nx);
        }
            break;
        case DNS_TYPE_MX:
            for (i = 0; i < rs->num; ++i) {
                rdlength = load16be(data);
                uint16_t  pref = load16be(data+2);
                len2dotlabel(data+4, human);
                s = sdscatprintf(s, " %d IN MX %d %s\n", rs->ttl, pref, human);
                data += (2 + rdlength);
            }
            break;
        case DNS_TYPE_TXT:
            for (i = 0; i < rs->num; ++i) {
                char txt[256] = {0};
                s = sdscatprintf(s, " %d IN TXT", rs->ttl);

                rdlength = load16be(data);
                data += 2;

                int readlen = 0;
                // one TXT record may contain multiple strings
                while(readlen < rdlength) {
                    uint8_t len = (uint8_t)(*data);
                    memcpy(txt, data+1, len);
                    txt[len] = 0;
                    data += (len+1);
                    readlen += (len+1);
                    s = sdscatprintf(s, " \"%s\"", txt);
                }
                s = sdscat(s, "\n");
            }
            break;
        case DNS_TYPE_SRV:
            for (i = 0; i < rs->num; ++i) {
                // ignore rdlength
                data += 2;
                char target[256];
                uint16_t priority = load16be(data);
                data += 2;
                uint16_t weight = load16be(data);
                data += 2;
                uint16_t port = load16be(data);
                data += 2;
                len2dotlabel(data, target);
                data += (strlen(target) + 1);
                s = sdscatprintf(s, " %d IN SRV %d %d %d %s \n", rs->ttl, priority, weight, port, target);
            }
            break;
        case DNS_TYPE_PTR:
            for(i = 0; i < rs->num; ++i) {
                rdlength = load16be(data);
                assert(rdlength <= 255);

                len2dotlabel(data+2, human);
                s = sdscatprintf(s, " %d IN PTR %s\n", rs->ttl, human);
                data += (2 + rdlength);
            }
            break;
        default:
        LOG_FATAL(USER1, "invalid RR type");
    }
    return s;
}
/*----------------------------------------------
 *     zone definition
 *---------------------------------------------*/
zone *zoneCreate(char *ss) {
    char domain[256];
    char *origin, *dotOrigin;
    zone *zn = zcalloc(sizeof(*zn));
    // convert len label format if necessary.
    if (strchr(ss, '.') != NULL) {
        dot2lenlabel(ss, domain);
        dotOrigin = ss;
        origin = domain;
    } else {
        len2dotlabel(ss, domain);
        dotOrigin = domain;
        origin = ss;
    }
    zn->origin = zstrdup(origin);
    if (checkLenLabel(zn->origin, 0) == PROTO_ERR) {
        LOG_ERROR(USER1, "origin %s is invalid.", dotOrigin);
        zfree(zn->origin);
        zfree(zn);
        return NULL;
    }
    zn->dotOrigin = zstrdup(dotOrigin);
    zn->d = dictCreate(&dnsDictType, NULL);
    rte_atomic32_set(&(zn->refcnt), 1);
    rte_atomic64_set(&(zn->ts), (int64_t )time(NULL));
    return zn;
}

void zoneDestroy(zone *zn) {
    if (zn == NULL) return;
    LOG_DEBUG(USER1, "zone %s is destroyed", zn->dotOrigin);
    dictRelease(zn->d);
    zfree(zn->origin);
    zfree(zn->dotOrigin);
    zfree(zn);
}

dnsDictValue *zoneFetchValue(zone *z, void *key) {
    // support absolute domain name.
    // TODO: avoid check if the domain belongs to zone
    if (endscasewith(key, z->origin)) {
        char buf[255] = {0};
        size_t remain = strlen(key) - strlen(z->origin);
        if (remain == 0) strcpy(buf, "@");
        else memcpy(buf, key, remain);
        return dictFetchValue(z->d, buf);
    }
    return dictFetchValue(z->d, key);
}

// fetch the RRSet from zone, support relative and absolute name
RRSet *zoneFetchTypeVal(zone *z, void *key, uint16_t type) {
    dnsDictValue *dv = NULL;
    // TODO: avoid check if the domain belongs to zone
    if (endscasewith(key, z->origin) == true) {
        char label[MAX_LABEL_LEN+1] = "@";
        size_t remain = strlen(key) - strlen(z->origin);
        if (remain > 0) {
            memcpy(label, key, remain);
            label[remain] = 0;
        }
        dv = zoneFetchValue(z, label);
    } else {
        dv = zoneFetchValue(z, key);
    }
    return dv? dnsDictValueGet(dv, type): NULL;
}

int zoneReplace(zone *z, void *key, dnsDictValue *val) {
    return dictReplace(z->d, key, val);
}

// set RRSet
// TODO validate the implementation
int zoneReplaceTypeVal(zone *z, char *key, RRSet *rs) {
    dnsDictValue *dv = dictFetchValue(z->d, key);
    if (dv == NULL) {
        dv = dnsDictValueCreate();
        dnsDictValueSet(dv, rs);
        dictReplace(z->d, key, dv);
    } else {
        RRSet *old_rs = dnsDictValueGet(dv, rs->type);
        dnsDictValueSet(dv, rs);
        if (old_rs) RRSetDestroy(old_rs);
    }
    return 0;
}

// convert zone to a string, mainly for debug
sds zoneToStr(zone *z) {
    char human[256];
    sds s = sdsempty();
    s = sdscatprintf(s, "$ORIGIN %s\n", z->dotOrigin);
    //SOA
    if (z->soa) {
        sds soa_s = RRSetToStr(z->soa);
        s =sdscatprintf(s, "@%s\n", soa_s);
        sdsfree(soa_s);
    }
    // NS
    if (z->ns) {
        sds ns_s = RRSetToStr(z->ns);
        s = sdscatprintf(s, "@%s\n", ns_s);
        sdsfree(ns_s);
    }
    dictIterator *it = dictGetIterator(z->d);
    dictEntry *de;
    while((de = dictNext(it)) != NULL) {
        sds dv_s = NULL;
        char *k = dictGetKey(de);
        strncpy(human, k, 255);
        if (strcmp(human, "@") != 0) {
            len2dotlabel(human, NULL);
            human[strlen(human)-1] = 0;
        }
        dnsDictValue *dv = dictGetVal(de);
        for (int i = 0; i < SUPPORT_TYPE_NUM; ++i) {
            RRSet *rs = dv->v.rsArr[i];
            if (rs) {
                // SOA and NS records already printed at the top of file.
                if (rs->type == DNS_TYPE_SOA) continue;
                if (rs->type == DNS_TYPE_NS && strcmp(k, "@") == 0) continue;
                sds rs_s = RRSetToStr(rs);
                if (!dv_s) dv_s = sdsempty();
                dv_s = sdscatsds(dv_s, rs_s);
                sdsfree(rs_s);
            }
        }
        if (dv_s) {
            s = sdscat(s, human);
            s = sdscatsds(s, dv_s);
            s = sdscat(s, "\n");
            sdsfree(dv_s);
        }
    }
    dictReleaseIterator(it);
    return s;
}

void zoneUpdateRRSetOffsets(zone *z) {
    dictIterator *it = dictGetIterator(z->d);
    dictEntry *de;
    while((de = dictNext(it)) != NULL) {
        dnsDictValue *dv = dictGetVal(de);
        for (int i = 0; i < SUPPORT_TYPE_NUM; ++i) {
            RRSet *rs = dv->v.rsArr[i];
            if (rs) {
                RRSetUpdateOffsets(rs);
            }
        }
    }
    dictReleaseIterator(it);
}

/*----------------------------------------------
 *     zone dict definition
 *---------------------------------------------*/
zoneDict *zoneDictCreate() {
    zoneDict *zd = zcalloc(sizeof(*zd));
    zoneDictInitLock(zd);
    zd->d = dictCreate(&zoneDictType, NULL);
    return zd;
}

void zoneDictDestroy(zoneDict *zd) {
    dictRelease(zd->d);
    zoneDictDestroyLock(zd);
    zfree(zd);
}

/*
 * fetch zone from zone dict
 *
 * Notice: since this zone instance can be deleted in other thread,
 *   to avoid this data race condition, this function will increment the
 *   reference count of zone instance, after finished using this instance,
 *   a reference count decrement is needed.
 */
zone *zoneDictFetchVal(zoneDict *zd, char *key) {
    zoneDictRLock(zd);
    zone *z = dictFetchValue(zd->d, key);
    if (z != NULL) zoneIncRef(z);
    zoneDictRUnlock(zd);
    return z;
}

/*!
 * same as zoneDictFetchVal, but instead of fetch the zone whose origin is equal to name,
 * this function fetch the zone name belong to, so it will iterate parent domain.
 *
 * @param zd : zoneDict instance
 * @param name : nane in len label format
 * @return
 */
zone *zoneDictGetZone(zoneDict *zd, char *name) {
    zone *z = NULL;
    int nLabel = 0;
    char *start = name;

    nLabel = getNumLabels(start);
    if (nLabel < 2) return NULL;
    zoneDictRLock(zd);
    for (int i = nLabel; i >= 2; --i) {
        z = dictFetchValue(zd->d, start);
        if (z != NULL) break;
        start += (*start + 1);
    }
    if (z != NULL) zoneIncRef(z);
    zoneDictRUnlock(zd);
    return z;
}

/* Add a zone, discarding the old if the key already exists.
 * Return 1 if the key was added from scratch, 0 if there was already an
 * element with such key and dictReplace() just performed a value update
 * operation. */
int zoneDictReplace(zoneDict *zd, zone *z) {
    rte_atomic64_set(&(z->ts), (int64_t)time(NULL));
    zoneUpdateRRSetOffsets(z);

    zoneDictWLock(zd);
    int err = dictReplace(zd->d, z->origin, z);
    zoneDictWUnlock(zd);
    return err;
}

int zoneDictAdd(zoneDict *zd, zone *z) {
    int err;

    zoneDictWLock(zd);
    err = dictAdd(zd->d, z->origin, z);
    zoneDictWUnlock(zd);
    return err;
}

int zoneDictDelete(zoneDict *zd, char *origin) {
    int err;

    zoneDictWLock(zd);
    err = dictDelete(zd->d, origin);
    zoneDictWUnlock(zd);
    return err;
}

int zoneDictEmpty(zoneDict *zd) {
    zoneDictRLock(zd);
    dictEmpty(zd->d, NULL);
    zoneDictRUnlock(zd);
    return DS_OK;
}

size_t zoneDictGetNumZones(zoneDict *zd, int lock) {
    size_t n;
    if (lock) zoneDictRLock(zd);
    n = dictSize(zd->d);
    if (lock) zoneDictRUnlock(zd);
    return n;
}

zone *zoneDictGetRandomZone(zoneDict *zd, int lock) {
    zone *z = NULL;
    dictEntry *de;
    if (lock) zoneDictRLock(zd);
    if ((de = dictGetRandomKey(zd->d)) == NULL) goto end;
    z = dictGetVal(de);
end:
    if (lock) zoneDictRUnlock(zd);
    return z;
}

// may lock the dict long time, mainly for debug.
sds zoneDictToStr(zoneDict *zd) {
    zone *z;
    sds zone_s;
    sds s = sdsempty();

    zoneDictRLock(zd);
    dictIterator *it = dictGetIterator(zd->d);
    dictEntry *de;
    while((de = dictNext(it)) != NULL) {
        z = dictGetVal(de);
        zone_s = zoneToStr(z);
        s = sdscatsds(s, zone_s);
        sdsfree(zone_s);
    }
    dictReleaseIterator(it);
    zoneDictRUnlock(zd);
    return s;
}

#if defined(CDNS_TEST)
#include "testhelp.h"
int dsTest(int argc, char *argv[]) {
    ((void)argc); ((void) argv);
    char origin[] = "\7example\3com";
    zone *z = zoneCreate(origin);
    char k[] = "\3www";
    {
        RRSet *rs1 = RRSetCreate(DNS_TYPE_A);
        RRSet *rs2 = RRSetCreate(DNS_TYPE_AAAA);
        zoneReplaceTypeVal(z, k, rs1);
        zoneReplaceTypeVal(z, k, rs2);
        test_cond("zone 1", zoneFetchValue(z, "aaa") == NULL);
    }
    zfree(zmalloc(100000));
    dnsDictValue *dv = zoneFetchValue(z, k);
    test_cond("zone 2", dnsDictValueGet(dv, DNS_TYPE_A)->type == DNS_TYPE_A);
    test_cond("zone 3", dnsDictValueGet(dv, DNS_TYPE_AAAA)->type == DNS_TYPE_AAAA);
    // {
    //      char name1[] = "\3www\5baidu\3com";
    //      char name2[] = "\6zhidao\5baidu\3com";
    // }
    test_report();
    return 0;
}
#endif
