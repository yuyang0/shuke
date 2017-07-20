//
// Created by yangyu on 17-2-16.
//
#include <string.h>
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

dnsDictValue *dnsDictValueCreate(int socket_id) {
    dnsDictValue *dv = socket_calloc(socket_id, 1, sizeof(*dv));
    return dv;
}

dnsDictValue *dnsDictValueDup(dnsDictValue *dv, int socket_id) {
    dnsDictValue *new_dv = socket_memdup(socket_id, dv, sizeof(*dv));
    for (int i = 0; i < SUPPORT_TYPE_NUM; ++i) {
        if (dv->v.rsArr[i]) {
            new_dv->v.rsArr[i] = RRSetDup(dv->v.rsArr[i], socket_id);
        }
    }
    return new_dv;
}

void dnsDictValueDestroy(dnsDictValue *dv, int socket_id) {
    if (dv == NULL) return;
    for (int i = 0; i < SUPPORT_TYPE_NUM; ++i) {
        RRSet *rs = dv->v.rsArr[i];
        RRSetDestroy(rs);
    }
    socket_free(socket_id, dv);
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
RRSet *RRSetCreate(uint16_t type, int socket_id) {
    RRSet *rs = socket_calloc(socket_id, 1, sizeof(*rs));
    rs->socket_id = socket_id;
    rs->type = type;
    return rs;
}

RRSet *RRSetDup(RRSet *rs, int socket_id) {
    size_t sz = sizeof(*rs) + rs->len + rs->free;
    RRSet *new = socket_malloc(socket_id, sz);
    rte_memcpy(new, rs, sz);
    new->socket_id = socket_id;
    new->offsets = NULL;

    if (rs->offsets) {
        new->offsets = socket_memdup(socket_id, rs->offsets, rs->num*sizeof(size_t));
    }
    return new;
}

void RRSetUpdateOffsets(RRSet *rs) {
    if (rs == NULL) return;

    int i;
    size_t offset = 0;
    uint16_t rdlength;
    char *ptr = rs->data;

    assert(rs->offsets == NULL);
    rs->offsets = socket_malloc(rs->socket_id, rs->num * sizeof(size_t));

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
    new_rs = socket_realloc(rs->socket_id, rs, sizeof(*rs)+newlen);

    new_rs->free = newlen - len;
    return new_rs;
}

RRSet *RRSetRemoveFreeSpace(RRSet *rs) {
    if (rs->free == 0) return rs;
    RRSet *new = socket_realloc(rs->socket_id, rs, sizeof(*rs)+rs->len);
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
    socket_free(rs->socket_id, rs->offsets);
    socket_free(rs->socket_id, rs);
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
zone *zoneCreate(char *ss, int socket_id) {
    char domain[256];
    char *origin, *dotOrigin;
    zone *zn = socket_calloc(socket_id, 1, sizeof(*zn));
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
    zn->origin = socket_strdup(socket_id, origin);
    if (checkLenLabel(zn->origin, 0) == PROTO_ERR) {
        LOG_ERROR(USER1, "origin %s is invalid.", dotOrigin);
        socket_free(socket_id, zn->origin);
        socket_free(socket_id, zn);
        return NULL;
    }
    zn->originLen = strlen(zn->origin);
    zn->dotOrigin = socket_strdup(socket_id, dotOrigin);
    zn->socket_id = socket_id;
    zn->d = dictCreate(&dnsDictType, NULL, socket_id);
    rb_init_node(&zn->rbnode);
    LOG_DEBUG(USER1, "create zone (dotOrigin=>%s, sid=> %d)", zn->dotOrigin, socket_id);
    return zn;
}

zone *zoneCopy(zone *z, int socket_id) {
    zone *new_z = zoneCreate(z->dotOrigin, socket_id);
    assert(new_z != NULL);

    dictIterator *it = dictGetIterator(z->d);
    dictEntry *de;
    while((de = dictNext(it)) != NULL) {
        char *name = dictGetKey(de);
        dnsDictValue *dv = dictGetVal(de);
        dnsDictValue *new_dv = dnsDictValueDup(dv, socket_id);
        dictReplace(new_z->d, name, new_dv);
    }
    dictReleaseIterator(it);
    return new_z;
}

void zoneDestroy(zone *zn) {
    if (zn == NULL) return;
    LOG_DEBUG(USER1, "zone %s is destroyed(socket_id %d)", zn->dotOrigin, zn->socket_id);
    dictRelease(zn->d);
    socket_free(zn->socket_id, zn->origin);
    socket_free(zn->socket_id, zn->dotOrigin);
    socket_free(zn->socket_id, zn);
}

/*!
 * fetch dns dict value from zone
 * @param z
 * @param key: must be absolute domain name in len label format.
 * @param keyLen: the length of the key
 * @return
 */
dnsDictValue *zoneFetchValueAbs(zone *z, void *key, size_t keyLen) {
    // TODO: avoid check if the domain belongs to zone
    size_t originLen = z->originLen;
    size_t remain = keyLen - originLen;
    // the key ends with origin(absolute domain name).
    assert (keyLen >= originLen && strcasecmp(key+remain, z->origin) == 0);

    char buf[255] = {0};
    if (remain == 0) strcpy(buf, "@");
    else memcpy(buf, key, remain);
    return dictFetchValue(z->d, buf);
}

/*
 * same with zoneFetchValueAbs except key should be a relative domain name in len label format
 */
dnsDictValue *zoneFetchValueRelative(zone *z, void *key) {
    return dictFetchValue(z->d, key);
}

// fetch the RRSet from zone, support relative and absolute name
RRSet *zoneFetchTypeVal(zone *z, void *key, uint16_t type) {
    dnsDictValue *dv = NULL;
    size_t keyLen = strlen(key);
    size_t originLen = z->originLen;
    size_t remain = keyLen - originLen;

    // TODO: avoid check if the domain belongs to zone
    // the key ends with origin(absolute domain name).
    if (keyLen >= originLen && strcasecmp(key+remain, z->origin) == 0) {
        char label[MAX_DOMAIN_LEN+2] = "@";
        if (remain > 0) {
            memcpy(label, key, remain);
            label[remain] = 0;
        }
        dv = dictFetchValue(z->d, label);
    } else {
        dv = dictFetchValue(z->d, key);
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
        dv = dnsDictValueCreate(z->socket_id);
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
int rcu_ht_match(struct cds_lfht_node *ht_node, const void *_key)
{
    zone *z = caa_container_of(ht_node, struct _zone, htnode);
    const char *key = _key;
    return strcasecmp(z->origin, key) == 0;
}

void zoneDictFreeCallback(struct rcu_head *head)
{
    zone *z = caa_container_of(head, zone, rcu_head);
    zoneDestroy(z);
}

static
void *rcu_ht_fetch_value(struct cds_lfht *ht, void *key) {
    struct cds_lfht_iter iter;	/* For iteration on hash table */
    struct cds_lfht_node *ht_node;
    unsigned int hash = zoneDictHash(key, strlen(key));
    cds_lfht_lookup(ht, hash, rcu_ht_match, key, &iter);
    ht_node = cds_lfht_iter_get_node(&iter);
    if (!ht_node) {
        return NULL;
    } else {
        return caa_container_of(ht_node, zone, htnode);
    }
}

/* And a case insensitive hash function (based on djb hash) */
unsigned int zoneDictHash(char *buf, size_t len) {
    unsigned int hash = (unsigned int)5381;

    while (len--)
        hash = ((hash << 5) + hash) + (tolower(*buf++)); /* hash * 33 + c */
    return hash;
}

zoneDict *zoneDictCreate(int socket_id) {
    zoneDict *zd = socket_calloc(socket_id, 1, sizeof(*zd));
    zd->ht = cds_lfht_new(1, 1, 0,
                          CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
                          NULL);
    zd->socket_id = socket_id;
    return zd;
}

void zoneDictDestroy(zoneDict *zd) {
    int ret = 0;
    struct cds_lfht_iter iter;	/* For iteration on hash table */
    struct cds_lfht_node *ht_node;
    struct cds_lfht *ht = zd->ht;
    zone *z;
    zoneDictWLock(zd);
    cds_lfht_for_each_entry(ht, &iter, z, htnode) {
        ht_node = cds_lfht_iter_get_node(&iter);
        ret = cds_lfht_del(ht, ht_node);
        if (!ret) {
            call_rcu(&z->rcu_head, zoneDictFreeCallback);
        }
    }
    zoneDictWUnlock(zd);

    int err = cds_lfht_destroy(zd->ht, NULL);
    if (err) {
        LOG_ERR(USER1, "destroy cru hash table failed.");
    }
    socket_free(zd->socket_id, zd);
}

/*
 * fetch zone from zone dict
 *
 * Notice: since this function didn't acquire rlock,
 *         so the rlock must be acquired in caller
 */
zone *zoneDictFetchVal(zoneDict *zd, char *key) {
    zone *z = rcu_ht_fetch_value(zd->ht, key);
    return z;
}

/*!
 * same as zoneDictFetchVal, but instead of fetch the zone whose origin is equal to name,
 * this function fetch the zone name belong to, so it will iterate parent domain.
 *
 * Notice: since this function didn't acquire rlock,
 *         so the rlock must be acquired in caller.
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
    for (int i = nLabel; i >= 2; --i) {
        z = rcu_ht_fetch_value(zd->ht, start);
        if (z != NULL) break;
        start += (*start + 1);
    }
    return z;
}

/* Add a zone, discarding the old if the key already exists.
 * Return 1 if the key was added from scratch, 0 if there was already an
 * element with such key and dictReplace() just performed a value update
 * operation. */
int zoneDictReplace(zoneDict *zd, zone *z) {
    int err = 1;
    zone *old_z;
    struct cds_lfht *ht = zd->ht;
    struct cds_lfht_node *ht_node;
    unsigned int hash = zoneDictHash(z->origin, z->originLen);
    zoneDictWLock(zd);
    ht_node = cds_lfht_add_replace(ht, hash, rcu_ht_match, z->origin,
                                   &z->htnode);
    if (ht_node) {
        old_z = caa_container_of(ht_node, zone, htnode);
        call_rcu(&old_z->rcu_head, zoneDictFreeCallback);
        err = 0;
    }
    zoneDictWUnlock(zd);
    return err;
}

int zoneDictAdd(zoneDict *zd, zone *z) {
    int err = DICT_OK;
    void *key = z->origin;
    struct cds_lfht_node *htnode;
    unsigned int hash = zoneDictHash(key, strlen(key));
    zoneDictWLock(zd);
    htnode = cds_lfht_add_unique(zd->ht, hash, rcu_ht_match, z->origin, &z->htnode);
    if (htnode != &z->htnode) {
        err = DICT_ERR;
    }
    zoneDictWUnlock(zd);
    return err;
}

int zoneDictDelete(zoneDict *zd, char *origin) {
    int err = 0;
    struct cds_lfht *ht = zd->ht;	/* Hash table */
    int ret = 0;
    struct cds_lfht_iter iter;	/* For iteration on hash table */
    struct cds_lfht_node *ht_node;
    unsigned int hash = zoneDictHash(origin, strlen(origin));

    zoneDictWLock(zd);
    cds_lfht_lookup(ht, hash, rcu_ht_match, origin, &iter);
    ht_node = cds_lfht_iter_get_node(&iter);
    if (ht_node) {
        ret = cds_lfht_del(ht, ht_node);
        if (!ret) {
            zone *del_z = caa_container_of(ht_node, zone, htnode);
            call_rcu(&del_z->rcu_head, zoneDictFreeCallback);
        }
    }
    zoneDictWUnlock(zd);
    return err;
}

int zoneDictEmpty(zoneDict *zd) {
    struct cds_lfht_iter iter;	/* For iteration on hash table */
    struct cds_lfht_node *ht_node;
    zone *z;
    int ret;

    zoneDictRLock(zd);
    cds_lfht_for_each_entry(zd->ht, &iter, z, htnode) {
        ht_node = cds_lfht_iter_get_node(&iter);
        ret = cds_lfht_del(zd->ht, ht_node);
        if (!ret) {
            call_rcu(&z->rcu_head, zoneDictFreeCallback);
        }
    }
    zoneDictRUnlock(zd);
    return DS_OK;
}

int zoneDictExistZone(zoneDict *zd, char *origin) {
    int ret;
    zoneDictRLock(zd);
    ret = (rcu_ht_fetch_value(zd->ht, origin) != NULL);
    zoneDictRUnlock(zd);
    return ret;
}

size_t zoneDictGetNumZones(zoneDict *zd) {
    unsigned long count;
    long approx_before, approx_after;
    zoneDictRLock(zd);
    cds_lfht_count_nodes(zd->ht, &approx_before, &count,
                         &approx_after);
    zoneDictRUnlock(zd);
    return (size_t)count;
}

// may lock the dict long time, mainly for debug.
sds zoneDictToStr(zoneDict *zd) {
    struct cds_lfht_iter iter;	/* For iteration on hash table */
    zone *z;
    sds zone_s;
    sds s = sdsempty();

    zoneDictRLock(zd);
    cds_lfht_for_each_entry(zd->ht, &iter, z, htnode) {
        zone_s = zoneToStr(z);
        s = sdscatsds(s, zone_s);
        sdsfree(zone_s);
    }
    zoneDictRUnlock(zd);
    return s;
}

/*----------------------------------------------
 *     dict type definition
 *---------------------------------------------*/
static unsigned int _dictStringCaseHash(const void *key)
{
    return dictGenCaseHashFunction(key, strlen(key));
}

static void *_dictStringKeyDup(void *privdata, const void *key)
{
    dict *d = privdata;
    return socket_strdup(d->socket_id, key);
}

static void _dictStringKeyDestructor(void *privdata, void *key)
{
    dict *d = privdata;
    socket_free(d->socket_id, key);
}

static int _dictStringKeyCaseCompare(void *privdata, const void *key1,
                                     const void *key2)
{
    DICT_NOTUSED(privdata);
    return strcasecmp(key1, key2) == 0;
}

/* ----------------------- dns Hash Table Type ------------------------*/
static void _dnsDictValDestructor(void *privdata, void *val)
{
    dict *d = privdata;
    dnsDictValueDestroy(val, d->socket_id);
}

dictType dnsDictType = {
        _dictStringCaseHash, /* hash function */
        _dictStringKeyDup,             /* key dup */
        NULL,                          /* val dup */
        _dictStringKeyCaseCompare,         /* key compare */
        _dictStringKeyDestructor,         /* key destructor */
        _dnsDictValDestructor,         /* val destructor */
};

#if defined(SK_TEST)
#include "testhelp.h"
int dsTest(int argc, char *argv[]) {
    ((void)argc); ((void) argv);
    char origin[] = "\7example\3com";
    zone *z = zoneCreate(origin, SOCKET_ID_HEAP);
    char k[] = "\3www";
    {
        RRSet *rs1 = RRSetCreate(DNS_TYPE_A, SOCKET_ID_HEAP);
        RRSet *rs2 = RRSetCreate(DNS_TYPE_AAAA, SOCKET_ID_HEAP);
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
