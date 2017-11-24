//
// Created by yangyu on 17-2-16.
//
#include <string.h>
#include <arpa/inet.h>

#include <rte_branch_prediction.h>

#include "endianconv.h"
#include "zmalloc.h"
#include "log.h"
#include "utils.h"
#include "dnspacket.h"
#include "dpdk_module.h"
#include "ltree.h"
#include "shuke.h"
#include "edns.h"

static const unsigned char _dnsValidCharTable[256] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0X2A, 0, 0, 0X2D, 0, 0,
        0X30, 0X31, 0X32, 0X33, 0X34, 0X35, 0X36, 0X37, 0X38, 0X39, 0, 0, 0, 0, 0, 0,
        0, 0X61, 0X62, 0X63, 0X64, 0X65, 0X66, 0X67, 0X68, 0X69, 0X6A, 0X6B, 0X6C, 0X6D, 0X6E, 0X6F,
        0X70, 0X71, 0X72, 0X73, 0X74, 0X75, 0X76, 0X77, 0X78, 0X79, 0X7A, 0, 0, 0, 0, 0X5F,
        0, 0X61, 0X62, 0X63, 0X64, 0X65, 0X66, 0X67, 0X68, 0X69, 0X6A, 0X6B, 0X6C, 0X6D, 0X6E, 0X6F,
        0X70, 0X71, 0X72, 0X73, 0X74, 0X75, 0X76, 0X77, 0X78, 0X79, 0X7A, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*!
 * check dns name format.
 * name should in binary form(len label)
 *
 * @param name : the name <len label format>
 * @param max : the max size of name(include terminate null), mainly used to detect the name which doesn't endswith 0.
 * @return -1 if the format is incorrect, otherwise return the length of the len label string.
 */
int checkLenLabel(char *name, size_t max) {
    if (max == 0) max = strlen(name) + 1;

    char *start = name;
    for (int len = *name++; len != 0; len = *name++) {
        if (len > MAX_LABEL_LEN) return ERR_CODE;
        if ((size_t)(name+len-start) >= max) return ERR_CODE;

        for (int j = 0; j < len; ++j, name++) {
            if (! _dnsValidCharTable[(int)(*name)]) {
                return ERR_CODE;
            }
        }
    }
    return (int)(name-start);
}

//we do not support type DS, KEY etc.
bool isSupportDnsType(uint16_t type) {
    static const unsigned char supportTypeTable[256] = {
            0, DNS_TYPE_A, DNS_TYPE_NS, 0, 0, DNS_TYPE_CNAME, DNS_TYPE_SOA, 0, 0, 0, 0, 0, DNS_TYPE_PTR, 0, 0, DNS_TYPE_MX,
            DNS_TYPE_TXT, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, DNS_TYPE_AAAA, 0, 0, 0,
            0, DNS_TYPE_SRV, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    if (type > 0xFF) return false;
    return supportTypeTable[type] != 0;
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
    return ERR_CODE;
}

char *DNSTypeToStr(int ty) {
    switch (ty) {
        case DNS_TYPE_A:
            return "A";
        case DNS_TYPE_AAAA:
            return "AAAA";
        case DNS_TYPE_NS:
            return "NS";
        case DNS_TYPE_CNAME:
            return "CNAME";
        case DNS_TYPE_MX:
            return "MX";
        case DNS_TYPE_SOA:
            return "SOA";
        case DNS_TYPE_TXT:
            return "TXT";
        case DNS_TYPE_SRV:
            return "SRV";
        case DNS_TYPE_PTR:
            return "PTR";
        default:
            return "unsupported";
    }
}

char *abs2relative(char *name, char *origin) {
    size_t remain = strlen(name) - strlen(origin);
    if (remain == 0) {
        return zstrdup("@");
    } else {
        char *buf = zmalloc(remain+1);
        memcpy(buf, name, remain);
        buf[remain] = 0;
        return buf;
    }
}

int parseDNSHeader(char *buf, size_t size, uint16_t *xid, uint16_t *flag, uint16_t *nQd,
                   uint16_t *nAn, uint16_t *nNs, uint16_t *nAr)
{
    if (size < DNS_HDR_SIZE) {
        return ERR_CODE;
    }
    // ignore the byte order of xid.
    memcpy(xid, buf, 2);
    buf += 2;
    *flag = load16be(buf);
    buf += 2;
    *nQd = load16be(buf);
    buf += 2;
    *nAn = load16be(buf);
    buf += 2;
    *nNs = load16be(buf);
    buf += 2;
    *nAr = load16be(buf);
    return DNS_HDR_SIZE;
}

int dumpDNSHeader(char *buf, size_t size, uint16_t xid, uint16_t flag,
                  uint16_t nQd, uint16_t nAn, uint16_t nNs, uint16_t nAr)
{
    if (size < DNS_HDR_SIZE) {
        return ERR_CODE;
    }
    // ignore the byte order of xid.
    memcpy(buf, &xid, 2);
    dump16be(flag, buf+2);
    dump16be(nQd, buf+4);
    dump16be(nAn, buf+6);
    dump16be(nNs, buf+8);
    dump16be(nAr, buf+10);
    return DNS_HDR_SIZE;
}

int parseDnsQuestion(char *buf, size_t size, char **name, uint16_t *qType, uint16_t *qClass) {
    char *p = buf;
    int err;
    if ((err = checkLenLabel(buf, size)) == ERR_CODE) {
        return ERR_CODE;
    }
    size_t nameLen = (size_t)err;
    if (size < nameLen+4) {
        return ERR_CODE;
    }
    *name = p;
    p += nameLen;
    *qType = load16be(p);
    p += 2;
    *qClass = load16be(p);
    return (int) (nameLen + 4);
}

int contextMakeRoomForResp(struct context *ctx, int addlen) {
    int freelen = (int)(ctx->chunk_len - ctx->cur);
    if (likely(freelen >= addlen)) return OK_CODE;
    int newlen = (ctx->cur+addlen)*2;
    char *new_buf;
    struct rte_mbuf *new_m, *last_m, *head_m;
    switch (ctx->resp_type) {
        case RESP_STACK:
            new_buf = zmalloc(newlen);
            if (unlikely(new_buf == NULL)) return ERR_CODE;
            rte_memcpy(new_buf, ctx->chunk, ctx->cur);
            ctx->chunk = new_buf;
            ctx->chunk_len = newlen;
            ctx->resp_type = RESP_HEAP;
            break;
        case RESP_HEAP:
            new_buf = zrealloc(ctx->chunk, newlen);
            if (unlikely(new_buf == NULL)) return ERR_CODE;
            ctx->chunk = new_buf;
            ctx->chunk_len = newlen;
            break;
        case RESP_MBUF:
            head_m = ctx->m;
            new_m = get_mbuf();
            last_m = rte_pktmbuf_lastseg(head_m);
            last_m->data_len = (uint16_t )ctx->cur;
            last_m->next = new_m;
            head_m->pkt_len += ctx->cur;
            head_m->nb_segs++;

            ctx->chunk = rte_pktmbuf_mtod(new_m, void*);
            ctx->cur = 0;
            ctx->chunk_len = rte_pktmbuf_tailroom(new_m);
            if (unlikely(ctx->chunk_len < addlen)) return ERR_CODE;
            break;
    }
    return OK_CODE;
}

static int
getCommonSuffixOffset(compressInfo *cps, char *name2, size_t *offset1, size_t *offset2) {
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
    if (*end2 == 0) return ERR_CODE;
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
    if (*end2 == 0) return ERR_CODE;

    *offset1 = end1 - name1;
    *offset2 = end2 - name2;
    if (*offset1 > uncompress_len) {
        return ERR_CODE;
    }
    return OK_CODE;
}

static int
dumpCompressedName(struct context *ctx, char *name) {
    int cur = ctx->cur;
    size_t offset1=0, offset2=0;
    size_t best_offset1 = 256;
    size_t best_offset2 = 256;
    int best_idx = -1;
    for (size_t i = 0; i < ctx->cps_sz; ++i) {
        if (getCommonSuffixOffset(ctx->cps+i, name, &offset1, &offset2) != OK_CODE) continue;
        if (offset2 < best_offset2) {
            best_offset1 = offset1;
            best_offset2 = offset2;
            best_idx = (int)i;
        }
    }
    // add an entry to compress info array.
    if (best_offset2 > 0 && (ctx->cps_sz < CPS_INFO_SIZE)) {
        compressInfo temp = {name, cur, best_offset2};
        ctx->cps[ctx->cps_sz] = temp;
        (ctx->cps_sz)++;
    }

    if (best_offset2 < 256) {

        size_t nameOffset = ctx->cps[best_idx].offset + best_offset1;
        nameOffset |= 0xC000;

        cur = snpack(ctx->chunk, cur, ctx->chunk_len, "m>h", name, best_offset2, (uint16_t)nameOffset);
    } else {
        cur = snpack(ctx->chunk, cur, ctx->chunk_len, "m", name, strlen(name)+1);
    }
    if (cur == ERR_CODE) return ERR_CODE;
    ctx->cur = cur;
    return cur;
}

/*
 * dump the common fields(name(compressed), type, class, ttl) of RR
 */
static inline int dumpCompressedRRHeader(char *buf, int offset, size_t size, uint16_t nameOffset,
                                        uint16_t type, uint16_t cls, uint32_t ttl) {
    if (unlikely(size < (size_t)(offset + 10))) return ERR_CODE;
    char *start = buf + offset;
    (*((uint16_t*) start)) = rte_cpu_to_be_16(nameOffset);
    (*((uint16_t*) (start+2))) = rte_cpu_to_be_16(type);
    (*((uint16_t*) (start+4))) = rte_cpu_to_be_16(cls);
    (*((uint32_t*) (start+6))) = rte_cpu_to_be_32(ttl);
    return offset+10;
}

/*!
 * dump the RRSet object to response buffer
 *
 * @param ctx:  context object, used to store the dumped bytes
 * @param rs:  the RRSet object needs to be dumped
 * @param nameOffset: the offset of the name in sds, used to compress the name
 * @return OK_CODE if everything is OK, otherwise return ERR_CODE.
 */
int RRSetCompressPack(struct context *ctx, RRSet *rs, size_t nameOffset)
{
    char *name;
    char *rdata;
    int32_t start_idx = 0;
    uint16_t dnsNameOffset = (uint16_t)(nameOffset | 0xC000);
    int len_offset;

    // support round robin
    if (rs->num > 1) {
        //TODO better way to support round rabin
        zone *z = ctx->z;
        int idx = ctx->lcore_id - z->start_core_idx;
        uint8_t *arr = (uint8_t *)(z->rr_offset_array) + z->rr_offset_array[idx];
        start_idx = (++ arr[rs->z_rr_idx]) % rs->num;
        LOG_DEBUG(USER1, "core: %d, rr idx: %d", ctx->lcore_id, arr[rs->z_rr_idx]);
    }

    for (int i = 0; i < rs->num; ++i) {
        int idx = (i + start_idx) % rs->num;
        rdata = rs->data + (rs->offsets[idx]);

        uint16_t rdlength = load16be(rdata);

        /*
         * expand response buffer if need.
         * the following operation doesn't need to check if the response size is enough.
         */
        if (contextMakeRoomForResp(ctx, rdlength+12) == ERR_CODE) {
            return ERR_CODE;
        }
        ctx->cur = dumpCompressedRRHeader(ctx->chunk, ctx->cur,
                                          ctx->chunk_len, dnsNameOffset,
                                          rs->type, DNS_CLASS_IN, rs->ttl);

        // compress the domain name in NS and MX record.
        switch (rs->type) {
            case DNS_TYPE_CNAME:
            case DNS_TYPE_NS:
                name = rdata + 2;
                len_offset = ctx->cur;
                ctx->cur = snpack(ctx->chunk, ctx->cur, ctx->chunk_len, "m", rdata, 2);
                dumpCompressedName(ctx, name);

                dump16be((uint16_t)(ctx->cur-len_offset-2), ctx->chunk+len_offset);
                if (ctx->ari_sz < AR_INFO_SIZE) {
                    arInfo ai_temp = {name, len_offset+2};
                    ctx->ari[ctx->ari_sz++] = ai_temp;
                }
                break;
            case DNS_TYPE_MX:
                name = rdata + 4;
                len_offset = ctx->cur;
                // store preference
                rte_memcpy(ctx->chunk+ctx->cur+2, rdata+2, 2);
                ctx->cur+=4;

                dumpCompressedName(ctx, name);
                // store rdlength
                dump16be((uint16_t)(ctx->cur-len_offset-2), ctx->chunk+len_offset);
                if (ctx->ari_sz < AR_INFO_SIZE) {
                    arInfo ai_temp = {name, len_offset+4};
                    ctx->ari[ctx->ari_sz++] = ai_temp;
                }
                break;
            case DNS_TYPE_SRV:
                // don't compress the target field, but need add compress info for the remain records.
                name = rdata + 8;
                len_offset = ctx->cur;
                if (ctx->cps_sz < CPS_INFO_SIZE) {
                    compressInfo temp = {name, len_offset+8, rdlength-6};
                    ctx->cps[ctx->cps_sz++] = temp;
                }
                rte_memcpy(ctx->chunk+ctx->cur, rdata, rdlength+2);
                ctx->cur += (rdlength+2);

                if (ctx->ari_sz < AR_INFO_SIZE) {
                    arInfo ai_temp = {name, len_offset+8};
                    ctx->ari[ctx->ari_sz++] = ai_temp;
                }
                break;
            default:
                rte_memcpy(ctx->chunk+ctx->cur, rdata, rdlength+2);
                ctx->cur += (rdlength+2);
        }
    }
    return OK_CODE;
}

static int
parseEdnsOptions(char *rdata, unsigned rdlength, struct context *ctx) {
    struct clientSubnetOpt *opt = &ctx->subnet_opt;
    while(rdlength) {
        if (rdlength < 4) {
            return ERR_CODE;
        }
        uint16_t opt_code = load16be(rdata);
        rdata += 2;
        uint16_t opt_len = load16be(rdata);
        rdata += 2;
        rdlength -=2;
        if (opt_len > rdlength) return ERR_CODE;
        if (opt_code == OPT_CLIENT_SUBNET_CODE) {
            if (parseClientSubnet(rdata, rdlength, opt) != OK_CODE) {
                return ERR_CODE;
            }
        }
        rdata += opt_len;
        rdlength -= opt_len;
    }
    return OK_CODE;
}

decodeRcode decodeQuery(char *buf, size_t sz, struct context *ctx) {
    int n;
    if (sz < 12) {
        LOG_DEBUG(USER1, "receive bad dns query message with only %d bytes, drop it", sz);
        // just ignore this packet(don't send response)
        return DECODE_IGNORE;
    }
    dnsHeader_load(buf, sz, &(ctx->hdr));
    n = parseDnsQuestion(buf+DNS_HDR_SIZE, sz-DNS_HDR_SIZE, &(ctx->name), &(ctx->qType), &(ctx->qClass));
    if (n == ERR_CODE) {
        LOG_DEBUG(USER1, "parse dns question error.");
        return DECODE_IGNORE;
    }
    // skip dns header and dns question.
    ctx->cur = DNS_HDR_SIZE + n;

    LOG_DEBUG(USER1, "receive dns query message(xid: %d, qd: %d, an: %d, ns: %d, ar:%d)",
              ctx->hdr.xid, ctx->hdr.nQd, ctx->hdr.nAnRR, ctx->hdr.nNsRR, ctx->hdr.nArRR);
    // in order to support EDNS, nArRR can bigger than 0
    if (ctx->hdr.nQd != 1 || ctx->hdr.nAnRR > 0 || ctx->hdr.nNsRR > 0) {
        LOG_DEBUG(USER1, "receive bad dns query message(xid: %d, qd: %d, an: %d, ns: %d, ar: %d), drop it",
                  ctx->hdr.xid, ctx->hdr.nQd, ctx->hdr.nAnRR, ctx->hdr.nNsRR, ctx->hdr.nArRR);
        return DECODE_FORMERR;
    }

    ctx->nameLen = lenlabellen(ctx->name);

    if (isSupportDnsType(ctx->qType) == false) {
        return DECODE_NOTIMP;
    }
    /*
     * parse OPT message(EDNS)
     */
    if (ctx->hdr.nArRR > 0
        && likely(sz-ctx->cur >= 11)
        && likely(buf[ctx->cur] == '\0'
        && likely(load16be(buf+ctx->cur+1) == DNS_TYPE_OPT))) {
        ctx->cur += 3;
        if (ednsParse(buf+ctx->cur, sz-ctx->cur, &(ctx->edns)) == ERR_CODE) {
            return DECODE_FORMERR;
        }
        if (ctx->edns.version != 0) {
            return DECODE_BADVERS;
        }
        LOG_DEBUG(USER1, "ENDS: payload: %d, version: %d, rdlength: %d",
                  ctx->edns.payload_size, ctx->edns.version, ctx->edns.rdlength);
        if (ctx->edns.rdlength) {
            if (parseEdnsOptions(ctx->edns.rdata, ctx->edns.rdlength, ctx) == ERR_CODE) {
                return DECODE_FORMERR;
            }
        }
    }
    LOG_DEBUG(USER1, "dns question: %s, %d", ctx->name, ctx->qType);
    return DECODE_OK;
}

int dumpDnsResp(struct context *ctx, dnsDictValue *dv, zone *z) {
    if (dv == NULL) return ERR_CODE;
    int errcode;
    numaNode_t *node = ctx->node;

    compressInfo temp = {ctx->name, DNS_HDR_SIZE, ctx->nameLen+1};
    ctx->cps[0] = temp;
    ctx->cps_sz = 1;
    ctx->ari_sz = 0;

    RRSet *cname;
    dnsHeader_t hdr = {ctx->hdr.xid, 0, 1, 0, 0, ctx->hdr.nArRR};

    SET_QR_R(hdr.flag);
    SET_AA(hdr.flag);
    if (GET_RD(ctx->hdr.flag)) SET_RD(hdr.flag);

    cname = dnsDictValueGet(dv, DNS_TYPE_CNAME);
    if (cname) {
        hdr.nAnRR = 1;
        errcode = RRSetCompressPack(ctx, cname, DNS_HDR_SIZE);
        if (errcode == ERR_CODE) {
            return ERR_CODE;
        }
        // dump NS records of the zone this CNAME record's value belongs to to authority section
        if (!sk.minimize_resp) {
            char *name = ctx->ari[0].name;
            size_t offset = ctx->ari[0].offset;
            LOG_DEBUG(USER1, "name: %s, offset: %d", name, offset);
            zone *ns_z = ltreeGetZoneRaw(node->lt, name);
            if (ns_z) {
                if (ns_z->ns) {
                    hdr.nNsRR += ns_z->ns->num;
                    size_t nameOffset = offset + strlen(name) - strlen(ns_z->origin);
                    errcode = RRSetCompressPack(ctx, ns_z->ns, nameOffset);
                    if (errcode == ERR_CODE) {
                        return ERR_CODE;
                    }
                }
            }
        }
    } else {
        // dump answer section.
        RRSet *rs = dnsDictValueGet(dv, ctx->qType);
        if (rs) {
            hdr.nAnRR = rs->num;
            errcode = RRSetCompressPack(ctx, rs, DNS_HDR_SIZE);
            if (errcode == ERR_CODE) {
                return ERR_CODE;
            }
        }
        if (!sk.minimize_resp) {
            // dump NS section
            if (z->ns && (ctx->qType != DNS_TYPE_NS || strcasecmp(z->origin, ctx->name) != 0)) {
                hdr.nNsRR += z->ns->num;
                size_t nameOffset = DNS_HDR_SIZE + ctx->nameLen - strlen(z->origin);
                errcode = RRSetCompressPack(ctx, z->ns, nameOffset);
                if (errcode == ERR_CODE) {
                    return ERR_CODE;
                }
            }
        }
    }
    // MX, NS, SRV records cause additional section processing.
    //TODO avoid duplication
    for (size_t i = 0; i < ctx->ari_sz; i++) {
        zone *ar_z;
        char *name = ctx->ari[i].name;
        size_t offset = ctx->ari[i].offset;

        // TODO avoid fetch when the name belongs to z
        ar_z = ltreeGetZoneRaw(node->lt, name);
        if (ar_z == NULL) continue;
        RRSet *ar_a = zoneFetchTypeVal(ar_z, name, DNS_TYPE_A);
        if (ar_a) {
            hdr.nArRR += ar_a->num;
            errcode = RRSetCompressPack(ctx, ar_a, offset);
            if (errcode == ERR_CODE) {
                return ERR_CODE;
            }
        }
        RRSet *ar_aaaa = zoneFetchTypeVal(ar_z, name, DNS_TYPE_AAAA);
        if (ar_aaaa) {
            hdr.nArRR += ar_aaaa->num;
            errcode = RRSetCompressPack(ctx, ar_aaaa, offset);
            if (errcode == ERR_CODE) {
                return ERR_CODE;
            }
        }
    }
    // dump edns
    if (ctx->hdr.nArRR == 1) {
        int edns_len = ctx->edns.rdlength + 11;
        if (unlikely(contextMakeRoomForResp(ctx, edns_len) == ERR_CODE)) {
            return ERR_CODE;
        }
        ednsDump(ctx->chunk+ctx->cur, ctx->chunk_len-ctx->cur, &ctx->edns);
        ctx->cur += edns_len;
    }
    // update the header. don't update `cur` in ctx
    dnsHeader_dump(&hdr, ctx->chunk, DNS_HDR_SIZE);
    return OK_CODE;
}

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
        test_cond("zone 1", zoneFetchValueRelative(z, "aaa") == NULL);
    }
    zfree(zmalloc(100000));
    dnsDictValue *dv = zoneFetchValueRelative(z, k);
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
