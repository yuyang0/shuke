//
// Created by yangyu on 17-2-16.
//
#include <string.h>
#include <arpa/inet.h>

#include <rte_branch_prediction.h>

#include "endianconv.h"
#include "zmalloc.h"
#include "protocol.h"
#include "log.h"
#include "utils.h"
#include "dnspacket.h"
#include "dpdk_module.h"


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
