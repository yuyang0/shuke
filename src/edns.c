//
// Created by yangyu on 11/12/17.
//
#include <rte_memcpy.h>
#include "defines.h"
#include "protocol.h"
#include "edns.h"
#include "endianconv.h"

int ednsParse(char *buf, size_t size, edns_t *edns) {
    uint16_t type;
    char *p = buf;
    if (size < 11) return ERR_CODE;
    // skip name
    if (*p != 0) return ERR_CODE;
    p++;
    type = load16be(p);
    p += 2;
    if (type != DNS_TYPE_OPT) return ERR_CODE;

    edns->payload_size = load16be(p);
    p += 2;
    edns->rcode = (uint8_t )(*p);
    edns->version = (uint8_t )(*(p+1));
    edns->flags = load16be(p+2);
    p += 4;
    edns->rdlength = load16be(p);
    p += 2;
    edns->rdata = p;
    return OK_CODE;
}

int ednsDump(char *buf, int size, edns_t *edns) {
    if (size < 11 + edns->rdlength) return ERR_CODE;
    char *p = buf;
    *p++ = 0;
    dump16be(DNS_TYPE_OPT, p);
    p += 2;
    dump16be(edns->payload_size, p);
    p += 2;
    *p++ = edns->rcode;
    *p++ = edns->version;
    dump16be(edns->flags, p);
    p += 2;
    dump16be(edns->rdlength, p);
    p += 2;
    if (edns->rdlength > 0) rte_memcpy(p, edns->rdata, edns->rdlength);
    return OK_CODE;
}

int parseClientSubnet(char *buf, int size, struct clientSubnetOpt *opt) {
    static uint8_t max_addr_size[3] = {0, 4, 16};
    char *p = buf;
    opt->family = load16be(p);
    p += 2;
    opt->source_prefix_len = (uint8_t)(*p++);
    opt->scope_prefix_len = (uint8_t)(*p++);
    if (opt->scope_prefix_len != 0) return ERR_CODE;

    // only support ipv4 and ipv6 address
    if (opt->family != 1 && opt->family != 2) return ERR_CODE;
    int addrlen = (opt->source_prefix_len+7U)/8U;
    if (size < addrlen+4) return ERR_CODE;
    if (addrlen > max_addr_size[opt->family]) return ERR_CODE;

    memcpy(opt->addr, p, addrlen);
    return OK_CODE;
}
