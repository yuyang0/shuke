//
// Created by Yu Yang on 2017-01-10
//

#include "fmacros.h"

#include <string.h>
#include <stdbool.h>

#include "endianconv.h"
#include "zmalloc.h"
#include "protocol.h"

#define MAXLINE 1024

//we do not support type DS, KEY etc.
bool isSupportDnsType(uint16_t type) {
    static unsigned char supportTypeTable[256] = {
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
    return PROTO_ERR;
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

int getNumLabels(char *name) {
    int len;
    int nLabels = 0;

    for (len=*name; len != 0; name += (len+1), len=*name) {
        nLabels++;
    }
    return nLabels;
}

void getNameInfo(char *name, int *nLabels, size_t *len) {
    char *start = name;
    int l;

    for (l=*name; l != 0; name += (l+1), l=*name) {
        (*nLabels)++;
    }
    *len = name-start;
}

int parseDNSHeader(char *buf, size_t size, uint16_t *xid, uint16_t *flag, uint16_t *nQd,
                   uint16_t *nAn, uint16_t *nNs, uint16_t *nAr)
{
    if (size < DNS_HDR_SIZE) {
        return PROTO_ERR;
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
        return PROTO_ERR;
    }
    // ignore the byte order of xid.
    memcpy(buf, &xid, 2);
    buf += 2;
    dump16be(flag, buf);
    buf += 2;
    dump16be(nQd, buf);
    buf += 2;
    dump16be(nAn, buf);
    buf += 2;
    dump16be(nNs, buf);
    buf += 2;
    dump16be(nAr, buf);
    return DNS_HDR_SIZE;
}

int parseDnsQuestion(char *buf, size_t size, char **name, uint16_t *qType, uint16_t *qClass) {
    char *p = buf;
    if (checkLenLabel(buf, size) == PROTO_ERR) {
        return PROTO_ERR;
    }
    size_t nameLen = strlen(buf) + 1;
    if (size < nameLen+4) {
        return PROTO_ERR;
    }
    *name = p;
    p += nameLen;
    *qType = load16be(p);
    p += 2;
    *qClass = load16be(p);
    return (int) (nameLen + 4);
}

int dumpDnsQuestion(char *buf, size_t size, char *name, uint16_t qType, uint16_t qClass) {
    char *p = buf;
    size_t nameLen = strlen(name) + 1;
    if (size < nameLen+4) {
        return PROTO_ERR;
    }
    memcpy(p, name, nameLen);
    p += nameLen;
    dump16be(qType, p);
    p += 2;
    dump16be(qClass, p);
    return (int) (nameLen + 4);
}

int parseDnsRRInfo(char *buf, size_t sz, char *name, uint16_t *type, uint16_t *cls,
                   uint32_t *ttl, uint16_t *rdlength, void *rdata)
{
    char *p = buf;
    size_t nameLen = strlen(p) + 1;
    size_t totallen = nameLen + 10;
    if (sz < totallen) return PROTO_ERR;

    memcpy(name, p, nameLen);
    p += nameLen;
    *type = load16be(p);
    p += 2;
    *cls = load16be(p);
    p += 2;
    *ttl = load32be(p);
    p += 4;
    *rdlength = load16be(p);
    p += 2;
    totallen += *rdlength;
    if (sz < totallen) return PROTO_ERR;

    memcpy(rdata, p, *rdlength);
    return (int)totallen;
}

int dumpDnsRRInfo(char *buf, size_t sz, char *name, uint16_t type,
                  uint16_t cls, uint32_t ttl, uint16_t rdlength, void *rdata)
{
    char *p = buf;
    size_t nameLen = strlen(name) + 1;
    size_t totallen = nameLen + 10 + rdlength;
    if (sz < totallen) {
        return PROTO_ERR;
    }
    memcpy(p, name, nameLen);
    p += nameLen;

    dump16be(type, p);
    p += 2;
    dump16be(cls, p);
    p += 2;
    dump32be(ttl, p);
    p += 4;
    dump16be(rdlength, p);
    p += 2;
    memcpy(p, rdata, rdlength);
    return (int)(totallen);
}

/*!
 * check dns name format.
 * name should in binary form(len label)
 *
 * @param name : the name <len label format>
 * @param max : the max size of name(include terminate null), mainly used to detect the name which doesn't endswith 0.
 * @return
 */
int checkLenLabel(char *name, size_t max) {
    static unsigned char DnsValidCharTable[256] = {
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
    if (max == 0) max = strlen(name) + 1;

    char *start = name;
    for (int len = *name++; len != 0; len = *name++) {
        if (len > MAX_LABEL_LEN) return PROTO_ERR;
        if ((size_t)(name+len-start) >= max) return PROTO_ERR;

        for (int j = 0; j < len; ++j, name++) {
            if (! DnsValidCharTable[(int)(*name)]) {
                return PROTO_ERR;
            }
        }
    }
    return PROTO_OK;
}

#if defined(CDNS_TEST)
#include <stdio.h>
#include <stdlib.h>
#include "testhelp.h"

#define UNUSED(x) (void)(x)

int dnsTest(int argc, char *argv[]) {
    UNUSED(argc);
    UNUSED(argv);
    test_report();
    return 0;
}
#endif
