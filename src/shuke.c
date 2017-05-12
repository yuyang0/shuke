//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-05
//
#include <sys/time.h>
#include "dpdk_module.h"

#include <assert.h>
#include "conf.h"
#include "utils.h"
#include "version.h"
#include "ds.h"
#include "protocol.h"
#include "str.h"
#include "zmalloc.h"
#include "endianconv.h"

#include "shuke.h"
#include <getopt.h>
#include <arpa/inet.h>

struct shuke sk;

static void usage() {
    printf("-c /path/to/cdns.conf    configure file.\n"
           "-h                       print this help and exit. \n"
           "-v                       print version. \n");
}

static void version() {
    printf("shuke version: %s\n", SHUKE_VERSION);
}
/*----------------------------------------------
 *     file data store
 *---------------------------------------------*/
int checkFileStore() {
    return OK_CODE;
}

int initFileStore() {
    return OK_CODE;
}

int getAllZoneFromFile() {
    dictIterator *it = dictGetIterator(sk.zone_files_dict);
    dictEntry *de;
    zone *z;
    while((de = dictNext(it)) != NULL) {
        char *dotOrigin = dictGetKey(de);
        char *fname = dictGetVal(de);
        if (loadZoneFromFile(fname, &z) == DS_ERR) {
            return ERR_CODE;
        } else {
            if (strcasecmp(z->dotOrigin, dotOrigin) != 0) {
                LOG_ERROR(USER1, "the origin(%s) of zone in file %s is not %s", z->dotOrigin, fname, dotOrigin);
                zoneDestroy(z);
                return ERR_CODE;
            }
            zoneDictReplace(sk.zd, z);
        }
    }
    dictReleaseIterator(it);
    return OK_CODE;
}

int reloadZoneFromFile(zoneReloadTask *t) {
    zone *z;
    char origin[MAX_DOMAIN_LEN+2];
    char *fname = dictFetchValue(sk.zone_files_dict, t->dotOrigin);
    if (fname == NULL) {
        dot2lenlabel(t->dotOrigin, origin);
        zoneDictDelete(sk.zd, origin);
    } else {
        if (loadZoneFromFile(fname, &z) == DS_ERR) {
            return ERR_CODE;
        } else {
            if (strcasecmp(z->dotOrigin, t->dotOrigin) != 0) {
                LOG_ERROR(USER1, "the origin(%s) of zone in file %s is not %s", z->dotOrigin, fname, t->dotOrigin);
                zoneDestroy(z);
                return ERR_CODE;
            }
            zoneDictReplace(sk.zd, z);
        }
    }
    return OK_CODE;
}

/*----------------------------------------------
 *     utility fucntion
 *---------------------------------------------*/
void logQuery(struct context *ctx, char *cip, int cport, bool is_tcp) {

    char *tcpstr;
    char dotName[MAX_DOMAIN_LEN+2];
    char *ty_str = DNSTypeToStr(ctx->qType);
    char buf[64];
    size_t off;
    struct timeval tv;

    gettimeofday(&tv,NULL);
    off = strftime(buf,sizeof(buf),"%Y/%m/%d %H:%M:%S.",localtime(&tv.tv_sec));
    snprintf(buf+off,sizeof(buf)-off,"%03d",(int)tv.tv_usec/1000);
    len2dotlabel(ctx->name, dotName);
    tcpstr = is_tcp? " +tcp": "";

    fprintf(sk.query_log_fp, "%s queries: client %s#%d%s: query %s IN %s \n", buf, cip, cport, tcpstr, dotName, ty_str);
}

/*!
 * this function will dump all the arguments to buf, the format is specified by fmt.
 * it is similar to the struct package in python.
 *
 * @param buf: buffer used to store bytes
 * @param offset: the start position where the new data should stays.
 * @param size: the total size of buffer
 * @param fmt: the format of the arguments, format used to specify the byte order and data size
 *        byte order:
 *             1. =(native endian)
 *             2. >(big endian)
 *             3. <(little endian)
 *        data size:
 *             1. b(byte)      1 byte
 *             2. h(short)     2 bytes
 *             3. i(int)       4 bytes
 *             4. q(long long) 8 bytes
 *             5. s(string)    using strlen(s)+1 to get length
 *             6. m(memory)    an extra argument is needed to provide the length
 *       pls note if byte order is ignored, then it will use the previous byte order.
 * @param ...
 * @return -1 when the buffer size is not enough, otherwise return the size of bytes written to the buffer(the new offset)
 */
int snpack(char *buf, int offset, size_t size, char const *fmt, ...) {
    char *ptr = buf + offset;
    const char *f = fmt;
    size_t remain = size - offset;
    int result;

    uint8_t  u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    char *ss;
    size_t mem_len;

    va_list ap;
    va_start(ap, fmt);

    bool need_rev = false;
    while(*f) {
        switch(*f) {
            case '=':
                need_rev = false;
                f++;
                break;
            case '<':  // little endian
#if (BYTE_ORDER == BIG_ENDIAN)
                need_rev = true;
#else
                need_rev = false;
#endif
                f++;
                break;
            case '>':  // big endian
            case '!':
#if (BYTE_ORDER == LITTLE_ENDIAN)
                need_rev = true;
#else
                need_rev = false;
#endif
                f++;
                break;
            default:
                break;
        }
        switch(*f) {
            case 'b':
            case 'B':
                if (remain < 1) goto error;
                u8 = (uint8_t)va_arg(ap, int);
                *ptr++ = u8;
                remain--;
                break;
            case 'h':  //signed short
            case 'H':
                if (remain < 2) goto error;
                u16 = (uint16_t )va_arg(ap, int);
                if (need_rev) u16 = rte_bswap16(u16);
                memcpy(ptr, &u16, 2);
                ptr += 2;
                remain -= 2;
                break;
            case 'i':
            case 'I':
                if (remain < 4) goto error;
                u32 = (uint32_t )va_arg(ap, int);
                if (need_rev) u32 = rte_bswap32(u32);
                memcpy(ptr, &u32, 4);
                ptr += 4;
                remain -= 4;
                break;
            case 'q':
            case 'Q':
                if (remain < 8) goto error;
                u64 = (uint64_t )va_arg(ap, long long);
                if (need_rev) u64 = rte_bswap64(u64);
                memcpy(ptr, &u64, 8);
                ptr += 8;
                remain -= 4;
                break;
            case 's':
            case 'S':
                ss = va_arg(ap, char *);
                size_t ss_len = strlen(ss) + 1;
                if (remain < ss_len) goto error;
                memcpy(ptr, ss, ss_len);
                ptr += ss_len;
                remain -= ss_len;
                break;
            case 'm':
            case 'M':
                ss = va_arg(ap, char *);
                mem_len = va_arg(ap, size_t);
                if (remain < mem_len) goto error;
                if (mem_len == 0) break;
                memcpy(ptr, ss, mem_len);
                ptr += mem_len;
                remain -= mem_len;
                break;
            default:
            LOG_FATAL(USER1, "BUG: unknown format %s", fmt);
        }
        f++;
    }
    result = (int)(size-remain);
    goto ok;
error:
    result = -1;
ok:
    va_end(ap);
    return result;
}

int dumpDnsResp(struct context *ctx, dnsDictValue *dv, zone *z) {
    if (dv == NULL) return ERR_CODE;
    // current start position in response buffer.
    int cur;
    int errcode;
    const int AR_INFO_SIZE = 64;
    const int CPS_INFO_SIZE = 64;
    arInfo ari[AR_INFO_SIZE];
    size_t ar_sz = 0;

    compressInfo cps[CPS_INFO_SIZE];
    compressInfo temp = {ctx->name, DNS_HDR_SIZE, ctx->nameLen+1};
    cps[0] = temp;
    size_t cps_sz = 1;

    RRSet *cname;
    dnsHeader_t hdr = {ctx->hdr.xid, 0, 1, 0, 0, 0};

    SET_QR_R(hdr.flag);
    SET_AA(hdr.flag);
    if (GET_RD(ctx->hdr.flag)) SET_RD(hdr.flag);

    cname = dnsDictValueGet(dv, DNS_TYPE_CNAME);
    if (cname) {
        hdr.nAnRR = 1;
        errcode = RRSetCompressPack(ctx, cname, DNS_HDR_SIZE, cps, &cps_sz, CPS_INFO_SIZE, ari, &ar_sz, AR_INFO_SIZE);
        if (errcode == DS_ERR) {
            return ERR_CODE;
        }
        // dump NS records of the zone this CNAME record's value belongs to to authority section
        if (!sk.minimize_resp) {
            char *name = ari[0].name;
            size_t offset = ari[0].offset;
            LOG_DEBUG(USER1, "name: %s, offset: %d", name, offset);
            zone *ns_z = zoneDictGetZone(sk.zd, name);
            if (ns_z) {
                if (ns_z->ns) {
                    hdr.nNsRR += ns_z->ns->num;
                    size_t nameOffset = offset + strlen(name) - strlen(ns_z->origin);
                    errcode = RRSetCompressPack(ctx, ns_z->ns, nameOffset, cps, &cps_sz, CPS_INFO_SIZE, ari, &ar_sz, AR_INFO_SIZE);
                    if (errcode == DS_ERR) {
                        zoneDecRef(ns_z);
                        return ERR_CODE;
                    }
                }
                zoneDecRef(ns_z);
            }
        }
    } else {
        // dump answer section.
        RRSet *rs = dnsDictValueGet(dv, ctx->qType);
        if (rs) {
            hdr.nAnRR = rs->num;
            errcode = RRSetCompressPack(ctx, rs, DNS_HDR_SIZE, cps, &cps_sz, CPS_INFO_SIZE, ari, &ar_sz, AR_INFO_SIZE);
            if (errcode == DS_ERR) {
                return ERR_CODE;
            }
        }
        if (!sk.minimize_resp) {
            // dump NS section
            if (z->ns && (ctx->qType != DNS_TYPE_NS || strcasecmp(z->origin, ctx->name) != 0)) {
                hdr.nNsRR += z->ns->num;
                size_t nameOffset = DNS_HDR_SIZE + ctx->nameLen - strlen(z->origin);
                errcode = RRSetCompressPack(ctx, z->ns, nameOffset, cps, &cps_sz, CPS_INFO_SIZE, ari, &ar_sz, AR_INFO_SIZE);
                if (errcode == DS_ERR) {
                    return ERR_CODE;
                }
            }
        }
    }
    // MX, NS, SRV records cause additional section processing.
    //TODO avoid duplication
    for (size_t i = 0; i < ar_sz; i++) {
        zone *ar_z;
        char *name = ari[i].name;
        size_t offset = ari[i].offset;

        // TODO avoid fetch when the name belongs to z
        ar_z = zoneDictGetZone(sk.zd, name);
        if (ar_z == NULL) continue;
        RRSet *ar_a = zoneFetchTypeVal(ar_z, name, DNS_TYPE_A);
        if (ar_a) {
            hdr.nArRR += ar_a->num;
            errcode = RRSetCompressPack(ctx, ar_a, offset, NULL, NULL, 0, NULL, NULL, 0);
            if (errcode == DS_ERR) {
                zoneDecRef(ar_z);
                return ERR_CODE;
            }
        }
        RRSet *ar_aaaa = zoneFetchTypeVal(ar_z, name, DNS_TYPE_AAAA);
        if (ar_aaaa) {
            hdr.nArRR += ar_aaaa->num;
            errcode = RRSetCompressPack(ctx, ar_aaaa, offset, NULL, NULL, 0, NULL, NULL, 0);
            if (errcode == DS_ERR) {
                zoneDecRef(ar_z);
                return ERR_CODE;
            }
        }
        zoneDecRef(ar_z);
    }
    // update the header. don't update `cur` in ctx
    cur = snpack(ctx->resp, 2, ctx->totallen, ">hhhhh", hdr.flag, hdr.nQd, hdr.nAnRR, hdr.nNsRR, hdr.nArRR);
    assert(cur != ERR_CODE);

    return OK_CODE;
}

int dumpDnsError(struct context *ctx, int err) {
    int cur;
    dnsHeader_t hdr = {ctx->hdr.xid, 0, 1, 0, 0, 0};

    SET_QR_R(hdr.flag);
    if (GET_RD(ctx->hdr.flag)) SET_RD(hdr.flag);
    SET_ERROR(hdr.flag, err);
    if (err == DNS_RCODE_NXDOMAIN) SET_AA(hdr.flag);

    // a little trick, overwrite the dns header, don't update `cur` in ctx
    cur = snpack(ctx->resp, 2, ctx->totallen, ">hhhhh", hdr.flag, hdr.nQd, hdr.nAnRR, hdr.nNsRR, hdr.nArRR);
    assert(cur != ERR_CODE);
    return OK_CODE;
}

static inline int dumpDnsNameErr(struct context *ctx) {
    return dumpDnsError(ctx, DNS_RCODE_NXDOMAIN);
}

static inline int dumpDnsFormatErr(struct context *ctx) {
    return dumpDnsError(ctx, DNS_RCODE_FORMERR);
}

static inline int dumpDnsNotImplErr(struct context *ctx) {
    return dumpDnsError(ctx, DNS_RCODE_NOTIMPL);
}

static inline int dumpDnsRefusedErr(struct context *ctx) {
    return dumpDnsError(ctx, DNS_RCODE_REFUSED);
}

int processUDPDnsQuery(char *buf, size_t sz, char *resp, size_t respLen,
                       char *src_addr, uint16_t src_port, bool is_ipv4)
{
    struct context tmp_ctx;
    struct context *ctx = &tmp_ctx;
    zone *z = NULL;
    dnsDictValue *dv = NULL;
    long ts;
    char *name;
    int ret;

    ctx->resp = resp;
    ctx->totallen = respLen;
    ctx->cur = 0;

    if (sz < 12) {
        LOG_WARN(USER1, "receive bad dns query message with only %d bytes, drop it", sz);
        // just ignore this packet(don't send response)
        return ERR_CODE;
    }
    // ATOM_INC(&(server.nr_req));
    dnsHeader_load(buf, sz, &(ctx->hdr));
    ret = parseDnsQuestion(buf+DNS_HDR_SIZE, sz-DNS_HDR_SIZE, &(ctx->name), &(ctx->qType), &(ctx->qClass));
    if (ret == PROTO_ERR) {
        return ERR_CODE;
    }
    // skip dns header and dns question.
    ctx->cur = DNS_HDR_SIZE + ret;

    LOG_DEBUG(USER1, "receive dns query message(xid: %d, qd: %d, an: %d, ns: %d, ar:%d)",
              ctx->hdr.xid, ctx->hdr.nQd, ctx->hdr.nAnRR, ctx->hdr.nNsRR, ctx->hdr.nArRR);
    // in order to support EDNS, nArRR can bigger than 0
    if (ctx->hdr.nQd != 1 || ctx->hdr.nAnRR > 0 || ctx->hdr.nNsRR > 0 || ctx->hdr.nArRR > 1) {
        LOG_WARN(USER1, "receive bad dns query message(xid: %d, qd: %d, an: %d, ns: %d, ar: %d), drop it",
                 ctx->hdr.xid, ctx->hdr.nQd, ctx->hdr.nAnRR, ctx->hdr.nNsRR, ctx->hdr.nArRR);
        dumpDnsFormatErr(ctx);
        return ctx->cur;
    }

    ctx->nameLen = lenlabellen(ctx->name);

    if (isSupportDnsType(ctx->qType) == false) {
        dumpDnsNotImplErr(ctx);
        return ctx->cur;
    }
    if (ctx->hdr.nArRR == 1) {
        // TODO parse OPT message(EDNS)
    }
    LOG_DEBUG(USER1, "dns question: %s, %d", ctx->name, ctx->qType);

    if (sk.query_log_fp) {
        char cip[IP_STR_LEN];
        int cport;
        int af = is_ipv4? AF_INET:AF_INET6;
        inet_ntop(af, (void*)src_addr,cip,IP_STR_LEN);
        cport = ntohs(src_port);
        logQuery(ctx, cip, cport, false);
    }

    name = ctx->name;

    if (ctx->qType == DNS_TYPE_SRV) {
        // ignore SRV service
        name += (*name +1);
        // ignore SRV proto
        name += (*name +1);
    }
    z = zoneDictGetZone(sk.zd, name);

    if (z == NULL) {
        // zone is not managed by this server
        LOG_DEBUG(USER1, "zone is NULL, name: %s", ctx->name);
        dumpDnsRefusedErr(ctx);
        return ctx->cur;
    }

    // time_t now = sock->srv->unixtime;
    // // check if zone need reload.
    // ts = ATOM_GET(&(z->ts));
    // if (ts + z->refresh < now) {
    //     // put async task to queue to reload zone.
    //     enqueueZoneReloadTaskRaw(z->dotOrigin, z->sn, ts);
    // }
    // if (ts + z->expiry < now) {
    //     dumpDnsNameErr(ctx);
    //     goto end;
    // }

    dv = zoneFetchValue(z, ctx->name);
    if (dv == NULL) {
        dumpDnsNameErr(ctx);
        goto end;
    }
    if (dumpDnsResp(ctx, dv, z) == OK_CODE) {
        goto end;
    }
end:
    if (z != NULL) zoneDecRef(z);
    return ctx->cur;
}

/*----------------------------------------------
 *     dict type definition
 *---------------------------------------------*/
// static unsigned int _dictStringHash(const void *key)
// {
//     return dictGenHashFunction(key, strlen(key));
// }

static unsigned int _dictStringCaseHash(const void *key)
{
    return dictGenCaseHashFunction(key, strlen(key));
}

static void *_dictStringKeyDup(void *privdata, const void *key)
{
    DICT_NOTUSED(privdata);
    return zstrdup(key);
}

static void _dictStringKeyDestructor(void *privdata, void *key)
{
    DICT_NOTUSED(privdata);
    zfree(key);
}

// static int _dictStringKeyCompare(void *privdata, const void *key1,
//                                  const void *key2)
// {
//     DICT_NOTUSED(privdata);
//     return strcmp(key1, key2) == 0;
// }

static int _dictStringKeyCaseCompare(void *privdata, const void *key1,
                                     const void *key2)
{
    DICT_NOTUSED(privdata);
    return strcasecmp(key1, key2) == 0;
}

/* ----------------------- dns Hash Table Type ------------------------*/
static void _dnsDictValDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);
    dnsDictValueDestroy(val);
}

dictType dnsDictType = {
        _dictStringCaseHash, /* hash function */
        _dictStringKeyDup,             /* key dup */
        NULL,                          /* val dup */
        _dictStringKeyCaseCompare,         /* key compare */
        _dictStringKeyDestructor,         /* key destructor */
        _dnsDictValDestructor,         /* val destructor */
};

/* ----------------------- zone Hash Table Type ------------------------*/
static void _zoneDictValDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);
    zone *z = val;
    zoneDecRef(z);
}

dictType zoneDictType = {
        _dictStringCaseHash,  /* hash function */
        _dictStringKeyDup,              /* key dup */
        NULL,                           /* val dup */
        _dictStringKeyCaseCompare,          /* key compare */
        _dictStringKeyDestructor,         /* key destructor */
        _zoneDictValDestructor,         /* val destructor */
};

/* ----------------------- zone file Hash Table Type ------------------------*/
dictType zoneFileDictType = {
        _dictStringCaseHash,  /* hash function */
        _dictStringKeyDup,              /* key dup */
        _dictStringKeyDup,                           /* val dup */
        _dictStringKeyCaseCompare,          /* key compare */
        _dictStringKeyDestructor,         /* key destructor */
        _dictStringKeyDestructor,         /* val destructor */
};
/* ----------------------- command Hash Table Type ------------------------*/
dictType commandTableDictType = {
        _dictStringCaseHash,  /* hash function */
        NULL,              /* key dup */
        NULL,                           /* val dup */
        _dictStringKeyCaseCompare,          /* key compare */
        _dictStringKeyDestructor,         /* key destructor */
        NULL,         /* val destructor */
};

dictType tqOriginsDictType = {
        _dictStringCaseHash,  /* hash function */
        NULL,              /* key dup */
        NULL,                           /* val dup */
        _dictStringKeyCaseCompare,          /* key compare */
        NULL,         /* key destructor */
        NULL,         /* val destructor */
};

/* void processDnsQuery(void *udp_data, int udp_data_len, */
/*                      void *resp_data, int resp_data_len) */
static int handleZoneFileConf(char *errstr, int argc, char *argv[], void *privdata) {
    int err = CONF_OK;
    dict *d = privdata;
    char *k = NULL, *v = NULL;
    if (argc != 2) goto error;
    k = strip(argv[0], "\"");
    v = strip(argv[1], "\"");
    if (isAbsDotDomain(k) == false) {
        snprintf(errstr, ERR_STR_LEN, "%s is not absolute domain name.", k);
        goto error;
    }
    v = toAbsPath(v, sk.zone_files_root);
    if (access(v, F_OK) == -1) {
        snprintf(errstr, ERR_STR_LEN, "%s doesn't exist.", v);
        goto error;
    }
    if (dictAdd(d, k, v) != DICT_OK) {
        snprintf(errstr, ERR_STR_LEN, "duplicate zone file %s", k);
        goto error;
    }
    goto ok;
    error:
    err = CONF_ERR;
    ok:
    zfree(v);
    return err;
}

static void initConfig(int argc, char **argv) {
    int c;
    char *conffile = NULL;
    char *cbuf;
    char cwd[MAXLINE];
    int conf_err;
    if (getcwd(cwd, MAXLINE) == NULL) {
        fprintf(stderr, "getcwd: %s.\n", strerror(errno));
        exit(1);
    }

    // set default values
    sk.promiscuous_on = false;
    sk.numa_on = false;
    sk.parse_ptype = false;

    sk.port = 53;
    sk.daemonize = false;
    sk.logVerbose = false;

    sk.tcp_backlog = 511;
    sk.tcp_keepalive = 300;
    sk.tcp_idle_timeout = 120;
    sk.max_tcp_connections = 1024;

    sk.redis_port = 6379;
    sk.redis_retry_interval = 120;
    sk.mongo_port = 27017;

    sk.admin_port = 14141;
    sk.all_reload_interval = 36000;
    sk.minimize_resp = true;

    while ((c = getopt(argc, argv, "c:hv")) != -1) {
        switch (c) {
        case 'c':
            conffile = optarg;
            break;
        case 'h':
            usage();
            exit(0);
        case 'v':
            version();
            exit(0);
        default:
            abort();
        }
    }

    if (conffile == NULL) {
        fprintf(stderr, "you must specify config file\n");
        exit(1);
    }
    cbuf = readFile(conffile);
    if (cbuf == NULL) {
        fprintf(stderr, "Can't open configure file(%s)\n", conffile);
        exit(1);
    }
    sk.configfile = toAbsPath(conffile, cwd);

    sk.coremask = getStrVal(cbuf, "coremask", NULL);
    CHECK_CONFIG("coremask", sk.coremask != NULL,
                 "Config Error: coremask can't be empty");
    sk.mem_channels = getStrVal(cbuf, "mem_channels", NULL);
    CHECK_CONFIG("mem_channels", sk.mem_channels != NULL,
                 "Config Error: mem_channels can't be empty");
    conf_err = getBoolVal(sk.errstr, cbuf, "promiscuous_on", &sk.promiscuous_on);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getIntVal(sk.errstr, cbuf, "portmask", &sk.portmask);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getBoolVal(sk.errstr, cbuf, "parse_ptype", &sk.parse_ptype);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getBoolVal(sk.errstr, cbuf, "numa_on", &sk.numa_on);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getBoolVal(sk.errstr, cbuf, "jumbo_on", &sk.jumbo_on);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getIntVal(sk.errstr, cbuf, "max_pkt_len", &sk.max_pkt_len);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    sk.rx_queue_config = getStrVal(cbuf, "rx_queue_config", NULL);
    CHECK_CONFIG("rx_queue_config", sk.rx_queue_config != NULL,
                 "Config Error: rx_queue_config can't be empty");

    /* printf("cmsk: %s, pmsk: %d" */
    /*        " config: %s, promiscuous: %d" */
    /*        " enable_jumbo: %d\n", */
    /*        sk.coremask, sk.portmask, */
    /*        sk.rx_queue_config, sk.promiscuous_on, */
    /*        sk.jumbo_on); */

    conf_err = getIntVal(sk.errstr, cbuf, "port", &sk.port);
    CHECK_CONF_ERR(conf_err, sk.errstr);

    sk.data_store = getStrVal(cbuf, "data_store", NULL);
    CHECK_CONFIG("data_store", sk.data_store != NULL,
                 "Config Error: data_store can't be empty");

    if (strcasecmp(sk.data_store, "file") == 0) {
        sk.zone_files_root = getStrVal(cbuf, "zone_files_root", cwd);
        if (*(sk.zone_files_root) != '/') {
            fprintf(stderr, "Config Error: zone_files_root must be an absolute path.\n");
            exit(1);
        }
        sk.zone_files_dict = dictCreate(&zoneFileDictType, NULL);
        if (getBlockVal(sk.errstr, cbuf, "zone_files", &handleZoneFileConf, sk.zone_files_dict) != CONF_OK) {
            fprintf(stderr, "Config Error: %s.\n", sk.errstr);
            exit(1);
        }
    } else if (strcasecmp(sk.data_store, "redis") == 0) {
        sk.redis_host = getStrVal(cbuf, "redis_host", NULL);
        conf_err = getIntVal(sk.errstr, cbuf, "redis_port", &sk.redis_port);
        CHECK_CONF_ERR(conf_err, sk.errstr);

        sk.redis_zone_prefix = getStrVal(cbuf, "redis_zone_prefix", NULL);
        sk.redis_soa_prefix = getStrVal(cbuf, "redis_soa_prefix", NULL);
        sk.redis_origins_key = getStrVal(cbuf, "redis_origins_key", NULL);
        conf_err = getLongVal(sk.errstr, cbuf, "redis_retry_interval", &sk.redis_retry_interval);
        CHECK_CONF_ERR(conf_err, sk.errstr);

        CHECK_CONFIG("redis_host", sk.redis_host != NULL, "redis_host can't be empty");
        CHECK_CONFIG("redis_zone_prefix", sk.redis_zone_prefix != NULL, "redis_zone_prefix can't be empty");
        CHECK_CONFIG("redis_soa_prefix", sk.redis_soa_prefix != NULL, "redis_soa_prefix can't be empty");
        CHECK_CONFIG("redis_origins_key", sk.redis_origins_key != NULL, "redis_origins_key can't be empty");

    } else if (strcasecmp(sk.data_store, "mongo") == 0) {
        sk.mongo_host = getStrVal(cbuf, "mongo_host", NULL);
        conf_err = getIntVal(sk.errstr, cbuf, "mongo_port", &sk.mongo_port);
        CHECK_CONF_ERR(conf_err, sk.errstr);

        CHECK_CONFIG("mongo_host", sk.mongo_host != NULL, NULL);
    } else {
        fprintf(stderr, "invalid data_store config.\n");
        exit(1);
    }

    conf_err = getIntVal(sk.errstr, cbuf, "tcp_backlog", &sk.tcp_backlog);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getIntVal(sk.errstr, cbuf, "tcp_keepalive", &sk.tcp_keepalive);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getIntVal(sk.errstr, cbuf, "tcp_idle_timeout", &sk.tcp_idle_timeout);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getIntVal(sk.errstr, cbuf, "max_tcp_connections", &sk.max_tcp_connections);
    CHECK_CONF_ERR(conf_err, sk.errstr);

    sk.pidfile = getStrVal(cbuf, "pidfile", "/var/run/cdns.pid");
    sk.query_log_file = getStrVal(cbuf, "query_log_file", NULL);
    sk.logfile = getStrVal(cbuf, "logfile", "");

    conf_err = getBoolVal(sk.errstr, cbuf, "log_verbose", &sk.logVerbose);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getBoolVal(sk.errstr, cbuf, "daemonize", &sk.daemonize);
    CHECK_CONF_ERR(conf_err, sk.errstr);

    sk.logLevelStr = getStrVal(cbuf, "loglevel", "info");

    sk.admin_host = getStrVal(cbuf, "admin_host", NULL);
    conf_err = getIntVal(sk.errstr, cbuf, "admin_port", &sk.admin_port);
    CHECK_CONF_ERR(conf_err, sk.errstr);

    conf_err = getIntVal(sk.errstr, cbuf, "all_reload_interval", &sk.all_reload_interval);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getBoolVal(sk.errstr, cbuf, "minimize_resp", &sk.minimize_resp);
    CHECK_CONF_ERR(conf_err, sk.errstr);

    free(cbuf);
}

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
               signum);
        sk.force_quit = true;
    }
}

static void initShuke() {
    sk.arch_bits = (sizeof(long) == 8)? 64 : 32;
    sk.zd = zoneDictCreate();
    if (isEmptyStr(sk.query_log_file)) {
        sk.query_log_fp = NULL;
    } else {
        if (!strcasecmp(sk.query_log_file, "stdout")) sk.query_log_fp = stdout;
        else {
            sk.query_log_fp = fopen(sk.query_log_file, "a");
            if (!sk.query_log_fp) {
                fprintf(stderr, "can't open %s.\n", sk.query_log_file);
                exit(1);
            }
        }
    }

    // if (strcasecmp(sk.data_store, "redis") == 0) {
    //     sk.initAsyncContext = &initRedis;
    //     sk.checkAsyncContext = &checkRedis;
    //     sk.syncGetAllZone = &redisGetAllZone;
    //     sk.asyncReloadAllZone = &redisAsyncReloadAllZone;
    //     sk.asyncReloadZone = &redisAsyncReloadZone;
    // } else
    if (strcasecmp(sk.data_store, "mongo") == 0) {
        sk.initAsyncContext = &initMongo;
        sk.checkAsyncContext = &checkMongo;
        sk.syncGetAllZone = &mongoGetAllZone;
        sk.asyncReloadAllZone = &mongoAsyncReloadAllZone;
        sk.asyncReloadZone = &mongoAsyncReloadZone;
    } else if (strcasecmp(sk.data_store, "file") == 0) {
        sk.initAsyncContext = &initFileStore;
        sk.checkAsyncContext = &checkFileStore;
        sk.syncGetAllZone = &getAllZoneFromFile;
        sk.asyncReloadAllZone = &getAllZoneFromFile;
        sk.asyncReloadZone = &reloadZoneFromFile;
    } else {
        LOG_FATAL(USER1, "invalid data store config %s", sk.data_store);
    }
    // run admin server
    LOG_INFO(USER1, "starting admin server on %s:%d", sk.admin_host, sk.admin_port);
    if (initAdminServer() == ERR_CODE) {
        LOG_FATAL(USER1, "can't init admin server.");
    }
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    sk.force_quit = false;
    initConfig(argc, argv);
    initDpdkModule();
    cleanupDpdkModule();
}
