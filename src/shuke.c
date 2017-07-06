//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-05
//
#include <sys/time.h>
#include <getopt.h>
#include <arpa/inet.h>

#include "dpdk_module.h"

#include <assert.h>
#include "conf.h"
#include "utils.h"
#include "version.h"
#include "ds.h"
#include "zmalloc.h"

#include "shuke.h"
#include "asciilogo.h"

struct shuke sk;

int rbtreeInsertZone(zone *z) {
    struct rb_node **new = &(sk.rbroot.rb_node), *parent = NULL;

    /* Figure out where to put new node */
    while (*new) {
        zone *this = container_of(*new, zone, node);
        long result = z->refresh_ts - this->refresh_ts;

        parent = *new;
        if (result <= 0)
            new = &((*new)->rb_left);
        else
            new = &((*new)->rb_right);
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&z->node, parent, new);
    rb_insert_color(&z->node, &sk.rbroot);

    return 1;
}

void rbtreeDeleteZone(zone *z) {
    // return if the zone is not in rbtree
    if (RB_EMPTY_NODE(&z->node)) return;
    rb_erase(&z->node, &sk.rbroot);
    RB_CLEAR_NODE(&z->node);
}

zone *getOldestZone() {
    struct rb_node *n = rb_first(&sk.rbroot);
    if (n) {
        return rb_entry(n, zone, node);
    }
    return NULL;
}

void refreshZone(zone* z) {
    assert(RB_EMPTY_NODE(&z->node));
    z->refresh_ts = sk.unixtime + z->refresh;
    rbtreeInsertZone(z);
}

/*!
 * add or replace a zone to master zone dict, we need update new zone's offsets and  refresh_ts
 * @param z
 * @return
 */
int masterZoneDictReplace(zone *z) {
    zoneDict *zd = sk.zd;
    z->refresh_ts = sk.unixtime + z->refresh;
    zoneUpdateRRSetOffsets(z);

    zoneDictWLock(zd);
    zone *old_z = dictFetchValue(zd->d, z->origin);
    if (old_z) {
        rbtreeDeleteZone(old_z);
    }
    int err = dictReplace(zd->d, z->origin, z);
    rbtreeInsertZone(z);
    zoneDictWUnlock(zd);
    return err;
}

/*!
 * delete zone on all numa node(include master nuam node).
 * @param origin
 * @return
 */
int deleteZoneAllNumaNode(char *origin) {
    int err;
    zoneDict *zd = sk.zd;

    // delete the zone on non-master numa node
    deleteZoneOtherNuma(origin);

    // delete zone on master numa node.
    zoneDictWLock(zd);
    zone *old_z = dictFetchValue(zd->d, origin);
    if (old_z) {
        rbtreeDeleteZone(old_z);
    }
    err = dictDelete(zd->d, origin);
    zoneDictWUnlock(zd);
    return err;
}

/*!
 * create a zone reload Context
 *
 * @param dotOrigin : the origin in <label dot> format
 * @param sn : the serial number of the zone(the sn field in SOA record)
 * @param ts : the timestamp of last update of this zone,
 *             -1 means this function needs to check if this zone is in memory cache.
 * @return obj if everything is ok otherwise return NULL
 */
zoneReloadContext *zoneReloadContextCreate(char *dotOrigin, zone *old_zn) {
    uint32_t sn = 0;
    if (old_zn == NULL) {
        char origin[MAX_DOMAIN_LEN+2];
        dot2lenlabel(dotOrigin, origin);
        old_zn = zoneDictFetchValNoRef(sk.zd, origin);
    }
    if (old_zn != NULL) {
        sn = old_zn->sn;
        // the zone is reloading should not in rbtree.
        rbtreeDeleteZone(old_zn);
    }
    zoneReloadContext *t = zcalloc(sizeof(*t));
    t->dotOrigin = zstrdup(dotOrigin);
    t->sn = sn;
    t->status = TASK_PENDING;
    t->old_zn = old_zn;
    return t;
}

void zoneReloadContextReset(zoneReloadContext *t) {
    t->status = TASK_PENDING;
    if (t->new_zn) zoneDestroy(t->new_zn);
    t->new_zn = NULL;
}

void zoneReloadContextDestroy(zoneReloadContext *t) {
    zfree(t->dotOrigin);
    if (t->new_zn) zoneDestroy(t->new_zn);
    if (t->psr) RRParserDestroy(t->psr);
    zfree(t);
}

/*!
 * re-reload the zone,
 * this function is mainly used to retry the failed zone reload task.
 * @param t
 * @return
 */
int asyncRereloadZone(zoneReloadContext *t) {
    // this is a good place to check if the zone is expired.
    if (t->old_zn) {
        zone *z = t->old_zn;
        long last_reload_ts = z->refresh_ts - z->refresh;
        // the zone is expired, remove it.
        if (last_reload_ts+z->expiry < sk.unixtime) {
            deleteZoneAllNumaNode(z->origin);
            t->old_zn = NULL;
            return ERR_CODE;
        }
    }

    zoneReloadContextReset(t);
    return sk.asyncReloadZone(t);
}

int asyncReloadZoneRaw(char *dotOrigin, zone *old_zn) {
    zoneReloadContext *t = zoneReloadContextCreate(dotOrigin, old_zn);
    if (t == NULL) return ERR_CODE;
    return sk.asyncReloadZone(t);
}

void deleteZoneOtherNuma(char *origin) {
    for (int i = 0; i < sk.nr_numa_id; ++i) {
        int numa_id = sk.numa_ids[i];
        numaNode_t *node = sk.nodes[numa_id];
        if (numa_id == sk.master_numa_id) continue;
        zoneDictDelete(node->zd, origin);
    }
}

void reloadZoneOtherNuma(zone *z) {
    for (int i = 0; i < sk.nr_numa_id; ++i) {
        int numa_id = sk.numa_ids[i];
        numaNode_t *node = sk.nodes[numa_id];
        if (numa_id == sk.master_numa_id) continue;
        zone *new_z = zoneCopy(z, numa_id);
        zoneDictReplace(node->zd, new_z);
    }
}

void config_log() {
    static FILE *fp = NULL;

    uint32_t level = str2loglevel(sk.logLevelStr);
    rte_set_log_level(level);

    if (fp == NULL) {
        fp = stdout;
        char *logfile = sk.logfile;
        if (logfile != NULL && logfile[0] != 0) {
            if (strcasecmp(logfile, "stdout") == 0) {
                fp = stdout;
            } else if (strcasecmp(logfile, "stderr") == 0) {
                fp = stderr;
            } else {
                fp = fopen(sk.logfile, "wb");
                if (fp == NULL)
                    rte_exit(EXIT_FAILURE, "can't open log file %s\n", sk.logfile);
            }
        }
    }
    if(rte_openlog_stream(fp) < 0)
        rte_exit(EXIT_FAILURE, "can't openstream\n");
}

static void printAsciiLogo() {
    LOG_RAW(INFO, USER1, "SHUKE %s\n\n%s\n", SHUKE_VERSION, shuke_ascii_logo);
}

void createPidFile(void) {
    /* Try to write the pid file in a best-effort way. */
    FILE *fp = fopen(sk.pidfile,"w");
    if (fp) {
        fprintf(fp,"%d\n",(int)getpid());
        fclose(fp);
    }
}

static void daemonize(void) {
    int fd;

    if (fork() != 0)
        exit(0); /* parent exits */
    setsid(); /* create a new session */

    /* Every output goes to /dev/null. If Agent is daemonized but
     * the 'logfile' is set to 'stdout' in the configuration file
     * it will not log at all. */
    if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
}

static void usage() {
    printf("-c /path/to/cdns.conf    configure file.\n"
           "-h                       print this help and exit. \n"
           "-v                       print version. \n");
}

static void version() {
    printf("shuke version: %s\n", SHUKE_VERSION);
}

static void sigShutdownHandler(int sig) {
    char *msg;

    switch (sig) {
        case SIGINT:
            msg = "Received SIGINT scheduling shutdown...";
            break;
        case SIGTERM:
            msg = "Received SIGTERM scheduling shutdown...";
            break;
        default:
            msg = "Received shutdown signal, scheduling shutdown...";
    };

    LOG_WARN(USER1, msg);
    sk.force_quit = true;
    aeStop(sk.el);
}

void setupSignalHandlers(void) {
    struct sigaction act;

    /* When the SA_SIGINFO flag is set in sa_flags then sa_sigaction is used.
     * Otherwise, sa_handler is used. */
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sigShutdownHandler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);

    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NODEFER | SA_RESETHAND | SA_SIGINFO;
    act.sa_sigaction = sigsegvHandler;
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS, &act, NULL);
    sigaction(SIGFPE, &act, NULL);
    sigaction(SIGILL, &act, NULL);
    return;
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
            masterZoneDictReplace(z);
        }
    }
    dictReleaseIterator(it);
    sk.last_all_reload_ts = sk.unixtime;
    return OK_CODE;
}

int reloadZoneFromFile(zoneReloadContext *t) {
    zone *z;
    char origin[MAX_DOMAIN_LEN+2];
    char *fname = dictFetchValue(sk.zone_files_dict, t->dotOrigin);
    if (fname == NULL) {
        dot2lenlabel(t->dotOrigin, origin);
        deleteZoneAllNumaNode(origin);
    } else {
        if (loadZoneFromFile(fname, &z) == DS_ERR) {
            return ERR_CODE;
        } else {
            if (strcasecmp(z->dotOrigin, t->dotOrigin) != 0) {
                LOG_ERROR(USER1, "the origin(%s) of zone in file %s is not %s", z->dotOrigin, fname, t->dotOrigin);
                zoneDestroy(z);
                return ERR_CODE;
            }
            masterZoneDictReplace(z);
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
    uint64_t msec = rte_tsc_mstime();
    time_t sec = msec/1000;
    // printf("ts %lld, ms %llu\n", sec, msec);
    // struct timeval tv;

    // gettimeofday(&tv,NULL);
    // off = strftime(buf,sizeof(buf),"%Y/%m/%d %H:%M:%S.",localtime(&tv.tv_sec));
    // snprintf(buf+off,sizeof(buf)-off,"%03d",(int)tv.tv_usec/1000);

    off = strftime(buf,sizeof(buf),"%Y/%m/%d %H:%M:%S.",localtime((const time_t *)&sec));
    snprintf(buf+off,sizeof(buf)-off,"%03d",(int)(msec%1000));
    len2dotlabel(ctx->name, dotName);
    tcpstr = is_tcp? " +tcp": "";

    fprintf(sk.query_log_fp, "%s queries: client %s#%d%s: query %s IN %s \n", buf, cip, cport, tcpstr, dotName, ty_str);
}

int dumpDnsResp(struct context *ctx, dnsDictValue *dv, zone *z) {
    if (dv == NULL) return ERR_CODE;
    // current start position in response buffer.
    int cur;
    int errcode;
    numaNode_t *node = ctx->node;
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
            zone *ns_z = zoneDictGetZone(node->zd, name);
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
        ar_z = zoneDictGetZone(node->zd, name);
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
    cur = snpack(ctx->resp, 0, ctx->totallen, "h>hhhhh", hdr.xid, hdr.flag, hdr.nQd, hdr.nAnRR, hdr.nNsRR, hdr.nArRR);
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
    cur = snpack(ctx->resp, 0, ctx->totallen, "h>hhhhh", hdr.xid, hdr.flag, hdr.nQd, hdr.nAnRR, hdr.nNsRR, hdr.nArRR);
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

static int _getDnsResponse(char *buf, size_t sz, struct context *ctx)
{
    numaNode_t *node = ctx->node;
    zone *z = NULL;
    dnsDictValue *dv = NULL;
    // int64_t now;
    char *name;
    int ret;


    if (sz < 12) {
        LOG_WARN(USER1, "receive bad dns query message with only %d bytes, drop it", sz);
        // just ignore this packet(don't send response)
        return ERR_CODE;
    }
    // ATOM_INC(&(server.nr_req));
    dnsHeader_load(buf, sz, &(ctx->hdr));
    ret = parseDnsQuestion(buf+DNS_HDR_SIZE, sz-DNS_HDR_SIZE, &(ctx->name), &(ctx->qType), &(ctx->qClass));
    if (ret == PROTO_ERR) {
        LOG_DEBUG(USER1, "parse dns question error.");
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

    name = ctx->name;

    if (ctx->qType == DNS_TYPE_SRV) {
        // ignore SRV service
        name += (*name +1);
        // ignore SRV proto
        name += (*name +1);
    }
    z = zoneDictGetZone(node->zd, name);

    if (z == NULL) {
        // zone is not managed by this server
        LOG_DEBUG(USER1, "zone is NULL, name: %s", ctx->name);
        dumpDnsRefusedErr(ctx);
        return ctx->cur;
    }

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

int processUDPDnsQuery(char *buf, size_t sz, char *resp, size_t respLen, char *src_addr, uint16_t src_port, bool is_ipv4,
                       numaNode_t *node)
{
    struct context ctx;
    ctx.node = node;
    ctx.resp = resp;
    ctx.totallen = respLen;
    ctx.cur = 0;
    int status;
    status = _getDnsResponse(buf, sz, &ctx);

    if (status != ERR_CODE && sk.query_log_fp) {
        char cip[IP_STR_LEN];
        int cport;
        int af = is_ipv4? AF_INET:AF_INET6;
        inet_ntop(af, (void*)src_addr,cip,IP_STR_LEN);
        cport = ntohs(src_port);
        logQuery(&ctx, cip, cport, false);
    }
    return status;
}

int processTCPDnsQuery(tcpConn *conn, char *buf, size_t sz)
{
    int status;
    char resp[4096];
    size_t respLen = 4096;

    struct context ctx;
    ctx.node = sk.nodes[sk.master_numa_id];
    ctx.resp = resp;
    ctx.totallen = respLen;
    ctx.cur = 0;

    status = _getDnsResponse(buf, sz, &ctx);

    if (status != ERR_CODE && sk.query_log_fp) {
        logQuery(&ctx, conn->cip, conn->cport, true);
    }

    snpack(ctx.resp, DNS_HDR_SIZE, respLen, "m>hh", ctx.name, ctx.nameLen+1, ctx.qType, ctx.qClass);
    tcpConnAppendDnsResponse(conn, ctx.resp, ctx.cur);
    return status;
}

static void updateCachedTime() {
    sk.unixtime = time(NULL);
    sk.mstime = mstime();
}

static int mainThreadCron(struct aeEventLoop *el, long long id, void *clientData) {
    UNUSED3(el, id, clientData);
    zone *z;

    updateCachedTime();
    if (sk.checkAsyncContext() == ERR_CODE) {
        // we don't care the return value.
        sk.initAsyncContext();
    }
    if (sk.checkAsyncContext() == OK_CODE) {
        // reload the oldest zones
        while((z = getOldestZone()) != NULL) {
            if (z->refresh_ts > sk.unixtime) break;
            asyncReloadZoneRaw(NULL, z);
        }
        // check if need to do all reload
        if (sk.unixtime - sk.last_all_reload_ts > sk.all_reload_interval) {
            LOG_INFO(USER1, "start reloading all zone asynchronously.");
            sk.asyncReloadAllZone();
        }
    }
    // run tcp dns server cron
    tcpServerCron(el, id, (void *)sk.tcp_srv);
    return TIME_INTERVAL;
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

static void *_dictStringDup(void *privdata, const void *key)
{
    dict *d = privdata;
    return socket_strdup(d->socket_id, key);
}

static void _dictStringDestructor(void *privdata, void *key)
{
    dict *d = privdata;
    socket_free(d->socket_id, key);
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

/* ----------------------- zone file Hash Table Type ------------------------*/
dictType zoneFileDictType = {
        _dictStringCaseHash,         /* hash function */
        _dictStringDup,              /* key dup */
        _dictStringDup,              /* val dup */
        _dictStringKeyCaseCompare,   /* key compare */
        _dictStringDestructor,       /* key destructor */
        _dictStringDestructor,       /* val destructor */
};
/* ----------------------- command Hash Table Type ------------------------*/
dictType commandTableDictType = {
        _dictStringCaseHash,          /* hash function */
        NULL,                         /* key dup */
        NULL,                         /* val dup */
        _dictStringKeyCaseCompare,    /* key compare */
        _dictStringDestructor,        /* key destructor */
        NULL,                         /* val destructor */
};

static int addZoneFileToConf(char *errstr, int argc, char **argv, void *privdata) {
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
    // don't use zfree.
    free(v);
    return err;
}

static char *getConfigBuf(int argc, char **argv) {
    int c;
    char *conffile = NULL;
    char *cbuf;
    char cwd[MAXLINE];
    if (getcwd(cwd, MAXLINE) == NULL) {
        fprintf(stderr, "getcwd: %s.\n", strerror(errno));
        exit(1);
    }
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
    return cbuf;
}

static void initConfigFromFile(int argc, char **argv) {
    int conf_err;
    char cwd[MAXLINE];

    char *cbuf = getConfigBuf(argc, argv);
    if (getcwd(cwd, MAXLINE) == NULL) {
        fprintf(stderr, "getcwd: %s.\n", strerror(errno));
        exit(1);
    }

    // set default values
    sk.master_lcore_id = -1;
    sk.promiscuous_on = false;
    sk.numa_on = false;

    sk.port = 53;
    sk.daemonize = false;
    sk.logVerbose = false;

    sk.tcp_backlog = 511;
    sk.tcp_keepalive = 300;
    sk.tcp_idle_timeout = 120;
    sk.max_tcp_connections = 1024;

    sk.retry_interval = 120;
    sk.mongo_port = 27017;

    sk.admin_port = 14141;
    sk.all_reload_interval = 36000;
    sk.minimize_resp = true;


    sk.coremask = getStrVal(cbuf, "coremask", NULL);
    CHECK_CONFIG("coremask", sk.coremask != NULL,
                 "Config Error: coremask can't be empty");
    conf_err = getIntVal(sk.errstr, cbuf, "master_lcore_id", &sk.master_lcore_id);
    CHECK_CONF_ERR(conf_err, sk.errstr);

    sk.kni_tx_config = getStrVal(cbuf, "kni_tx_config", NULL);
    CHECK_CONFIG("kni_tx_config", sk.kni_tx_config != NULL,
                 "Config Error: kni_tx_config can't be empty");
    sk.kni_kernel_config = getStrVal(cbuf, "kni_kernel_config", NULL);

    sk.mem_channels = getStrVal(cbuf, "mem_channels", NULL);
    CHECK_CONFIG("mem_channels", sk.mem_channels != NULL,
                 "Config Error: mem_channels can't be empty");
    conf_err = getBoolVal(sk.errstr, cbuf, "promiscuous_on", &sk.promiscuous_on);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getIntVal(sk.errstr, cbuf, "portmask", &sk.portmask);
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

    sk.bindaddr_count = CONFIG_BINDADDR_MAX;
    if (getStrArrayVal(sk.errstr, cbuf, "bind", sk.bindaddr, &(sk.bindaddr_count)) < 0) {
        fprintf(stderr, "Config Error: %s\n", sk.errstr);
        exit(1);
    }

    conf_err = getIntVal(sk.errstr, cbuf, "port", &sk.port);
    CHECK_CONF_ERR(conf_err, sk.errstr);

    sk.data_store = getStrVal(cbuf, "data_store", NULL);
    CHECK_CONFIG("data_store", sk.data_store != NULL,
                 "Config Error: data_store can't be empty");

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

    if (strcasecmp(sk.data_store, "file") == 0) {
        sk.zone_files_root = getStrVal(cbuf, "zone_files_root", cwd);
        if (*(sk.zone_files_root) != '/') {
            fprintf(stderr, "Config Error: zone_files_root must be an absolute path.\n");
            exit(1);
        }
        sk.zone_files_dict = dictCreate(&zoneFileDictType, NULL, SOCKET_ID_HEAP);
        if (getBlockVal(sk.errstr, cbuf, "zone_files", &addZoneFileToConf, sk.zone_files_dict) != CONF_OK) {
            fprintf(stderr, "Config Error: %s.\n", sk.errstr);
            exit(1);
        }
    } else if (strcasecmp(sk.data_store, "mongo") == 0) {
        sk.mongo_host = getStrVal(cbuf, "mongo_host", NULL);
        sk.mongo_dbname = getStrVal(cbuf, "mongo_dbname", NULL);
        conf_err = getIntVal(sk.errstr, cbuf, "mongo_port", &sk.mongo_port);
        CHECK_CONF_ERR(conf_err, sk.errstr);
        conf_err = getLongVal(sk.errstr, cbuf, "retry_interval", &sk.retry_interval);
        CHECK_CONF_ERR(conf_err, sk.errstr);

        CHECK_CONFIG("mongo_host", sk.mongo_host != NULL, NULL);
        CHECK_CONFIG("mongo_dbname", sk.mongo_dbname != NULL, NULL);
    } else {
        fprintf(stderr, "invalid data_store config.\n");
        exit(1);
    }
    free(cbuf);
}

static void initShuke() {
    char ring_name[MAXLINE];
    numaNode_t *master_node = sk.nodes[sk.master_numa_id];
    sk.arch_bits = (sizeof(long) == 8)? 64 : 32;
    sk.starttime = time(NULL);
    updateCachedTime();

    sk.el = aeCreateEventLoop(1024, true);
    assert(sk.el);

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

    sk.rbroot = RB_ROOT;
    master_node->zd = zoneDictCreate(SOCKET_ID_ANY);
    sk.zd = master_node->zd;
    long long reload_all_start = mstime();
    if (sk.syncGetAllZone() == ERR_CODE) {
        LOG_FATAL(USER1, "can't load all zone data from %s", sk.data_store);
    }
    sk.zone_load_time = mstime() - reload_all_start;
    LOG_INFO(USER1, "loading all zone from %s to memory cost %lld milliseconds.", sk.data_store, sk.zone_load_time);
    // replicate zone data to other numa node
    for (int i = 0; i < sk.nr_numa_id; ++i) {
        int numa_id = sk.numa_ids[i];
        if (numa_id == sk.master_numa_id) continue;

        // FIXME: should allocate memory belongs to numa node
        sk.nodes[numa_id]->zd = zoneDictCopy(sk.zd, numa_id);
        snprintf(ring_name, MAXLINE, "NUMA_%d_RING", i);
    }

    sk.last_all_reload_ts = sk.unixtime;

    if (sk.initAsyncContext() == ERR_CODE) {
        LOG_FATAL(USER1, "init %s async context error.", sk.data_store);
    }
    // process task queue
    if (aeCreateTimeEvent(sk.el, TIME_INTERVAL, mainThreadCron, NULL, NULL) == AE_ERR) {
        LOG_FATAL(USER1, "Can't create time event proc");
    }

    // run admin server
    LOG_INFO(USER1, "starting admin server on %s:%d", sk.admin_host, sk.admin_port);
    if (initAdminServer() == ERR_CODE) {
        LOG_FATAL(USER1, "can't init admin server.");
    }
}

static int construct_lcore_list() {
    // construct total lcore list
    char buffer[4096];
    int offset = 0;
    int n = 0;
    for (int i = 0; i < sk.nr_lcore_ids; ++i) {
        if (offset >= 4096) return ERR_CODE;
        if (i == 0)
            n = snprintf(buffer+offset, 4096-offset, "%d", sk.lcore_ids[i]);
        else
            n = snprintf(buffer+offset, 4096-offset, ",%d", sk.lcore_ids[i]);
        offset += n;
    }

    for (int i = 0; i < sk.nr_kni_tx_lcore_id; ++i) {
        if (offset >= 4096) return ERR_CODE;
        n = snprintf(buffer+offset, 4096-offset, ",%d", sk.kni_tx_lcore_ids[i]);
        offset += n;
    }
    sk.total_lcore_list = strdup(buffer);
    return OK_CODE;
}

static int hexchar_to_int(char c) {
    char buf[2] = {c, 0};
    return (int)strtol(buf, NULL, 16);
}

static int parse_kni_tx_config() {
    int ids[1024];
    int nr_id = 0;
    bool found;

    char s[256];
    const char *p, *p0 = sk.kni_tx_config;
    char *end;
    enum fieldnames {
        FLD_PORT = 0,
        FLD_LCORE,
        _NUM_FLD
    };
    unsigned long int_fld[_NUM_FLD];
    char *str_fld[_NUM_FLD];
    int nr_fld = _NUM_FLD;
    int i;
    unsigned size;

    int nb_params = 0;

    while ((p = strchr(p0,'(')) != NULL) {
        ++p;
        if((p0 = strchr(p,')')) == NULL) {
            snprintf(sk.errstr, ERR_STR_LEN, "unbalanced parens.");
            return ERR_CODE;
        }

        size = (unsigned)(p0 - p);
        if(size >= sizeof(s)) {
            snprintf(sk.errstr, ERR_STR_LEN, "config part is too long(%d chars).", size);
            return ERR_CODE;
        }

        snprintf(s, sizeof(s), "%.*s", size, p);
        if (strsplit(s, " ,", str_fld, &nr_fld) < 0 || nr_fld != _NUM_FLD) {
            snprintf(sk.errstr, ERR_STR_LEN, "every part should contain %d token.", _NUM_FLD);
            return ERR_CODE;
        }
        for (i = 0; i < _NUM_FLD; i++){
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno != 0 || end == str_fld[i] || int_fld[i] > 255) {
                snprintf(sk.errstr, ERR_STR_LEN, "token %s is not a number.", str_fld[i]);
                return ERR_CODE;
            }
        }
        if (nb_params >= sk.nr_ports) {
            snprintf(sk.errstr, ERR_STR_LEN, "config number should equal to port number.");
            return ERR_CODE;
        }
        unsigned long portid = int_fld[FLD_PORT];
        int lcore_id = (int)int_fld[FLD_LCORE];
        found = false;
        for (int i = 0; i < nr_id; ++i) {
            if (ids[i] == lcore_id) {
                found = true;
                break;
            }
        }
        if (!sk.kni_conf[portid]) {
            snprintf(sk.errstr, ERR_STR_LEN, "port %lu is not enabled.", portid);
            return ERR_CODE;
        }
        if (found == false) ids[nr_id++] = lcore_id;
        if (sk.kni_conf[portid]->lcore_tx >= 0) {
            snprintf(sk.errstr, ERR_STR_LEN, "duplicate config for port %lu.", portid);
            return ERR_CODE;
        }
        sk.kni_conf[portid]->lcore_tx = lcore_id;
        ++nb_params;
    }
    // check if every port contains lcore_tx
    for (int i = 0; i < sk.nr_ports; ++i) {
        int portid = sk.port_ids[i];
        if (sk.kni_conf[portid]->lcore_tx < 0) {
            snprintf(sk.errstr, ERR_STR_LEN, "port %d doesn't have kni tx lcore config.", portid);
            return ERR_CODE;
        }
    }
    sk.kni_tx_lcore_ids = memdup(ids, nr_id * sizeof(int));
    sk.nr_kni_tx_lcore_id = nr_id;
    sortIntArray(sk.kni_tx_lcore_ids, (size_t)sk.nr_kni_tx_lcore_id);
    return OK_CODE;
}

static int parse_kni_kernel_config() {
    char s[256];
    const char *p, *p0 = sk.kni_kernel_config;
    char *end;
    enum fieldnames {
        FLD_PORT = 0,
        FLD_LCORE,
        _NUM_FLD
    };
    unsigned long int_fld[_NUM_FLD];
    char *str_fld[_NUM_FLD];
    int nr_fld = _NUM_FLD;
    int i;
    unsigned size;

    int nb_params = 0;

    while ((p = strchr(p0,'(')) != NULL) {
        ++p;
        if((p0 = strchr(p,')')) == NULL) {
            snprintf(sk.errstr, ERR_STR_LEN, "unbalanced parens.");
            return ERR_CODE;
        }

        size = (unsigned )(p0 - p);
        if(size >= sizeof(s)) {
            snprintf(sk.errstr, ERR_STR_LEN, "config part is too long(%d chars).", size);
            return ERR_CODE;
        }

        snprintf(s, sizeof(s), "%.*s", size, p);
        if (strsplit(s, " ,", str_fld, &nr_fld) < 0 || nr_fld != _NUM_FLD) {
            snprintf(sk.errstr, ERR_STR_LEN, "every part should contain %d token.", _NUM_FLD);
            return ERR_CODE;
        }

        for (i = 0; i < _NUM_FLD; i++){
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno != 0 || end == str_fld[i] || int_fld[i] > 255) {
                snprintf(sk.errstr, ERR_STR_LEN, "token %s is not a number.", str_fld[i]);
                return ERR_CODE;
            }
        }
        if (nb_params >= sk.nr_ports) {
            snprintf(sk.errstr, ERR_STR_LEN, "config number should equal to port number.");
            return ERR_CODE;
        }
        unsigned long portid = int_fld[FLD_PORT];
        int lcore_id = (int)int_fld[FLD_LCORE];
        if (!sk.kni_conf[portid]) {
            snprintf(sk.errstr, ERR_STR_LEN, "port %lu is not enabled.", portid);
            return ERR_CODE;
        }
        if (sk.kni_conf[portid]->lcore_k >= 0) {
            snprintf(sk.errstr, ERR_STR_LEN, "duplicate config for port %lu.", portid);
            return ERR_CODE;
        }
        sk.kni_conf[portid]->lcore_k = lcore_id;
        ++nb_params;
    }
    // check if every port contains lcore_k
    for (int i = 0; i < sk.nr_ports; ++i) {
        int portid = sk.port_ids[i];
        if (sk.kni_conf[portid]->lcore_k < 0) {
            snprintf(sk.errstr, ERR_STR_LEN, "port %d doesn't have kni kernel lcore config.", portid);
            return ERR_CODE;
        }
    }
    return OK_CODE;
}

static int parse_str_coremask(char *coremask, int buf[], int *n) {
    int max = *n;
    int nr_id = 0;
    // skip '0' and 'x'
    char *start = coremask + 2;
    char *end = coremask + strlen(coremask) - 1;
    char *p = end;
    for (; p >= start; --p) {
        int char_int = hexchar_to_int(*p);
        for (int i = 0; i < 4; ++i) {
            if ((1 << i) & char_int) {
                int lcore_id = (int)(4 * (end - p) + i);
                if (nr_id >= max) return ERR_CODE;
                buf[nr_id++] = lcore_id;
            }
        }
    }
    *n = nr_id;
    return OK_CODE;
}

static int get_port_ids(int buf[], int *n) {
    int max = *n;
    int nr_id = 0;
    int num_bits = sizeof(sk.portmask) * 8;
    for (int i = 0; i < num_bits; ++i) {
        if (sk.portmask & (1 << i)) {
            if (nr_id >= max) return ERR_CODE;
            buf[nr_id++] = i;
        }
    }
    *n = nr_id;
    return OK_CODE;
}

int initNumaConfig() {
    int n = 0;
    sk.master_numa_id = rte_lcore_to_socket_id((unsigned)sk.master_lcore_id);

    for (int i = 0; i < sk.nr_lcore_ids; ++i) {
        int lcore_id = sk.lcore_ids[i];
        int numa_id = rte_lcore_to_socket_id((unsigned)lcore_id);
        if (sk.nodes[numa_id] == NULL) {
            sk.nodes[numa_id] = malloc(sizeof(numaNode_t));
            sk.nodes[numa_id]->numa_id = numa_id;
            sk.nodes[numa_id]->main_lcore_id = lcore_id;
            sk.nodes[numa_id]->nr_lcore_ids = 1;
        } else {
            sk.nodes[numa_id]->nr_lcore_ids++;
        }
        sk.lcore_conf[lcore_id].node = sk.nodes[numa_id];
    }
    if (sk.nodes[sk.master_numa_id]->nr_lcore_ids <= 1) {
        fprintf(stderr, "master lcore (%d) is the only enabled core on numa %d.\n",
                sk.master_lcore_id, sk.master_numa_id);
        exit(-1);
    }
    n = 0;
    for (int i = 0; i < MAX_NUMA_NODES; ++i) {
        if (sk.nodes[i] != NULL) {
            sk.numa_ids[n++] = sk.nodes[i]->numa_id;
        }
    }
    sk.nr_numa_id = n;
    LOG_INFO(USER1, "lcore list: %s, numa: %d.", sk.total_lcore_list, sk.nr_numa_id);
    return 0;
}

int initKniConfig() {
    int ids[1024];
    int nr_id;

    nr_id = 1024;
    if (get_port_ids(ids, &nr_id) == ERR_CODE) {
        fprintf(stderr, "error: the number of port is bigger than %d.\n", nr_id);
        abort();
    }
    sk.port_ids = memdup(ids, nr_id * sizeof(int));
    sk.nr_ports = nr_id;

    // initialize kni config
    if (sk.bindaddr_count != sk.nr_ports) {
        fprintf(stderr, "the number of ip address should equal to number of ports.\n");
        exit(-1);
    }
    for (int i = 0; i < sk.nr_ports; ++i) {
        int portid = sk.port_ids[i];
        assert(sk.kni_conf[portid] == NULL);
        sk.kni_conf[portid] = calloc(1, sizeof(struct port_kni_conf));
        assert(sk.kni_conf[portid]);
        snprintf(sk.kni_conf[portid]->name, RTE_KNI_NAMESIZE, "vEth%u", portid);
        sk.kni_conf[portid]->port_id = (uint8_t)portid;
        sk.kni_conf[portid]->lcore_tx = -1;
        sk.kni_conf[portid]->lcore_k = -1;
        sk.kni_conf[portid]->tx_queue_id = (uint16_t )(sk.nr_lcore_ids - 1);
    }

    if (parse_kni_tx_config() != OK_CODE) {
        fprintf(stderr, "kni_tx_config error: %s\n", sk.errstr);
        exit(-1);
    }

    if (sk.kni_kernel_config) {
        if (parse_kni_kernel_config() != OK_CODE) {
            fprintf(stderr, "kni_kernel_config error: %s.\n", sk.errstr);
            exit(-1);
        }
    }
    return OK_CODE;
}

int initOtherConfig() {
    int ids[1024];
    int nr_id;

    nr_id = 1024;
    if (parse_str_coremask(sk.coremask, ids, &nr_id) == ERR_CODE) {
        fprintf(stderr, "error: the number of locre is bigger than %d.\n", nr_id);
        abort();
    }
    sk.lcore_ids = memdup(ids, nr_id * sizeof(int));
    sk.nr_lcore_ids = nr_id;
    /*
     * if master_lcore_id is not set, then use the last lcore id in coremask
     */
    if (sk.master_lcore_id < 0)
        sk.master_lcore_id = sk.lcore_ids[sk.nr_lcore_ids-1];

    initKniConfig();

    if (construct_lcore_list() == ERR_CODE) {
        fprintf(stderr, "error: lcore list is too long\n");
        exit(-1);
    }
    /*
     * because all function provided by dpdk should be called after EAL has been initialized
     * and when init numa config, we need call rte_lcore_to_socket_id. so we init EAL here,
     */
    initDpdkEal();

    initNumaConfig();

    // all kni tx lcores should stay in one socket
    unsigned kni_socket_id = rte_lcore_to_socket_id((unsigned) sk.kni_tx_lcore_ids[0]);
    for (int i = 0; i < sk.nr_kni_tx_lcore_id; ++i) {
        if (kni_socket_id != rte_lcore_to_socket_id((unsigned) sk.kni_tx_lcore_ids[i])) {
            fprintf(stderr, "all kni tx lcores should stay in one socket");
            exit(-1);
        }
    }

    return OK_CODE;
}

int main(int argc, char *argv[]) {
    memset(&sk, 0, sizeof(sk));

    struct timeval tv;
    srand(time(NULL)^getpid());
    gettimeofday(&tv,NULL);
    dictSetHashFunctionSeed(tv.tv_sec^tv.tv_usec^getpid());

#ifdef SK_TEST
    if (argc >= 3 && !strcasecmp(argv[1], "test")) {
        if (!strcasecmp(argv[2], "mongo")) {
            return mongoTest(argc, argv);
        } else if (!strcasecmp(argv[2], "ds")) {
            return dsTest(argc, argv);
        } else if (!strcasecmp(argv[2], "zone_parser")) {
            return zoneParserTest(argc, argv);
        }
        return -1;  /* test not found */
    }
#endif

    rte_atomic64_init(&(sk.nr_req));
    rte_atomic64_init(&(sk.nr_dropped));

    initConfigFromFile(argc, argv);
    if (sk.daemonize) daemonize();
    if (sk.daemonize) createPidFile();
    config_log();

    printAsciiLogo();

    initOtherConfig();

    setupSignalHandlers();

    sk.force_quit = false;
    initDpdkModule();
    init_kni_module();

    initShuke();

    startDpdkThreads();
    start_kni_tx_threads();
    kni_ifconfig_all();

    sleep(4);
    LOG_INFO(USER1, "starting dns tcp server.");
    sk.tcp_srv = tcpServerCreate();
    assert(sk.tcp_srv);

    aeMain(sk.el);

    cleanup_kni_module();
    cleanupDpdkModule();
}
