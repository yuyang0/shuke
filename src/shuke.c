//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-05
//
#include <sys/time.h>
#include <getopt.h>
#include <arpa/inet.h>

#include "dpdk_module.h"

#include "utils.h"
#include "version.h"
#include "dnspacket.h"
#include "zmalloc.h"
#include "edns.h"

#include "shuke.h"
#include "asciilogo.h"


struct shuke sk;

int rbtreeInsertZone(zone *z) {
    struct rb_node **new = &(sk.rbroot.rb_node), *parent = NULL;

    /* Figure out where to put new node */
    while (*new) {
        zone *this = sk_container_of(*new, zone, rbnode);
        long result = z->refresh_ts - this->refresh_ts;

        parent = *new;
        if (result <= 0)
            new = &((*new)->rb_left);
        else
            new = &((*new)->rb_right);
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&z->rbnode, parent, new);
    rb_insert_color(&z->rbnode, &sk.rbroot);

    return 1;
}

void rbtreeDeleteZone(zone *z) {
    // return if the zone is not in rbtree
    if (RB_EMPTY_NODE(&z->rbnode)) return;
    rb_erase(&z->rbnode, &sk.rbroot);
    RB_CLEAR_NODE(&z->rbnode);
}

zone *getOldestZone() {
    struct rb_node *n = rb_first(&sk.rbroot);
    if (n) {
        return rb_entry(n, zone, rbnode);
    }
    return NULL;
}

/*!
 * adjust the position of zone in rbtree
 * @param origin: must be absolute domain name in len label format.
 */
void masterRefreshZone(char *origin) {
    ltreeRLock(sk.lt);
    zone *z = ltreeGetZoneExactRaw(sk.lt, origin);
    ltreeRUnlock(sk.lt);

    if (z == NULL) return;
    assert(RB_EMPTY_NODE(&z->rbnode));
    z->refresh_ts = sk.unixtime + z->refresh;
    rbtreeInsertZone(z);
}

void zoneUpdateRoundRabinInfo(zone *z) {
    int nr_rr_idx = 0;
    struct numaNode_s *node;

    dictIterator *it = dictGetIterator(z->d);
    dictEntry *de;
    while((de = dictNext(it)) != NULL) {
        dnsDictValue *dv = dictGetVal(de);
        for (int i = 0; i < SUPPORT_TYPE_NUM; ++i) {
            RRSet *rs = dv->v.rsArr[i];
            if (rs) {
                RRSetUpdateOffsets(rs);
                if (rs->num > 1) {
                    rs->z_rr_idx = nr_rr_idx++;
                }
            }
        }
    }
    dictReleaseIterator(it);

    assert(z->rr_offset_array == NULL);
    node = sk.nodes[z->socket_id];

    // to avoid False Share
    nr_rr_idx = ((nr_rr_idx - 1) / RTE_CACHE_LINE_SIZE + 1) * RTE_CACHE_LINE_SIZE;

    z->start_core_idx = node->min_lcore_id;
    int arr_len = node->max_lcore_id - node->min_lcore_id + 1;
    uint32_t arr_size = sizeof(uint32_t)*arr_len;
    size_t totalsize = arr_size + node->nr_lcore_ids * nr_rr_idx;
    z->rr_offset_array = socket_calloc(z->socket_id, 1, totalsize);

    for (int i = 0; i < node->nr_lcore_ids; ++i) {
        int lcore_id = node->lcore_ids[i];
        int idx = lcore_id - node->min_lcore_id;
        z->rr_offset_array[idx] = arr_size + i * nr_rr_idx * sizeof(uint8_t);
    }
}

/*!
 * add or replace a zone to all numa node's zone dict, we need update new zone's offsets and refresh_ts
 * @param z
 * @return
 */
int replaceZoneAllNumaNodes(zone *z) {
    int err = 0;
    z->refresh_ts = sk.unixtime + z->refresh;
    zoneUpdateRoundRabinInfo(z);

    replaceZoneOtherNuma(z);

    ltreeWLock(sk.lt);
    zone *old_z = ltreeGetZoneExactRaw(sk.lt, z->origin);
    if (old_z != NULL) {
        rbtreeDeleteZone(old_z);
        err = 0;
    }
    ltreeReplaceNoLock(sk.lt, z);
    ltreeWUnlock(sk.lt);

    rbtreeInsertZone(z);
    return err;
}

int addZoneAllNumaNodes(zone *z) {
    z->refresh_ts = sk.unixtime + z->refresh;
    zoneUpdateRoundRabinInfo(z);

    addZoneOtherNuma(z);

    int err = ltreeAdd(sk.lt, z);
    assert(err == DICT_OK);
    rbtreeInsertZone(z);
    return err;
}
/*!
 * delete zone on all numa node(include master nuam node).
 * @param origin
 * @return
 */
int deleteZoneAllNumaNodes(char *origin) {
    int err = 0;

    // delete the zone on non-master numa node
    deleteZoneOtherNuma(origin);

    ltreeWLock(sk.lt);
    zone *del_z = ltreeGetZoneExactRaw(sk.lt, origin);
    if (del_z != NULL) {
        rbtreeDeleteZone(del_z);
    }
    ltreeDeleteNoLock(sk.lt, origin);

    ltreeWUnlock(sk.lt);
    return err;
}

static int __pushZoneReloadContext(zoneReloadContext *ctx) {
    zoneReloadContextList *list = &sk.tasks;
    assert(ctx != NULL);

    /* Store callback in list */
    if (list->head == NULL)
        list->head = ctx;
    if (list->tail != NULL)
        list->tail->next = ctx;
    list->tail = ctx;
    return OK_CODE;
}

static zoneReloadContext* __shiftZoneReloadContext() {
    zoneReloadContextList *list = &sk.tasks;
    zoneReloadContext *ctx = list->head;

    if (ctx != NULL) {
        list->head = ctx->next;
        if (ctx == list->tail)
            list->tail = NULL;
        ctx->next = NULL;
    }
    return ctx;
}

/*!
 * create a zone reload Context
 *
 * @param dotOrigin : the origin in <label dot> format
 * @return obj if everything is ok otherwise return NULL
 */
zoneReloadContext *zoneReloadContextCreate(char *dotOrigin) {
    zoneReloadContext *t = NULL;
    zone *old_zn;
    uint32_t sn = 0;
    int32_t refresh=0, expiry=0;
    long refresh_ts = 0;
    bool zone_exist = false;

    char origin[MAX_DOMAIN_LEN+2];
    dot2lenlabel(dotOrigin, origin);

    ltreeRLock(sk.lt);
    old_zn = ltreeGetZoneExactRaw(sk.lt, origin);

    if (old_zn != NULL) {
        /*
         * this zone is in reloading state.
         */
        if (RB_EMPTY_NODE(&old_zn->rbnode)) {
            t = NULL;
            snprintf(sk.errstr, ERR_STR_LEN, "%s is already in reloading state.", dotOrigin);
            goto invalid;
        }
        sn = old_zn->sn;
        dotOrigin = old_zn->dotOrigin;
        refresh = old_zn->refresh;
        expiry = old_zn->expiry;
        refresh_ts = old_zn->refresh_ts;
        zone_exist = true;
        // the zone is reloading should not in rbtree.
        rbtreeDeleteZone(old_zn);
    }

    t = zcalloc(sizeof(*t));
    t->dotOrigin = zstrdup(dotOrigin);
    t->sn = sn;
    t->refresh = refresh;
    t->expiry = expiry;
    t->refresh_ts = refresh_ts;
    t->zone_exist = zone_exist;
    t->status = TASK_PENDING;
invalid:
    ltreeRUnlock(sk.lt);
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
 * @param ctx
 * @return
 */
int asyncRereloadZone(zoneReloadContext *ctx) {
    // this is a good place to check if the zone is expired.
    if (ctx->zone_exist) {
        char origin[MAX_DOMAIN_LEN+2];
        long last_reload_ts = ctx->refresh_ts - ctx->refresh;
        dot2lenlabel(ctx->dotOrigin, origin);
        // the zone is expired, remove it.
        if (last_reload_ts+ctx->expiry < sk.unixtime) {
            deleteZoneAllNumaNodes(origin);
            return ERR_CODE;
        }
    }
    zoneReloadContextReset(ctx);
    __pushZoneReloadContext(ctx);
    return OK_CODE;
}

int asyncReloadZoneRaw(char *dotOrigin) {
    if (sk.checkAsyncContext() != OK_CODE) return ERR_CODE;
    zoneReloadContext *ctx = zoneReloadContextCreate(dotOrigin);
    if (ctx == NULL) return ERR_CODE;
    __pushZoneReloadContext(ctx);
    return OK_CODE;
}

int triggerReloadAllZone() {
    // just reset last_all_reload_ts, then it will trigger reload all immediately.
    sk.last_all_reload_ts -= sk.all_reload_interval;
    return OK_CODE;
}

void deleteZoneOtherNuma(char *origin) {
    for (int i = 0; i < sk.nr_numa_id; ++i) {
        int numa_id = sk.numa_ids[i];
        numaNode_t *node = sk.nodes[numa_id];
        if (numa_id == sk.master_numa_id) continue;
        ltreeDelete(node->lt, origin);
    }
}

void replaceZoneOtherNuma(zone *z) {
    for (int i = 0; i < sk.nr_numa_id; ++i) {
        int numa_id = sk.numa_ids[i];
        numaNode_t *node = sk.nodes[numa_id];
        if (numa_id == sk.master_numa_id) continue;
        zone *new_z = zoneCopy(z, numa_id);
        zoneUpdateRoundRabinInfo(new_z);

        ltreeReplace(node->lt, new_z);
    }
}

void addZoneOtherNuma(zone *z) {
    int err;
    for (int i = 0; i < sk.nr_numa_id; ++i) {
        int numa_id = sk.numa_ids[i];
        numaNode_t *node = sk.nodes[numa_id];
        if (numa_id == sk.master_numa_id) continue;
        zone *new_z = zoneCopy(z, numa_id);
        zoneUpdateRoundRabinInfo(new_z);

        err = ltreeAdd(node->lt, new_z);
        assert(err == DICT_OK);
    }
}

void collectStats() {
    int64_t nr_req = 0, nr_dropped = 0;
    unsigned lcore_id = 0;
    lcore_conf_t *qconf;

    for (int i = 0; i < sk.nr_lcore_ids; ++i) {
        lcore_id = (unsigned )sk.lcore_ids[i];
        if (lcore_id == rte_get_master_lcore()) continue;

        qconf = &sk.lcore_conf[lcore_id];
        nr_req += qconf->nr_req;
        nr_dropped += qconf->nr_dropped;
    }
    sk.nr_req = nr_req;
    sk.nr_dropped = nr_dropped;
    sk.last_collect_ms = mstime();
}

void config_log() {
    FILE *fp = sk.log_fp;

    uint32_t level = str2loglevel(sk.logLevelStr);
    rte_log_set_global_level(level);

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
        sk.log_fp = fp;
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
    printf("-c /path/to/shuke.conf    configure file.\n"
           "-h                        print this help and exit. \n"
           "-v                        print version. \n");
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
    if (sk.daemonize)
        unlink(sk.pidfile);
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

static int _getAllZoneFromFile(bool is_first) {
    dictIterator *it = dictGetIterator(sk.zone_files_dict);
    dictEntry *de;
    zone *z;
    while((de = dictNext(it)) != NULL) {
        char *dotOrigin = dictGetKey(de);
        char *fname = dictGetVal(de);
        if (loadZoneFromFile(sk.master_numa_id, fname, &z) == ERR_CODE) {
            return ERR_CODE;
        } else {
            if (strcasecmp(z->dotOrigin, dotOrigin) != 0) {
                LOG_ERROR(USER1, "the origin(%s) of zone in file %s is not %s", z->dotOrigin, fname, dotOrigin);
                zoneDestroy(z);
                return ERR_CODE;
            }
            if (is_first) addZoneAllNumaNodes(z);
            else replaceZoneAllNumaNodes(z);
        }
    }
    dictReleaseIterator(it);
    sk.last_all_reload_ts = sk.unixtime;
    return OK_CODE;
}

int getAllZoneFromFile() {
    return _getAllZoneFromFile(false);
}

int initialGetAllZoneFromFile() {
    return _getAllZoneFromFile(true);
}

int reloadZoneFromFile(zoneReloadContext *t) {
    zone *z;
    char origin[MAX_DOMAIN_LEN+2];
    char *fname = dictFetchValue(sk.zone_files_dict, t->dotOrigin);
    if (fname == NULL) {
        dot2lenlabel(t->dotOrigin, origin);
        deleteZoneAllNumaNodes(origin);
    } else {
        if (loadZoneFromFile(sk.master_numa_id, fname, &z) == ERR_CODE) {
            return ERR_CODE;
        } else {
            if (strcasecmp(z->dotOrigin, t->dotOrigin) != 0) {
                LOG_ERROR(USER1, "the origin(%s) of zone in file %s is not %s", z->dotOrigin, fname, t->dotOrigin);
                zoneDestroy(z);
                return ERR_CODE;
            }
            replaceZoneAllNumaNodes(z);
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

int dumpDnsError(struct context *ctx, int err) {
    dnsHeader_t hdr = {ctx->hdr.xid, 0, 1, 0, 0, ctx->hdr.nArRR};

    SET_QR_R(hdr.flag);
    if (GET_RD(ctx->hdr.flag)) SET_RD(hdr.flag);
    SET_ERROR(hdr.flag, err);
    if (err == DNS_RCODE_NXDOMAIN) SET_AA(hdr.flag);

    if (ctx->hdr.nArRR == 1) {
        int edns_len = ctx->edns.rdlength + 11;
        if (unlikely(contextMakeRoomForResp(ctx, edns_len) == ERR_CODE)) {
            return ERR_CODE;
        }
        ednsDump(ctx->chunk+ctx->cur, ctx->chunk_len-ctx->cur, &ctx->edns);
        ctx->cur += edns_len;
    }
    // a little trick, overwrite the dns header, don't update `cur` in ctx
    dnsHeader_dump(&hdr, ctx->chunk, DNS_HDR_SIZE);
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
    struct dname dn;
    numaNode_t *node = ctx->node;
    zone *z = NULL;
    dnsDictValue *dv = NULL;
    // int64_t now;
    int ret;

    if (sz < 12) {
        LOG_DEBUG(USER1, "receive bad dns query message with only %d bytes, drop it", sz);
        // just ignore this packet(don't send response)
        return ERR_CODE;
    }
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
    if (ctx->hdr.nQd != 1 || ctx->hdr.nAnRR > 0 || ctx->hdr.nNsRR > 0) {
        LOG_DEBUG(USER1, "receive bad dns query message(xid: %d, qd: %d, an: %d, ns: %d, ar: %d), drop it",
                  ctx->hdr.xid, ctx->hdr.nQd, ctx->hdr.nAnRR, ctx->hdr.nNsRR, ctx->hdr.nArRR);
        dumpDnsFormatErr(ctx);
        ret = OK_CODE;
        goto end;
    }

    ctx->nameLen = lenlabellen(ctx->name);

    if (isSupportDnsType(ctx->qType) == false) {
        dumpDnsNotImplErr(ctx);
        ret = OK_CODE;
        goto end;
    }
    /*
     * parse OPT message(EDNS)
     */
    if (ctx->hdr.nArRR > 0
        && likely(sz-ctx->cur >= 11)
        && likely(buf[ctx->cur] == '\0')) {
        if (ednsParse(buf+ctx->cur, sz-ctx->cur, &(ctx->edns)) == ERR_CODE) {
            ret = ERR_CODE;
            goto end;
        }
        LOG_DEBUG(USER1, "ENDS: payload: %d, version: %d, rdlength: %d",
                  ctx->edns.payload_size, ctx->edns.version, ctx->edns.rdlength);
        if (ctx->edns.rdlength > 4) {
            struct clientSubnetOpt *opt;
            uint16_t opt_code = load16be(ctx->edns.rdata);
            uint16_t opt_len = load16be(ctx->edns.rdata+2);
            switch (opt_code) {
                case OPT_CLIENT_SUBNET_CODE:
                    opt  = &ctx->subnet_opt;
                    if (opt_len >= 4) {
                        if (parseClientSubnet(ctx->edns.rdata+4, ctx->edns.rdlength-4, opt) != OK_CODE) {
                            dumpDnsFormatErr(ctx);
                            ret = OK_CODE;
                            goto end;
                        }
                        LOG_DEBUG(USER1, "family: %d, prefix: %d addr: %#010x", opt->family, opt->source_prefix_len, opt->addr);
                        // printf("%i.%i.%i.%i\n\n", opt->addr[0], opt->addr[1], opt->addr[2], opt->addr[3]);
                    }
                    break;
                default:
                    break;
            }
        }
    }
    LOG_DEBUG(USER1, "dns question: %s, %d", ctx->name, ctx->qType);

    ltreeRLock(node->lt);
    makeDname(ctx->name, &dn);
    z = ltreeGetZone(node->lt, &dn);
    ctx->z = z;

    if (z == NULL) {
        // zone is not managed by this server
        LOG_DEBUG(USER1, "zone is NULL, name: %s", ctx->name);
        dumpDnsRefusedErr(ctx);
        ret = OK_CODE;
    } else {
        dv = zoneFetchValueAbs(z, ctx->name, ctx->nameLen);
        if (dv == NULL) {
            dumpDnsNameErr(ctx);
            ret = OK_CODE;
        } else {
            if (dumpDnsResp(ctx, dv, z) == ERR_CODE) {
                ret = ERR_CODE;
            }
        }
    }
    ltreeRUnlock(node->lt);
end:
    return ret;
}

int processUDPDnsQuery(struct rte_mbuf *m, char *udp_data, size_t udp_data_len,
                       char *src_addr, uint16_t src_port,
                       bool is_ipv4, numaNode_t *node, int lcore_id)
{
    int udp_data_offset = (int)(udp_data - rte_pktmbuf_mtod(m, char*));
    struct context ctx;
    ctx.node = node;
    ctx.lcore_id = lcore_id;
    ctx.chunk = udp_data;
    ctx.chunk_len = rte_pktmbuf_tailroom(m);
    ctx.cur = 0;
    ctx.resp_type = RESP_MBUF;
    ctx.m = m;
    ctx.edns.payload_size = 512;
    int status;
    status = _getDnsResponse(udp_data, udp_data_len, &ctx);

    if (status != ERR_CODE && sk.query_log_fp) {
        char cip[IP_STR_LEN];
        int cport;
        int af = is_ipv4? AF_INET:AF_INET6;
        inet_ntop(af, (void*)src_addr,cip,IP_STR_LEN);
        cport = ntohs(src_port);
        logQuery(&ctx, cip, cport, false);
    }
    struct rte_mbuf *last_m = rte_pktmbuf_lastseg(m);
    last_m->data_len += (uint16_t )ctx.cur;
    m->pkt_len += ctx.cur;

    unsigned max_pkt_len = (unsigned)(ctx.edns.payload_size + udp_data_offset);
    if (m->pkt_len > max_pkt_len) {
        // set TC flag
        *((uint8_t*)(udp_data+2)) |= (uint8_t )0x02;

        rte_pktmbuf_trim(m, (uint16_t)(m->pkt_len - max_pkt_len));
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
    ctx.lcore_id = sk.master_lcore_id;
    ctx.chunk = resp;
    ctx.chunk_len = respLen;
    ctx.cur = 0;
    ctx.resp_type = RESP_STACK;

    status = _getDnsResponse(buf, sz, &ctx);

    if (status != ERR_CODE && sk.query_log_fp) {
        logQuery(&ctx, conn->cip, conn->cport, true);
    }

    snpack(ctx.chunk, DNS_HDR_SIZE, respLen, "m>hh", ctx.name, ctx.nameLen+1, ctx.qType, ctx.qClass);
    tcpConnAppendDnsResponse(conn, ctx.chunk, ctx.cur);
    if(ctx.resp_type == RESP_HEAP) zfree(ctx.chunk);
    return status;
}

static void updateCachedTime() {
    sk.unixtime = time(NULL);
    sk.mstime = mstime();
}

static int mainThreadCron(struct aeEventLoop *el, long long id, void *clientData) {
    UNUSED3(el, id, clientData);
    zone *z;
    zoneReloadContext *ctx;

    updateCachedTime();
    if (sk.checkAsyncContext() == ERR_CODE) {
        // we don't care the return value.
        sk.initAsyncContext();
    } else {
        // reload the oldest zones
        while((z = getOldestZone()) != NULL) {
            if (z->refresh_ts > sk.unixtime) break;
            asyncReloadZoneRaw(z->dotOrigin);
        }
        // check if need to do all reload
        if (sk.unixtime - sk.last_all_reload_ts > sk.all_reload_interval) {
            LOG_INFO(USER1, "start reloading all zone asynchronously.");
            sk.asyncReloadAllZone();
        }
        while ((ctx = __shiftZoneReloadContext()) != NULL) {
            sk.asyncReloadZone(ctx);
        }
    }

    if (! sk.only_udp) {
        // run tcp dns server cron
        tcpServerCron(el, id, (void *)sk.tcp_srv);
    }
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

static char *getConfigFname(int argc, char **argv) {
    int c;
    char *conffile = NULL;
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
    sk.configfile = toAbsPath(conffile, cwd);
    return sk.configfile;
}

static void initShuke() {
    numaNode_t *master_node = sk.nodes[sk.master_numa_id];
    sk.arch_bits = (sizeof(long) == 8)? 64 : 32;
    sk.starttime = time(NULL);
    updateCachedTime();
    sk.last_collect_ms = sk.mstime;

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
        sk.syncGetAllZone = &initialGetAllZoneFromFile;
        sk.asyncReloadAllZone = &getAllZoneFromFile;
        sk.asyncReloadZone = &reloadZoneFromFile;
    } else {
        LOG_EXIT(USER1, "invalid data store config %s", sk.data_store);
    }

    sk.rbroot = RB_ROOT;
    // create zoneDict for all numa nodes
    for (int i = 0; i < sk.nr_numa_id; ++i) {
        int numa_id = sk.numa_ids[i];
        sk.nodes[numa_id]->lt = ltreeCreate(numa_id);
    }
    assert(master_node->lt);
    sk.lt = master_node->lt;

    long long reload_all_start = mstime();
    if (sk.syncGetAllZone() == ERR_CODE) {
        LOG_EXIT(USER1, "can't load all zone data from %s", sk.data_store);
    }
    sk.zone_load_time = mstime() - reload_all_start;
    LOG_INFO(USER1, "loading all zone from %s to memory cost %lld milliseconds.", sk.data_store, sk.zone_load_time);
    sk.last_all_reload_ts = sk.unixtime;

    if (sk.initAsyncContext() == ERR_CODE) {
        LOG_EXIT(USER1, "init %s async context error.", sk.data_store);
    }
    // process task queue
    if (aeCreateTimeEvent(sk.el, TIME_INTERVAL, mainThreadCron, NULL, NULL) == AE_ERR) {
        LOG_EXIT(USER1, "Can't create time event proc");
    }

    // run admin server
    LOG_INFO(USER1, "starting admin server on %s:%d", sk.admin_host, sk.admin_port);
    if (initAdminServer() == ERR_CODE) {
        LOG_EXIT(USER1, "can't init admin server.");
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

    sk.total_lcore_list = strdup(buffer);
    return OK_CODE;
}

static int parseQueueConfigNumList(char *errstr, char *s, int arr[], int *nrEle) {
    char *tokens[1024];
    int nrTokens = 1024;
    int max = *nrEle;
    char *endptr;
    long int v;

    *nrEle = 0;

    s = strip(s, " ");
    if (*s == '[') {
        if (strchr(s, ']') == NULL) {
            snprintf(errstr, ERR_STR_LEN, "need ] near %s", s);
            goto invalid;
        }
        s = strip(s, "[] ");
        if (tokenize(s, tokens, &nrTokens, ",") < 0) {
            snprintf(errstr, ERR_STR_LEN, "%s has too many tokens", s);
            goto invalid;
        }
        for (int i = 0; i < nrTokens; i++) {
            char *subp = strchr(tokens[i], '-');

            if (subp == NULL) {
                tokens[i] = strip(tokens[i], " ");
                v = strtol(tokens[i], &endptr, 10);
                if (*endptr != '\0') {
                    snprintf(errstr, ERR_STR_LEN, "%s is not a integer.", tokens[i]);
                    goto invalid;
                }
                if (*nrEle >= max) {
                    snprintf(errstr, ERR_STR_LEN, "array size is not enough");
                    goto invalid;
                }
                arr[(*nrEle)++] = (int)v;
            } else {
                *subp++ = 0;
                tokens[i] = strip(tokens[i], " ");
                subp = strip(subp, " ");
                long int lbound = strtol(tokens[i], &endptr, 10);
                if (*endptr != '\0') {
                    snprintf(errstr, ERR_STR_LEN, "%s is not a integer.", tokens[i]);
                    goto invalid;
                }
                long int rbound = strtol(subp, &endptr, 10);
                if (*endptr != '\0') {
                    snprintf(errstr, ERR_STR_LEN, "%s is not a integer.", subp);
                    goto invalid;
                }
                for (v=lbound; v<=rbound; ++v) {
                    if (*nrEle >= max) {
                        snprintf(errstr, ERR_STR_LEN, "array size is not enough");
                        goto invalid;
                    }
                    arr[(*nrEle)++] = (int)v;
                }
            }
        }
    } else {
        long int v = strtol(s, &endptr, 10);
        if (*endptr != '\0') {
            snprintf(errstr, ERR_STR_LEN, "syntax error %s", s);
            goto invalid;
        }
        arr[0] = (int)v;
        *nrEle = 1;
    }
    return 0;
invalid:
    return -1;
}

int parseQueueConfigPart(char *errstr, char *s, int cores[], int *nrCores,
                     int ports[], int *nrPorts) {
    char *cStart, *pStart;
    cStart = s;
    pStart = strchr(s, '.');
    if (pStart == NULL) {
        snprintf(errstr, ERR_STR_LEN, "syntax error %s", s);
        goto invalid;
    }
    *pStart++ = 0;
    if (parseQueueConfigNumList(errstr, cStart, cores, nrCores) < 0) {
        goto invalid;
    }
    if (parseQueueConfigNumList(errstr, pStart, ports, nrPorts) < 0) {
        goto invalid;
    }
    return OK_CODE;
invalid:
    return ERR_CODE;
}

int parseQueueConfig(char *errstr, char *s) {
    char *ss = strdup(s);
    char *tokens[4096];
    int nrTokens = 4096;
    int cores[1024];
    int ports[1024];
    int nrCores = 1024;
    int nrPorts = 1024;
    int ret;

    if (tokenize(ss, tokens, &nrTokens, ";") < 0) {
        snprintf(errstr, ERR_STR_LEN, "queue config has syntax error or is too long");
        goto invalid;
    }

    for (int j = 0; j < nrTokens; ++j) {
        ret = parseQueueConfigPart(errstr, tokens[j], cores, &nrCores,
                                    ports, &nrPorts);
        if (ret != OK_CODE) {
            goto invalid;
        }
        sortIntArray(cores, nrCores);
        sortIntArray(ports, nrPorts);

        if (nrCores <= 0 || nrPorts <= 0) {
            snprintf(errstr, ERR_STR_LEN, "invalid queue config.");
            goto invalid;
        }
        for (int i = 0; i < nrPorts; i++) {
            int port_id = ports[i];
            if (port_id < 0 || port_id >= RTE_MAX_ETHPORTS) {
                snprintf(errstr, ERR_STR_LEN, "portid should in 0-%d, but gives %d.", RTE_MAX_ETHPORTS, port_id);
                goto invalid;
            }
            if (! sk.port_info[port_id]) {
                sk.port_info[port_id] = calloc(1, sizeof(port_info_t));
            }

            port_info_t *pinfo = sk.port_info[port_id];
            if (pinfo->lcore_list) {
                snprintf(errstr, ERR_STR_LEN, "duplicate queue config for port %d.", port_id);
                goto invalid;
            }
            pinfo->lcore_list = memdup(cores, sizeof(int)*nrCores);
            pinfo->nr_lcore = nrCores;
            for (int k = 0; k < nrCores; ++k) {
                int lcore_id = cores[k];
                if (lcore_id < 0 || lcore_id >= RTE_MAX_LCORE) {
                    snprintf(errstr, ERR_STR_LEN, "lcore should in 0-%d, but gives %d.", RTE_MAX_LCORE, lcore_id);
                    goto invalid;
                }
                if (lcore_id == sk.master_lcore_id) {
                    snprintf(errstr, ERR_STR_LEN, "queue config should not contain master lcore id.");
                    goto invalid;
                }
                lcore_conf_t *qconf = &sk.lcore_conf[lcore_id];
                qconf->queue_id_list[port_id] = k;

                qconf->port_id_list[qconf->nr_ports] = port_id;
                qconf->nr_ports++;
            }
        }
    }

    free(ss);
    return OK_CODE;
invalid:
    free(ss);
    return ERR_CODE;
}

int initNumaConfig() {
    int n = 0;
    numaNode_t *node;
    sk.master_numa_id = rte_lcore_to_socket_id((unsigned)sk.master_lcore_id);

    for (int i = 0; i < sk.nr_lcore_ids; ++i) {
        int lcore_id = sk.lcore_ids[i];
        int numa_id = rte_lcore_to_socket_id((unsigned)lcore_id);

        node = sk.nodes[numa_id];
        if (node == NULL) {
            node = calloc(1, sizeof(numaNode_t));
            node->numa_id = numa_id;
            node->main_lcore_id = lcore_id;

            node->max_lcore_id = lcore_id;
            node->min_lcore_id = lcore_id;

            node->nr_lcore_ids = 0;
            sk.nodes[numa_id] = node;
        }
        node->nr_lcore_ids++;

        sk.lcore_conf[lcore_id].lcore_id = (uint16_t)lcore_id;
        sk.lcore_conf[lcore_id].node = node;
        sk.lcore_conf[lcore_id].ipv4_packet_id = (uint16_t )i;
    }

    // initialize the lcore id array belongs to this numa node
    for (int i = 0; i < sk.nr_lcore_ids; ++i) {
        int lcore_id = sk.lcore_ids[i];
        int numa_id = rte_lcore_to_socket_id((unsigned)lcore_id);

        node = sk.nodes[numa_id];
        assert(node);
        if (node->lcore_ids == NULL) {
            node->lcore_ids = calloc(node->nr_lcore_ids, sizeof(int));
            node->nr_lcore_ids = 0;
        }
        node->lcore_ids[node->nr_lcore_ids++] = lcore_id;

        if (lcore_id < node->min_lcore_id)
            node->min_lcore_id = lcore_id;
        if (lcore_id > node->max_lcore_id)
            node->max_lcore_id = lcore_id;
    }

    /* if (sk.nodes[sk.master_numa_id]->nr_lcore_ids <= 1) { */
    /*     fprintf(stderr, "master lcore (%d) is the only enabled core on numa %d.\n", */
    /*             sk.master_lcore_id, sk.master_numa_id); */
    /*     exit(-1); */
    /* } */
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

static int merge_int_list(int *l1, int sz1, int *l2, int sz2) {
    int n = sz1;
    bool found;
    for (int i = 0; i < sz2; i++) {
        int v = l2[i];
        found = false;
        for (int j = 0; j < n; j++) {
            if (l1[j] == v) {
                found = true;
                break;
            }
        }
        if (found == false) l1[n++] = v;
    }
    return n;
}

int initOtherConfig() {
    int ids[1024];
    int nr_id;

    // parse queue config
    if (parseQueueConfig(sk.errstr, sk.queue_config) != OK_CODE) {
        fprintf(stderr, "queue config: %s\n", sk.errstr);
        exit(-1);
    }

    /*
     * collect port id list from port info
     */
    nr_id = 0;
    for (int portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
        port_info_t *pinfo = sk.port_info[portid];
        if (! pinfo) continue;
        ids[nr_id++] = portid;
    }
    sortIntArray(ids, nr_id);
    sk.nr_ports = nr_id;
    sk.port_ids = memdup(ids, nr_id*sizeof(int));

    if (sk.bindaddr_count != sk.nr_ports) {
        fprintf(stderr, "the number of ip address should equal to number of ports.\n");
        exit(-1);
    }

    for (int i = 0; i < sk.nr_ports; ++i) {
        int portid = sk.port_ids[i];
        assert(sk.port_info[portid]);
        sk.port_info[portid]->port_id = (uint8_t)portid;
        if (!str2ipv4(sk.bindaddr[i], &sk.port_info[portid]->ipv4_addr)) {
            fprintf(stderr, "invalid ipv4 address %s\n", sk.bindaddr[i]);
            exit(-1);
        }
    }

    /*
     * collect lcore id list from port info
     */
    nr_id = 0;
    ids[nr_id++] = sk.master_lcore_id;
    for (int i = 0; i < sk.nr_ports; i++) {
        int portid = sk.port_ids[i];
        port_info_t *pinfo = sk.port_info[portid];
        if (! pinfo->lcore_list) continue;
        nr_id = merge_int_list(ids, nr_id, pinfo->lcore_list, pinfo->nr_lcore);
    }
    sortIntArray(ids, nr_id);
    sk.nr_lcore_ids = nr_id;
    sk.lcore_ids = memdup(ids, nr_id*sizeof(int));

    if (construct_lcore_list() == ERR_CODE) {
        fprintf(stderr, "error: lcore list is too long\n");
        exit(-1);
    }
    /*
     * because all function provided by dpdk should be called after EAL has been initialized
     * and when init numa config, we need call rte_lcore_to_socket_id. so we init EAL here,
     */
    init_dpdk_eal();

    initNumaConfig();

    return OK_CODE;
}

int main(int argc, char *argv[]) {
    memset(&sk, 0, sizeof(sk));
    // set lcore_id to invalid id
    for (int i = 0; i < RTE_MAX_LCORE; ++i) {
        sk.lcore_conf[i].lcore_id = RTE_MAX_LCORE + 1;
    }

    struct timeval tv;
    srand(time(NULL)^getpid());
    gettimeofday(&tv,NULL);
    dictSetHashFunctionSeed(tv.tv_sec^tv.tv_usec^getpid());

#ifdef SK_TEST
    if (argc >= 3 && !strcasecmp(argv[1], "test")) {
        initTestDpdkEal();

        if (!strcasecmp(argv[2], "ds")) {
            return dsTest(argc, argv);
        } else if (!strcasecmp(argv[2], "zone_parser")) {
            return zoneParserTest(argc, argv);
        }
        return -1;  /* test not found */
    }
#endif

    getConfigFname(argc, argv);
    initConfigFromTomlFile(sk.configfile);
    if (sk.daemonize) daemonize();
    // configure log as early as possible
    config_log();

    printAsciiLogo();

    initOtherConfig();

    setupSignalHandlers();

    sk.force_quit = false;
    init_dpdk_module();

    if (!sk.only_udp) init_kni_module();

    rcu_register_thread();

    initShuke();

    start_dpdk_threads();

    if (! sk.only_udp) {
        kni_ifconfig_all();

        // wait util all kni virtual interfaces are up
        for (int i = 0; i < 20; i++) {
            sleep(1);
            if (is_all_veth_up()) break;
            else {
                if (i == 20) {
                    LOG_EXIT(USER1, "can't bring all kni virtual interfaces up.");
                }
            }
        }
        LOG_INFO(USER1, "starting dns tcp server.");
        sk.tcp_srv = tcpServerCreate();
        assert(sk.tcp_srv);
    }
    // create pidfile before enter the loop
    if (sk.daemonize) createPidFile();

    aeMain(sk.el);

    if (! sk.only_udp) cleanup_kni_module();

    cleanup_dpdk_module();

    rcu_unregister_thread();
}
