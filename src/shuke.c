//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-05
//
#include <sys/time.h>
#include <getopt.h>
#include <arpa/inet.h>

#include "dpdk_module.h"

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
        zone *this = container_of(*new, zone, rbnode);
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
    zoneDictRLock(sk.zd);
    zone *z = zoneDictFetchVal(sk.zd, origin);
    zoneDictRUnlock(sk.zd);

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
    zoneDict *zd = sk.zd;
    z->refresh_ts = sk.unixtime + z->refresh;
    zoneUpdateRoundRabinInfo(z);

    replaceZoneOtherNuma(z);

    int err = 1;
    zone *old_z;
    struct cds_lfht *ht = zd->ht;
    struct cds_lfht_node *ht_node;
    unsigned int hash = zoneDictHash(z->origin, z->originLen);
    zoneDictWLock(zd);
    ht_node = cds_lfht_add_replace(ht, hash, zoneDictHtMatch, z->origin,
                                   &z->htnode);
    if (ht_node) {
        old_z = caa_container_of(ht_node, zone, htnode);
        rbtreeDeleteZone(old_z);
        call_rcu(&old_z->rcu_head, zoneDictFreeCallback);
        err = 0;
    }
    zoneDictWUnlock(zd);
    rbtreeInsertZone(z);
    return err;
}

int addZoneAllNumaNodes(zone *z) {
    z->refresh_ts = sk.unixtime + z->refresh;
    zoneUpdateRoundRabinInfo(z);

    addZoneOtherNuma(z);

    int err = zoneDictAdd(sk.zd, z);
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
    zoneDict *zd = sk.zd;

    // delete the zone on non-master numa node
    deleteZoneOtherNuma(origin);

    struct cds_lfht *ht = zd->ht;	/* Hash table */
    int ret = 0;
    struct cds_lfht_iter iter;	/* For iteration on hash table */
    struct cds_lfht_node *ht_node;
    unsigned int hash = zoneDictHash(origin, strlen(origin));

    zoneDictWLock(zd);
    cds_lfht_lookup(ht, hash, zoneDictHtMatch, origin, &iter);
    ht_node = cds_lfht_iter_get_node(&iter);
    if (ht_node) {
        ret = cds_lfht_del(ht, ht_node);
        if (ret == 0) {
            zone *del_z = caa_container_of(ht_node, zone, htnode);
            rbtreeDeleteZone(del_z);
            call_rcu(&del_z->rcu_head, zoneDictFreeCallback);
        }
    }
    zoneDictWUnlock(zd);
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

    zoneDictRLock(sk.zd);
    old_zn = zoneDictFetchVal(sk.zd, origin);

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
    zoneDictRUnlock(sk.zd);
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
        zoneDictDelete(node->zd, origin);
    }
}

void replaceZoneOtherNuma(zone *z) {
    for (int i = 0; i < sk.nr_numa_id; ++i) {
        int numa_id = sk.numa_ids[i];
        numaNode_t *node = sk.nodes[numa_id];
        if (numa_id == sk.master_numa_id) continue;
        zone *new_z = zoneCopy(z, numa_id);
        zoneUpdateRoundRabinInfo(new_z);

        zoneDictReplace(node->zd, new_z);
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

        err = zoneDictAdd(node->zd, new_z);
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
        if (loadZoneFromFile(sk.master_numa_id, fname, &z) == DS_ERR) {
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
        if (loadZoneFromFile(sk.master_numa_id, fname, &z) == DS_ERR) {
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
    // current start position in response buffer.
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
                return ERR_CODE;
            }
        }
        RRSet *ar_aaaa = zoneFetchTypeVal(ar_z, name, DNS_TYPE_AAAA);
        if (ar_aaaa) {
            hdr.nArRR += ar_aaaa->num;
            errcode = RRSetCompressPack(ctx, ar_aaaa, offset, NULL, NULL, 0, NULL, NULL, 0);
            if (errcode == DS_ERR) {
                return ERR_CODE;
            }
        }
    }
    // update the header. don't update `cur` in ctx
    dnsHeader_dump(&hdr, ctx->resp, DNS_HDR_SIZE);
    return OK_CODE;
}

int dumpDnsError(struct context *ctx, int err) {
    dnsHeader_t hdr = {ctx->hdr.xid, 0, 1, 0, 0, 0};

    SET_QR_R(hdr.flag);
    if (GET_RD(ctx->hdr.flag)) SET_RD(hdr.flag);
    SET_ERROR(hdr.flag, err);
    if (err == DNS_RCODE_NXDOMAIN) SET_AA(hdr.flag);

    // a little trick, overwrite the dns header, don't update `cur` in ctx
    dnsHeader_dump(&hdr, ctx->resp, ctx->totallen);
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
        LOG_DEBUG(USER1, "receive bad dns query message(xid: %d, qd: %d, an: %d, ns: %d, ar: %d), drop it",
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
    zoneDictRLock(node->zd);
    z = zoneDictGetZone(node->zd, name);
    ctx->z = z;

    if (z == NULL) {
        // zone is not managed by this server
        LOG_DEBUG(USER1, "zone is NULL, name: %s", ctx->name);
        dumpDnsRefusedErr(ctx);
        //return ctx->cur;
        goto end;
    }

    dv = zoneFetchValueAbs(z, ctx->name, ctx->nameLen);
    if (dv == NULL) {
        dumpDnsNameErr(ctx);
        goto end;
    }
    if (dumpDnsResp(ctx, dv, z) == OK_CODE) {
        goto end;
    }
end:
    zoneDictRUnlock(node->zd);
    return ctx->cur;
}

int processUDPDnsQuery(char *buf, size_t sz, char *resp, size_t respLen, char *src_addr, uint16_t src_port, bool is_ipv4,
                       numaNode_t *node, int lcore_id)
{
    struct context ctx;
    ctx.node = node;
    ctx.lcore_id = lcore_id;
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
    // resetDname(&(ctx.dname));

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
    ctx.resp = resp;
    ctx.totallen = respLen;
    ctx.cur = 0;

    status = _getDnsResponse(buf, sz, &ctx);

    if (status != ERR_CODE && sk.query_log_fp) {
        logQuery(&ctx, conn->cip, conn->cport, true);
    }

    snpack(ctx.resp, DNS_HDR_SIZE, respLen, "m>hh", ctx.name, ctx.nameLen+1, ctx.qType, ctx.qClass);
    tcpConnAppendDnsResponse(conn, ctx.resp, ctx.cur);

    // resetDname(&(ctx.dname));
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

#ifndef ONLY_UDP
    if (! sk.only_udp) {
        // run tcp dns server cron
        tcpServerCron(el, id, (void *)sk.tcp_srv);
    }
#endif

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

    sk.only_udp = false;
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
    sk.queue_config = getStrVal(cbuf, "queue_config", NULL);
    CHECK_CONFIG("queue_config", sk.queue_config != NULL,
                 "Config Error: queue_config can't be empty");

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

    conf_err = getBoolVal(sk.errstr, cbuf, "only_udp", &sk.only_udp);
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
    sk.logfile = getStrVal(cbuf, "logfile", NULL);

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
        LOG_FATAL(USER1, "invalid data store config %s", sk.data_store);
    }

    sk.rbroot = RB_ROOT;
    // create zoneDict for all numa nodes
    for (int i = 0; i < sk.nr_numa_id; ++i) {
        int numa_id = sk.numa_ids[i];
        sk.nodes[numa_id]->zd = zoneDictCreate(numa_id);
    }
    assert(master_node->zd);
    sk.zd = master_node->zd;

    long long reload_all_start = mstime();
    if (sk.syncGetAllZone() == ERR_CODE) {
        LOG_FATAL(USER1, "can't load all zone data from %s", sk.data_store);
    }
    sk.zone_load_time = mstime() - reload_all_start;
    LOG_INFO(USER1, "loading all zone from %s to memory cost %lld milliseconds.", sk.data_store, sk.zone_load_time);
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

#ifndef ONLY_UDP
    for (int i = 0; i < sk.nr_kni_tx_lcore_id; ++i) {
        if (offset >= 4096) return ERR_CODE;
        n = snprintf(buffer+offset, 4096-offset, ",%d", sk.kni_tx_lcore_ids[i]);
        offset += n;
    }
#endif

    sk.total_lcore_list = strdup(buffer);
    return OK_CODE;
}

static int hexchar_to_int(char c) {
    char buf[2] = {c, 0};
    return (int)strtol(buf, NULL, 16);
}

static int parseList(char *errstr, char *s, int arr[], int *nrEle) {
    char *sArr[1024];
    int n = 1024;
    int max = *nrEle;
    char *endptr;
    long int v;

    *nrEle = 0;

    while(*s == ' ') s++;
    if (*s == '[') {
        if (strchr(s, ']') == NULL) {
            snprintf(errstr, ERR_STR_LEN, "need ] near %s", s);
            goto invalid;
        }
        tokenize(s, sArr, &n, " ,");
        for (int i = 0; i < n; i++) {
            if (*nrEle >= max) {
                snprintf(errstr, ERR_STR_LEN, "array size is not enough");
                goto invalid;
            }
            char *subp = strchr(sArr[i], '-');
            if (subp == NULL) {
                v = strtol(sArr[i], &endptr, 10);
                arr[(*nrEle)++] = (int)v;
            } else {
                *subp++ = 0;
                long int lbound = strtol(sArr[i], &endptr, 10);
                if (endptr != NULL) {
                    goto invalid;
                }
                long int hbound = strtol(subp, &endptr, 10);
                if (endptr != NULL) {
                    goto invalid;
                }
                for (v=lbound; v<=hbound; ++v) {
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
        if (endptr != NULL) {
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

char *parseQueueConfigPart(char *errstr, char *s, int cores[], int *nrCores,
                     int ports[], int *nrPorts) {
    char buf[4096] = {0};
    char *cStart, *pStart;
    char *end = strchr(s, ';');
    if (end == NULL) end = s + strlen(s);
    if (end - s >= 4096) goto invalid;
    memcpy(buf, s, end-s);
    cStart = buf;
    pStart = strchr(buf, '.');
    if (pStart == NULL) {
        snprintf(errstr, ERR_STR_LEN, "syntax error %s", buf);
        goto invalid;
    }
    *pStart++ = 0;
    if (parseList(errstr, cStart, cores, nrCores) < 0) {
        goto invalid;
    }
    if (parseList(errstr, pStart, ports, nrPorts) < 0) {
        goto invalid;
    }
    return end+1;
invalid:
    return NULL;
}

int parseQueueConfig(char *errstr, char *s) {
    char *end = s + strlen(s);
    char *next = s;
    int cores[1024];
    int ports[1024];
    int nrCores = 1024;
    int nrPorts = 1024;
    while (next < end) {
        next = parseQueueConfigPart(errstr, next, cores, &nrCores,
                                    ports, &nrPorts);
        if (next == NULL) {
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
            port_info_t *pinfo = sk.port_info[port_id];
            if (!pinfo) {
                snprintf(errstr, ERR_STR_LEN, "queue config: port %d is disabled.", port_id);
                goto invalid;
            }
            if (!pinfo->lcore_list) {
                snprintf(errstr, ERR_STR_LEN, "duplicate rx queue cofnig for port %d.", port_id);
                goto invalid;
            }
            pinfo->lcore_list = memdup(cores, sizeof(int)*nrCores);
            pinfo->nr_lcore = nrCores;
            for (int j = 0; j < nrCores; ++j) {
                int lcore_id = cores[j];
                if (lcore_id < 0 || lcore_id >= RTE_MAX_LCORE) {
                    snprintf(errstr, ERR_STR_LEN, "lcore should in 0-%d, but gives %d.", RTE_MAX_LCORE, lcore_id);
                    goto invalid;
                }
                if (lcore_id == sk.master_lcore_id) {
                    snprintf(errstr, ERR_STR_LEN, "queue config should not contain master lcore id.");
                    goto invalid;
                }
                lcore_conf_t *qconf = &sk.lcore_conf[lcore_id];
                if (qconf->lcore_id >= RTE_MAX_LCORE) {
                    snprintf(errstr, ERR_STR_LEN, "queue config: lcore %d is not enabled.", lcore_id);
                    goto invalid;
                }
                qconf->port_id_list[qconf->nr_ports] = port_id;
                qconf->queue_id_list[qconf->nr_ports] = j;
                qconf->nr_ports++;
            }
        }
    }
    return OK_CODE;
invalid:
    return ERR_CODE;
}

#ifndef ONLY_UDP
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
        if (!sk.port_info[portid]) {
            snprintf(sk.errstr, ERR_STR_LEN, "port %lu is not enabled.", portid);
            return ERR_CODE;
        }
        if (found == false) ids[nr_id++] = lcore_id;
        if (sk.port_info[portid]->kni_lcore_tx >= 0) {
            snprintf(sk.errstr, ERR_STR_LEN, "duplicate config for port %lu.", portid);
            return ERR_CODE;
        }
        sk.port_info[portid]->kni_lcore_tx = lcore_id;
        ++nb_params;
    }
    // check if every port contains kni_lcore_tx
    for (int i = 0; i < sk.nr_ports; ++i) {
        int portid = sk.port_ids[i];
        if (sk.port_info[portid]->kni_lcore_tx < 0) {
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
        if (!sk.port_info[portid]) {
            snprintf(sk.errstr, ERR_STR_LEN, "port %lu is not enabled.", portid);
            return ERR_CODE;
        }
        if (sk.port_info[portid]->kni_lcore_k >= 0) {
            snprintf(sk.errstr, ERR_STR_LEN, "duplicate config for port %lu.", portid);
            return ERR_CODE;
        }
        sk.port_info[portid]->kni_lcore_k = lcore_id;
        ++nb_params;
    }
    // check if every port contains kni_lcore_k
    for (int i = 0; i < sk.nr_ports; ++i) {
        int portid = sk.port_ids[i];
        if (sk.port_info[portid]->kni_lcore_k < 0) {
            snprintf(sk.errstr, ERR_STR_LEN, "port %d doesn't have kni kernel lcore config.", portid);
            return ERR_CODE;
        }
    }
    return OK_CODE;
}

int initKniConfig() {
    // initialize kni config
    if (sk.bindaddr_count != sk.nr_ports) {
        fprintf(stderr, "the number of ip address should equal to number of ports.\n");
        exit(-1);
    }
    for (int i = 0; i < sk.nr_ports; ++i) {
        int portid = sk.port_ids[i];
        assert(sk.port_info[portid]);
        snprintf(sk.port_info[portid]->veth_name, RTE_KNI_NAMESIZE, "vEth%u", portid);
        sk.port_info[portid]->kni_lcore_tx = -1;
        sk.port_info[portid]->kni_lcore_k = -1;
        sk.port_info[portid]->kni_tx_queue_id = (uint16_t )(sk.nr_lcore_ids - 1);
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
#endif

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

int initOtherConfig() {
    int ids[1024];
    int nr_id;

    // parse coremask
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

    // parse all port id
    nr_id = 1024;
    if (get_port_ids(ids, &nr_id) == ERR_CODE) {
        fprintf(stderr, "error: the number of port is bigger than %d.\n", nr_id);
        abort();
    }
    sk.port_ids = memdup(ids, nr_id * sizeof(int));
    sk.nr_ports = nr_id;

    for (int i = 0; i < sk.nr_ports; ++i) {
        int portid = sk.port_ids[i];
        assert(sk.port_info[portid] == NULL);
        sk.port_info[portid] = calloc(1, sizeof(port_info_t));
        assert(sk.port_info[portid]);
        sk.port_info[portid]->port_id = (uint8_t)portid;
    }

#ifndef ONLY_UDP
    initKniConfig();
#endif

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

#ifndef ONLY_UDP
    // all kni tx lcores should stay in one socket
    unsigned kni_socket_id = rte_lcore_to_socket_id((unsigned) sk.kni_tx_lcore_ids[0]);
    for (int i = 0; i < sk.nr_kni_tx_lcore_id; ++i) {
        if (kni_socket_id != rte_lcore_to_socket_id((unsigned) sk.kni_tx_lcore_ids[i])) {
            fprintf(stderr, "all kni tx lcores should stay in one socket");
            exit(-1);
        }
    }
#endif
    // parse queue config
    if (parseQueueConfig(sk.errstr, sk.queue_config) != OK_CODE) {
        fprintf(stderr, "queue config: %s\n", sk.errstr);
        exit(-1);
    }

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

    initConfigFromFile(argc, argv);
    if (sk.daemonize) daemonize();
    if (sk.daemonize) createPidFile();
    // configure log as early as possible
    config_log();

    printAsciiLogo();

    initOtherConfig();

    setupSignalHandlers();

    sk.force_quit = false;
    initDpdkModule();

#ifndef ONLY_UDP
    if (!sk.only_udp) init_kni_module();
#endif

    rcu_register_thread();

    initShuke();

    startDpdkThreads();

#ifndef ONLY_UDP
    if (! sk.only_udp) {
        start_kni_tx_threads();
        kni_ifconfig_all();

        sleep(4);
        LOG_INFO(USER1, "starting dns tcp server.");
        sk.tcp_srv = tcpServerCreate();
        assert(sk.tcp_srv);
    }
#endif

    aeMain(sk.el);

#ifndef ONLY_UDP
    if (! sk.only_udp) cleanup_kni_module();
#endif

    cleanupDpdkModule();

    rcu_unregister_thread();
}
