//
// Created by yangyu on 17-3-20.
//

#include <assert.h>
#include "shuke.h"
#include "utils.h"

/* ======================= himongo ae.c adapters =============================
 * Note: this implementation is taken from himongo/adapters/ae.h, however
 * we have our modified copy for Sentinel in order to use our allocator
 * and to have full control over how the adapter works. */
typedef struct mongoAeEvents {
    mongoAsyncContext *context;
    aeEventLoop *loop;
    int fd;
    int reading, writing;
} mongoAeEvents;

static void mongoAeReadEvent(aeEventLoop *el, int fd, void *privdata, int mask) {
    ((void)el); ((void)fd); ((void)mask);

    mongoAeEvents *e = (mongoAeEvents*)privdata;
    mongoAsyncHandleRead(e->context);
}

static void mongoAeWriteEvent(aeEventLoop *el, int fd, void *privdata, int mask) {
    ((void)el); ((void)fd); ((void)mask);

    mongoAeEvents *e = (mongoAeEvents*)privdata;
    mongoAsyncHandleWrite(e->context);
}

static void mongoAeAddRead(void *privdata) {
    mongoAeEvents *e = (mongoAeEvents*)privdata;
    aeEventLoop *loop = e->loop;
    if (!e->reading) {
        e->reading = 1;
        aeCreateFileEvent(loop,e->fd,AE_READABLE,mongoAeReadEvent,e);
    }
}

static void mongoAeDelRead(void *privdata) {
    mongoAeEvents *e = (mongoAeEvents*)privdata;
    aeEventLoop *loop = e->loop;
    if (e->reading) {
        e->reading = 0;
        aeDeleteFileEvent(loop,e->fd,AE_READABLE);
    }
}

static void mongoAeAddWrite(void *privdata) {
    mongoAeEvents *e = (mongoAeEvents*)privdata;
    aeEventLoop *loop = e->loop;
    if (!e->writing) {
        e->writing = 1;
        aeCreateFileEvent(loop,e->fd,AE_WRITABLE,mongoAeWriteEvent,e);
    }
}

static void mongoAeDelWrite(void *privdata) {
    mongoAeEvents *e = (mongoAeEvents*)privdata;
    aeEventLoop *loop = e->loop;
    if (e->writing) {
        e->writing = 0;
        aeDeleteFileEvent(loop,e->fd,AE_WRITABLE);
    }
}

static void mongoAeCleanup(void *privdata) {
    mongoAeEvents *e = (mongoAeEvents*)privdata;
    mongoAeDelRead(privdata);
    mongoAeDelWrite(privdata);
    free(e);
}

static int mongoAeAttach(aeEventLoop *loop, mongoAsyncContext *ac) {
    mongoContext *c = &(ac->c);
    mongoAeEvents *e;

    /* Nothing should be attached when something is already attached */
    if (ac->ev.data != NULL)
        return MONGO_ERR;

    /* Create container for context and r/w events */
    e = (mongoAeEvents*)malloc(sizeof(*e));
    e->context = ac;
    e->loop = loop;
    e->fd = c->fd;
    e->reading = e->writing = 0;

    /* Register functions to start/stop listening for events */
    ac->ev.addRead = mongoAeAddRead;
    ac->ev.delRead = mongoAeDelRead;
    ac->ev.addWrite = mongoAeAddWrite;
    ac->ev.delWrite = mongoAeDelWrite;
    ac->ev.cleanup = mongoAeCleanup;
    ac->ev.data = e;

    return MONGO_OK;
}

/*----------------------------------------------
 *     mongo fetcher implementation
 *---------------------------------------------*/
static void RRSetGetCallback(mongoAsyncContext *c, void *r, void *privdata) {
    ((void) c);
    char *name, *type, *rdata;
    uint32_t ttl;
    zoneReloadTask *t = privdata;
    if (t->status == TASK_ERROR) {
        goto error;
    }
    if (t->new_zn == NULL) t->new_zn = zoneCreate(t->dotOrigin);
    zone *z = t->new_zn;

    mongoReply *reply = r;
    if (reply == NULL) {
        goto error;
    }

    LOG_DEBUG(USER1, "RRSET cb %s %d", t->dotOrigin, reply->numberReturned);

    if (t->psr == NULL) t->psr = RRParserCreate("@", 0, t->dotOrigin);
    for (int i = 0; i < reply->numberReturned; ++i) {
        bson_t *b = reply->docs[i];
        name = bson_extract_string(b, "name");
        ttl = (uint32_t)bson_extract_int32(b, "ttl");
        type = bson_extract_string(b, "type");
        rdata = bson_extract_string(b, "rdata");
        if (RRParserFeedRdata(t->psr, rdata, name, ttl, type, z) == DS_ERR) {
            goto error;
        }
    }
    goto ok;

error:
    t->status = TASK_ERROR;
ok:
    if (!reply || reply->cursorID == 0) {
        if (t->status == TASK_ERROR) {
            LOG_ERROR(USER1, "failed to reload zone %s asynchronously.", t->dotOrigin);
            zoneReloadTaskReset(t);
            enqueueZoneReloadTask(t);
        } else if (t->new_zn->soa == NULL) {
            LOG_ERROR(USER1, "zone %s must contain a SOA record.", t->dotOrigin);
            zoneReloadTaskReset(t);
            enqueueZoneReloadTask(t);
        } else {
            LOG_INFO(USER1, "reload zone %s successfully. ", t->dotOrigin);
            zoneDictReplace(CUR_NODE->zd, t->new_zn);
            t->new_zn = NULL;
            zoneReloadTaskDestroy(t);
        }
    }
    return;
}

static void zoneSOAGetCallback(mongoAsyncContext *c, void *r, void *privdata) {
    int errcode;
    char errstr[ERR_STR_LEN];
    unsigned long sn;
    char origin[MAX_DOMAIN_LEN+2];
    time_t now = sk.unixtime;
    mongoReply *reply = r;
    char *type, *rdata;

    zoneReloadTask *t = privdata;

    if (reply == NULL) goto error;
    if (reply->numberReturned == 0) {
        // remove the zone
        dot2lenlabel(t->dotOrigin, origin);
        zoneDictDelete(CUR_NODE->zd, origin);
        zfree(t->dotOrigin);
        zfree(t);
        goto ok;
    }
    rdata = bson_extract_string(reply->docs[0], "rdata");
    type = bson_extract_string(reply->docs[0], "type");
    assert(strcasecmp(type, "SOA") == 0);

    if (parseSOASn(errstr, rdata, &sn) != PARSER_OK) {
        LOG_WARN(USER1, "Error SOA record: %s.", errstr);
        goto error;
    }
    LOG_DEBUG(USER1, "sn cb: %d %d", sn, t->sn);

    /*
     * negative `ts` means this zone is not in current memory cache,
     * so we don't need to validate sn, just fetch all the zone data.
     */
    if (t->sn >= sn && t->ts >= 0) {
        // update zone's ts field
        dot2lenlabel(t->dotOrigin, origin);

        zone *z = zoneDictFetchVal(CUR_NODE->zd, origin);
        rte_atomic64_set(&(z->ts), (int64_t)now);
        zoneDecRef(z);

        zoneReloadTaskDestroy(t);
        goto ok;
    } else {
        if (t->new_zn == NULL) t->new_zn = zoneCreate(t->dotOrigin);
        if (t->psr == NULL) t->psr = RRParserCreate("@", 0, t->dotOrigin);
        // if (RRParserFeed(t->psr, reply->str, "@", t->new_zn) == DS_ERR) {
        //     goto error;
        // }

        errcode = mongoAsyncFindAll(c, RRSetGetCallback, t, sk.mongo_dbname,
                                    t->dotOrigin, NULL, NULL, 0);
        if (errcode != MONGO_OK) {
            LOG_ERROR(USER1, "MONGO ERROR: %s", c->errstr);
            goto error;
        }
    }
    goto ok;
error:
    zoneReloadTaskReset(t);
    enqueueZoneReloadTask(t);
ok:
    return;
}

static void reloadAllCallback(mongoAsyncContext *c, void *r, void *privdata) {
    ((void) c); ((void) privdata);
    char dotOrigin[MAX_DOMAIN_LEN];
    mongoReply *reply = r;
    char **namev;
    char **p;

    if (reply == NULL) return;
    namev = bson_extract_collection_names(reply->docs[0]);
    for (p = namev; *p != NULL; ++p) {
        snprintf(dotOrigin, MAX_DOMAIN_LEN, "%s.", *p);
        if (!isAbsDotDomain(dotOrigin)) {
            LOG_WARN(USER1, "%s is too long, ignore it.", dotOrigin);
            continue;
        }
        enqueueZoneReloadTaskRaw(dotOrigin, 0, -1);
    }
    sk.last_all_reload_ts = sk.unixtime;
    freev((void **)namev);
    return;
}

static void connectCallback(const mongoAsyncContext *c, int status) {
    if (status != OK_CODE) {
        LOG_ERROR(USER1, "Failed to connect to redis: %s", c->errstr);
        sk.mongo_ctx = NULL;
        return;
    }
    sk.mongo_ctx = (mongoAsyncContext *) c;
    LOG_INFO(USER1, "redis connected..");
}

static void disconnectCallback(const mongoAsyncContext *c, int status) {
    sk.mongo_ctx = NULL;
    if (status != MONGO_OK) {
        LOG_ERROR(USER1, "Redis in disconnected state: %s", c->errstr);
        // do reconnect
        initMongo();
        return;
    }
    LOG_WARN(USER1, "Disconnected...");
}

int checkMongo() {
    return sk.mongo_ctx == NULL? ERR_CODE: OK_CODE;
}

int initMongo() {
    if (sk.mongo_ctx) return OK_CODE;
    long now = sk.unixtime;
    if (now - sk.last_redis_retry_ts < sk.redis_retry_interval) return ERR_CODE;
    sk.last_redis_retry_ts = now;

    mongoAsyncContext *ac = mongoAsyncConnect(sk.mongo_host, sk.mongo_port);
    if (ac->err) {
        LOG_ERROR(USER1, "Failed to init mongodb: %s", ac->errstr);
        sk.mongo_ctx = NULL;
        return ERR_CODE;
    }
    mongoAeAttach(sk.el, ac);
    mongoAsyncSetConnectCallback(ac,connectCallback);
    mongoAsyncSetDisconnectCallback(ac,disconnectCallback);
    return OK_CODE;
}

static zone *_mongoGetZone(mongoContext *c, RRParser *psr, char *db, char *col, char *dotOrigin) {
    mongoReply **replies;
    mongoReply *reply;
    uint32_t ttl;
    char *type, *rdata, *name;

    zone *z = zoneCreate(dotOrigin);

    replies = mongoFindAll(c, db, col, NULL, NULL, 0);

    for (int i = 0; replies[i] != NULL; ++i) {
        reply = replies[i];
        for (int j = 0; j < reply->numberReturned; ++j) {
            bson_t *b = reply->docs[j];
            name = bson_extract_string(b, "name");
            ttl = (uint32_t)bson_extract_int32(b, "ttl");
            type = bson_extract_string(b, "type");
            rdata = bson_extract_string(b, "rdata");
            LOG_DEBUG(USER1, "RR%d: %s, %d, %s, %s", j, name, ttl, type, rdata);
            if (RRParserFeedRdata(psr, rdata, name, ttl, type, z) == DS_ERR) {
                goto error;
            }
        }
    }
    goto ok;
error:
    if (c->err != MONGO_OK) LOG_ERROR(USER1, "Mongo Error: %s", c->errstr);
    if (psr->err != PARSER_OK) LOG_ERROR(USER1, "Parser: %s", psr->errstr);
    zoneDestroy(z);
    z = NULL;
ok:
    for (int i = 0; replies[i] != NULL; ++i) mongoReplyFree(replies[i]);
    free(replies);
    return z;
}

static int _mongoGetAllZone(zoneDict *zd, char *host, int port, char *db) {
    char dotOrigin[MAX_DOMAIN_LEN];
    char **namev = NULL;
    char **p;
    char *col;
    RRParser *psr = RRParserCreate("@", 0, NULL);
    int errcode = OK_CODE;
    mongoContext *c = mongoConnect(host, port);
    if (c == NULL || c->err) {
        if (c) {
            LOG_ERROR(USER1, "Error: %s\n", c->errstr);
            goto error;
        } else {
            LOG_ERROR(USER1, "Can't allocate mongo context\n");
            goto error;
        }
    }
    namev = mongoGetCollectionNames(c, db);
    for (p = namev; *p != NULL; ++p) {
        col = *p;
        snprintf(dotOrigin, MAX_DOMAIN_LEN, "%s.", *p);
        if (!isAbsDotDomain(dotOrigin)) {
            LOG_WARN(USER1, "%s is too long, ignore it.");
            continue;
        }
        RRParserSetDotOrigin(psr, dotOrigin);

        zone *z = _mongoGetZone(c, psr, db, col, dotOrigin);
        if (z->soa == NULL) {
            LOG_ERROR(USER1, "zone %s must contains a SOA record.", z->dotOrigin);
            zoneDestroy(z);
            goto error;
        }
        zoneDictReplace(zd, z);
    }
    goto ok;
error:
    if (c->err != 0) LOG_ERROR(USER1, "Mongo Error: %s", c->errstr);
    errcode = ERR_CODE;
ok:
    freev((void **)namev);
    mongoFree(c);
    RRParserDestroy(psr);
    return errcode;
}

int mongoGetAllZone() {
    LOG_INFO(USER1, "Synchronous get all zones from mongodb.");
    return _mongoGetAllZone(CUR_NODE->zd, sk.mongo_host, sk.mongo_port, sk.mongo_dbname);
}

int mongoAsyncReloadZone(zoneReloadTask *t) {
    int errcode;
    int retcode = OK_CODE;

    t->status = TASK_RUNNING;
    LOG_INFO(USER1, "asynchronous reload zone %s.", t->dotOrigin);

    LOG_DEBUG(USER1, "async sn: %d, ts: %d", t->sn, t->ts);
    bson_t *q = BCON_NEW("type", BCON_UTF8("SOA"));
    errcode = mongoAsyncFindOne(sk.mongo_ctx, zoneSOAGetCallback, t,
                                sk.mongo_dbname, t->dotOrigin, q, NULL);
    if (errcode != MONGO_OK) {
        LOG_ERROR(USER1, "MONGO ERROR: %s", sk.mongo_ctx->errstr);
        goto error;
    }
    goto ok;
error:
    zoneReloadTaskReset(t);
    enqueueZoneReloadTask(t);
    retcode = ERR_CODE;
ok:
    return retcode;
}

int mongoAsyncReloadAllZone() {
    LOG_INFO(USER1, "Asynchronous get all zones from mongodb");
    int errcode;
    errcode = mongoAsyncGetCollectionNames(sk.mongo_ctx, reloadAllCallback, NULL, sk.mongo_dbname);
    if (errcode != MONGO_OK) {
        LOG_ERROR(USER1, "Mongo ERROR: %s", sk.mongo_ctx->errstr);
        return ERR_CODE;
    }
    sk.last_all_reload_ts = sk.unixtime;
    return OK_CODE;
}

#if defined(SK_TEST)
int mongoTest(int argc, char *argv[]) {
    ((void) argc); ((void) argv);
    zoneDict *zd = zoneDictCreate();

    _mongoGetAllZone(zd, "127.0.0.1", 27017, "zone");

    sds s = zoneDictToStr(zd);
    printf("%s\n", s);
    sdsfree(s);

    zoneDict *copy_zd = zoneDictCopy(zd);
    zoneDictDestroy(zd);
    s = zoneDictToStr(copy_zd);

    printf("\n\nCOPY ZD:\n%s\n", s);
    sdsfree(s);
    return 0;
}
#endif
