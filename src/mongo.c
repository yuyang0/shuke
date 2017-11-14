//
// Created by yangyu on 17-3-20.
//

#include "shuke.h"
#include "utils.h"

#define RTE_LOGTYPE_MONGO RTE_LOGTYPE_USER1

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
static int prepareColName(char *dotOrigin, char *colName) {
    char *end;
    snprintf(colName, MAX_DOMAIN_LEN, "%s", dotOrigin);
    end = colName + strlen(colName) - 1;
    if (*end == '.') {
        *end = '\0';
    }
    return MONGO_OK;
}

static void RRSetGetCallback(mongoAsyncContext *c, void *r, void *privdata) {
    ((void) c);
    mongoReply *reply = r;
    zoneReloadContext *ctx = privdata;
    char *name, *type, *rdata;
    uint32_t ttl;
    if (reply == NULL) {
        goto error;
    }
    if (ctx->status == TASK_ERROR) {
        goto error;
    }

    LOG_DEBUG(MONGO, "RRSET cb %s %d", ctx->dotOrigin, reply->numberReturned);

    if (reply->numberReturned > 0) {
        if (ctx->new_zn == NULL) ctx->new_zn = zoneCreate(ctx->dotOrigin, sk.master_numa_id);
        if (ctx->psr == NULL) ctx->psr = RRParserCreate("@", 0, ctx->dotOrigin);

        for (int i = 0; i < reply->numberReturned; ++i) {
            bson_t *b = reply->docs[i];
            name = bson_extract_string(b, "name");
            ttl = (uint32_t)bson_extract_int32(b, "ttl");
            type = bson_extract_string(b, "type");
            rdata = bson_extract_string(b, "rdata");
            if (RRParserFeedRdata(ctx->psr, rdata, name, ttl, type, ctx->new_zn) == ERR_CODE) {
                LOG_ERR(MONGO, "parse rdata error %d.", ctx->psr->errstr);
                goto error;
            }
        }
    }
    goto ok;

error:
    ctx->status = TASK_ERROR;
ok:
    if (!reply || reply->cursorID == 0) {
        if (ctx->status == TASK_ERROR) {
            LOG_ERROR(MONGO, "failed to reload zone %s asynchronously.", ctx->dotOrigin);
            if (asyncRereloadZone(ctx) == ERR_CODE) {
                zoneReloadContextDestroy(ctx);
            }
        } else if (ctx->new_zn == NULL) {
            LOG_WARN(MONGO, "zone %s is not in mongodb.", ctx->dotOrigin);
            zoneReloadContextDestroy(ctx);
        } else if (ctx->new_zn->soa == NULL) {
            LOG_ERROR(MONGO, "zone %s must contain a SOA record.", ctx->dotOrigin);
            if (asyncRereloadZone(ctx) == ERR_CODE) {
                zoneReloadContextDestroy(ctx);
            }
        } else {
            LOG_INFO(MONGO, "reload zone %s successfully. ", ctx->dotOrigin);
            replaceZoneAllNumaNodes(ctx->new_zn);
            ctx->new_zn = NULL;
            zoneReloadContextDestroy(ctx);
        }
    }
    return;
}

static void zoneSOAGetCallback(mongoAsyncContext *c, void *r, void *privdata) {
    int errcode;
    char errstr[ERR_STR_LEN];
    unsigned long sn;
    char origin[MAX_DOMAIN_LEN+2];
    mongoReply *reply = r;
    char *type, *rdata;
    zoneReloadContext *ctx = privdata;
    char col_name[MAX_DOMAIN_LEN];

    assert(ctx->zone_exist);

    if (reply == NULL) goto error;
    if (reply->numberReturned == 0) {
        // remove the zone
        LOG_INFO(MONGO, "zone %s is removed.", ctx->dotOrigin);
        dot2lenlabel(ctx->dotOrigin, origin);
        deleteZoneAllNumaNodes(origin);
        zoneReloadContextDestroy(ctx);
        goto ok;
    }
    rdata = bson_extract_string(reply->docs[0], "rdata");
    type = bson_extract_string(reply->docs[0], "type");
    assert(strcasecmp(type, "SOA") == 0);

    if (parseSOASn(errstr, rdata, &sn) != PARSER_OK) {
        LOG_WARN(MONGO, "Error SOA record: %s.", errstr);
        goto error;
    }
    LOG_DEBUG(MONGO, "sn cb: %d %d", sn, ctx->sn);


    if (ctx->sn >= sn) {
        // update zone's ts field
        LOG_INFO(MONGO, "reload zone %s successfully(unchanged).", ctx->dotOrigin);
        dot2lenlabel(ctx->dotOrigin, origin);
        masterRefreshZone(origin);

        zoneReloadContextDestroy(ctx);
        goto ok;
    } else {
        // remove last dot
        prepareColName(ctx->dotOrigin, col_name);

        errcode = mongoAsyncFindAll(c, RRSetGetCallback, ctx, sk.mongo_dbname,
                                    col_name, NULL, NULL, 0);
        if (errcode != MONGO_OK) {
            LOG_ERROR(MONGO, "MONGO ERROR: %s", c->errstr);
            goto error;
        }
    }
    goto ok;
error:
    if (asyncRereloadZone(ctx) == ERR_CODE) {
        zoneReloadContextDestroy(ctx);
    }
ok:
    return;
}

static void reloadAllCallback(mongoAsyncContext *c, void *r, void *privdata) {
    ((void) c); ((void) privdata);
    char dotOrigin[MAX_DOMAIN_LEN];
    char origin[MAX_DOMAIN_LEN+2];
    mongoReply *reply = r;
    char **namev;
    char **p;

    if (reply == NULL) goto error;
    namev = bson_extract_collection_names(reply->docs[0]);
    for (p = namev; *p != NULL; ++p) {
        snprintf(dotOrigin, MAX_DOMAIN_LEN, "%s.", *p);
        if (!isAbsDotDomain(dotOrigin)) {
            LOG_WARN(MONGO, "%s is too long, ignore it.", dotOrigin);
            continue;
        }
        // only reload the zone doesn't exist in zone dict
        dot2lenlabel(dotOrigin, origin);
        if (!ztreeExistZone(sk.zt, origin)) {
            asyncReloadZoneRaw(dotOrigin);
        }
    }
    sk.last_all_reload_ts = sk.unixtime;
    freev((void **)namev);
    return;
error:
    triggerReloadAllZone();
}

static void connectCallback(const mongoAsyncContext *c, int status) {
    if (status != OK_CODE) {
        LOG_ERROR(MONGO, "Failed to connect to mongodb: %s", c->errstr);
        sk.mongo_ctx = NULL;
        return;
    }
    assert(sk.mongo_ctx == c);
    LOG_INFO(MONGO, "mongodb connected..");
}

static void disconnectCallback(const mongoAsyncContext *c, int status) {
    sk.mongo_ctx = NULL;
    if (status != MONGO_OK) {
        LOG_ERROR(MONGO, "Error: %s", c->errstr);
    }
    LOG_WARN(MONGO, "Disconnected...");
    // only reconnect in cron callback in main thread
    return;
}

/*
 * check if mongo async context is connected.
 */
int checkMongo() {
    return (sk.mongo_ctx && mongoAsyncIsConnected(sk.mongo_ctx)) ? OK_CODE: ERR_CODE;
}

/*
 * issue a connection to mongodb
 * pls note: async context is connected only after connectCallback is called sunccessfully
 */
int initMongo() {
    if (sk.mongo_ctx) return OK_CODE;
    long now = sk.unixtime;
    if (now - sk.last_retry_ts < sk.retry_interval) return ERR_CODE;
    sk.last_retry_ts = now;

    mongoAsyncContext *ac = mongoAsyncConnect(sk.mongo_host, sk.mongo_port);
    if (ac->err) {
        LOG_ERROR(MONGO, "Failed to init mongodb: %s", ac->errstr);
        sk.mongo_ctx = NULL;
        return ERR_CODE;
    }
    mongoAeAttach(sk.el, ac);
    mongoAsyncSetConnectCallback(ac,connectCallback);
    mongoAsyncSetDisconnectCallback(ac,disconnectCallback);
    sk.mongo_ctx = ac;
    return OK_CODE;
}

static zone *_mongoGetZone(mongoContext *c, RRParser *psr, char *db, char *col, char *dotOrigin) {
    mongoReply **replies;
    mongoReply *reply;
    uint32_t ttl;
    char *type, *rdata, *name;

    zone *z = zoneCreate(dotOrigin, sk.master_numa_id);

    replies = (mongoReply **)mongoFindAll(c, db, col, NULL, NULL, 0);

    for (int i = 0; replies[i] != NULL; ++i) {
        reply = replies[i];
        for (int j = 0; j < reply->numberReturned; ++j) {
            bson_t *b = reply->docs[j];
            name = bson_extract_string(b, "name");
            ttl = (uint32_t)bson_extract_int32(b, "ttl");
            type = bson_extract_string(b, "type");
            rdata = bson_extract_string(b, "rdata");
            LOG_DEBUG(MONGO, "RR%d: %s, %d, %s, %s", j, name, ttl, type, rdata);
            if (RRParserFeedRdata(psr, rdata, name, ttl, type, z) == ERR_CODE) {
                goto error;
            }
        }
    }
    goto ok;
error:
    if (c->err != MONGO_OK) LOG_ERROR(MONGO, "Mongo Error: %s", c->errstr);
    if (psr->err != PARSER_OK) LOG_ERROR(MONGO, "Parser: %s", psr->errstr);
    zoneDestroy(z);
    z = NULL;
ok:
    for (int i = 0; replies[i] != NULL; ++i) mongoReplyFree(replies[i]);
    free(replies);
    return z;
}

static int _mongoGetAllZone(char *host, int port, char *db) {
    char dotOrigin[MAX_DOMAIN_LEN];
    char **namev = NULL;
    char **p;
    char *col;
    RRParser *psr = RRParserCreate("@", 0, NULL);
    int errcode = OK_CODE;
    mongoContext *c = mongoConnect(host, port);
    if (c == NULL || c->err) {
        if (c) {
            LOG_ERROR(MONGO, "Error: %s\n", c->errstr);
            goto error;
        } else {
            LOG_ERROR(MONGO, "Can't allocate mongo context\n");
            goto error;
        }
    }
    namev = mongoGetCollectionNames(c, db);
    for (p = namev; *p != NULL; ++p) {
        col = *p;
        snprintf(dotOrigin, MAX_DOMAIN_LEN, "%s.", *p);
        if (!isAbsDotDomain(dotOrigin)) {
            LOG_WARN(MONGO, "%s is too long, ignore it.");
            continue;
        }
        RRParserSetDotOrigin(psr, dotOrigin);

        zone *z = _mongoGetZone(c, psr, db, col, dotOrigin);
        if (z == NULL) {
            goto error;
        }
        if (z->soa == NULL) {
            LOG_ERROR(MONGO, "zone %s must contains a SOA record.", z->dotOrigin);
            zoneDestroy(z);
            goto error;
        }
        addZoneAllNumaNodes(z);
    }
    goto ok;
error:
    if (c->err != 0) LOG_ERROR(MONGO, "Mongo Error: %s", c->errstr);
    errcode = ERR_CODE;
ok:
    freev((void **)namev);
    mongoFree(c);
    RRParserDestroy(psr);
    return errcode;
}

int mongoGetAllZone() {
    LOG_INFO(MONGO, "Synchronous get all zones from mongodb.");
    return _mongoGetAllZone(sk.mongo_host, sk.mongo_port, sk.mongo_dbname);
}

int mongoAsyncReloadZone(zoneReloadContext *t) {
    if (sk.mongo_ctx == NULL) return ERR_CODE;
    int errcode;
    int retcode = OK_CODE;
    char col_name[MAX_DOMAIN_LEN];

    // remove last dot
    prepareColName(t->dotOrigin, col_name);

    t->status = TASK_RUNNING;
    LOG_INFO(MONGO, "asynchronous reload zone %s.", t->dotOrigin);

    LOG_DEBUG(MONGO, "async sn: %d.", t->sn);
    if (t->zone_exist) {
        bson_t *q = BCON_NEW("type", BCON_UTF8("SOA"));
        errcode = mongoAsyncFindOne(sk.mongo_ctx, zoneSOAGetCallback, t,
                                    sk.mongo_dbname, col_name, q, NULL);
    } else {
        /*
         * new zone.
         * skip checking sn.
         */
        errcode = mongoAsyncFindAll(sk.mongo_ctx, RRSetGetCallback, t, sk.mongo_dbname,
                                    col_name, NULL, NULL, 0);
    }
    if (errcode != MONGO_OK) {
        LOG_ERROR(MONGO, "MONGO ERROR: %s", sk.mongo_ctx->errstr);
        goto error;
    }
    goto ok;
error:
    if (asyncRereloadZone(t) == ERR_CODE) {
        zoneReloadContextDestroy(t);
    }
    retcode = ERR_CODE;
ok:
    return retcode;
}

int mongoAsyncReloadAllZone() {
    if (sk.mongo_ctx == NULL) return ERR_CODE;
    LOG_INFO(MONGO, "Asynchronous get all zones from mongodb");
    int errcode;
    errcode = mongoAsyncGetCollectionNames(sk.mongo_ctx, reloadAllCallback, NULL, sk.mongo_dbname);
    if (errcode != MONGO_OK) {
        LOG_ERROR(MONGO, "Mongo ERROR: %s", sk.mongo_ctx->errstr);
        return ERR_CODE;
    }
    // we need set last_all_reload_ts here, otherwise it will trigger many reloadAll task in cron callback
    sk.last_all_reload_ts = sk.unixtime;
    return OK_CODE;
}
