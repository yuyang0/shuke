//
// Created by Yu Yang on 2017-01-12
//
#include <assert.h>

#include "shuke.h"

static void tcpReadHandler(struct aeEventLoop *el, int fd, void *privdata, int mask);
static void tcpAcceptHandler(struct aeEventLoop *el, int fd, void *privateData, int mask);
static void tcpWriteHandler(struct aeEventLoop *el, int fd, void *privdata, int mask);
static int tcpBindAddrs(tcpServer *srv);
void tcpConnDestroy(tcpConn *conn);

int tcpServerCron(struct aeEventLoop *el, long long id, void *clientData) {
    UNUSED2(el, id);
    tcpServer *srv = clientData;

    struct list_head *pos, *temp;

    // clear useless tcp connections
    list_for_each_safe(pos, temp, &(srv->tcp_head)) {
        tcpConn *c = list_entry(pos, tcpConn, node);
        if (sk.unixtime - c->lastActiveTs < sk.tcp_idle_timeout) break;

        LOG_INFO(USER1, "tcp connection is idle more than %ds, close it.", sk.tcp_idle_timeout);
        tcpConnDestroy(c);
    }
    // check if needs to stop the event loop
    if (sk.force_quit) {
        // remove udp fdInfo list.
        if (list_empty(&(srv->tcp_head))) {
            aeStop(srv->el);
        }
    }
    return TIME_INTERVAL;
}

tcpServer *tcpServerCreate() {
    tcpServer *srv = zcalloc(sizeof(*srv));
    srv->el = sk.el;

    INIT_LIST_HEAD(&(srv->tcp_head));
    if (tcpBindAddrs(srv) != OK_CODE) {
        zfree(srv);
        return NULL;
    }
    int j;
    for (j = 0; j < srv->ipfd_count; ++j) {
        if (aeCreateFileEvent(srv->el, srv->ipfd[j], AE_READABLE, tcpAcceptHandler, srv) == AE_ERR) {
            LOG_ERROR(USER1, "Can't create file event for listen socket %d", srv->ipfd[j]);
            return NULL;
        }
    }
    return srv;
}

void tcpContextDestroy(struct tcpContext *ctx) {
    zfree(ctx);
}

void tcpConnAppendDnsResponse(tcpConn *conn, char *resp, size_t respLen) {
    struct tcpContext *ctx = zcalloc(sizeof(*ctx) + respLen + 2);
    dump16be((uint16_t )respLen, ctx->reply);
    memcpy(ctx->reply+2, resp, respLen);
    ctx->wsize = respLen + 2;
    ctx->sock = conn;

    aeEventLoop *el = conn->el;
    int fd = conn->fd;
    struct tcpContext **head = &(conn->whead);
    struct tcpContext **tail = &(conn->wtail);
    aeFileProc *cb = tcpWriteHandler;

    LOG_DEBUG(USER1, "append context(%d) to write list", ctx->wsize);

    if (*head == NULL) {
        if (aeCreateFileEvent(el, fd, AE_WRITABLE, cb, conn) == AE_ERR) {
            LOG_ERROR(USER1, "Can't add write event callback for %d: %s", fd, strerror(errno));
            tcpContextDestroy(ctx);
            return;
        }
    }
    // append ctx to the end of context list
    if(*head == NULL) *head = ctx;
    if (*tail != NULL) (*tail)->next = ctx;
    *tail = ctx;
}

tcpConn *tcpConnCreate(int fd, tcpServer *srv) {
    tcpConn *conn = zcalloc(sizeof(*conn));
    conn->fd = fd;
    conn->state = CONN_READ_LEN;
    conn->data = conn->buf;
    conn->srv = srv;
    conn->el = srv->el;
    conn->lastActiveTs = sk.unixtime;
    list_add_tail(&(conn->node), &(srv->tcp_head));
    return conn;
}

void tcpConnDestroy(tcpConn *conn) {
    list_del(&(conn->node));
    while(conn->whead) {
        struct tcpContext *ctx = conn->whead;
        conn->whead = ctx->next;
        tcpContextDestroy(ctx);
    }
    aeDeleteFileEvent(conn->el, conn->fd, AE_READABLE|AE_WRITABLE);
    close(conn->fd);
    zfree(conn);
    --sk.num_tcp_conn;
}

// reset tcp connection's status and prepare to read next dns packet.
void tcpConnReset(tcpConn *c) {
    if (c->data != c->buf) {
        zfree(c->data);
        c->data = c->buf;
    }
    c->nRead = 0;
    c->dnsPacketSize = 0;
    c->state = CONN_READ_LEN;
}

static inline void tcpConnMoveTail(tcpConn *conn) {
    conn->lastActiveTs = sk.unixtime;
    list_del(&(conn->node));
    list_add_tail(&(conn->node), &(conn->srv->tcp_head));
}

static int tcpBindAddrs(tcpServer *srv) {
    int port = sk.port;
    char **bindaddr = sk.bindaddr;
    int bindaddr_count = sk.bindaddr_count;
    int *fds = srv->ipfd;
    int *count = &(srv->ipfd_count);
    int j;

    /* Force binding of 0.0.0.0 if no bind address is specified, always
     * entering the loop if j == 0. */
    for (j = 0; j < bindaddr_count || j == 0; j++) {
        if (bindaddr[j] == NULL) {
            int unsupported = 0;
            /* Bind * for both IPv6 and IPv4, we enter here only if
             * bindaddr_count == 0. */
            fds[*count] = anetTcp6Server(srv->errstr, port, NULL, sk.tcp_backlog, 1);
            if (fds[*count] != ANET_ERR) {
                anetNonBlock(NULL, fds[*count]);
                (*count)++;
            } else if (errno == EAFNOSUPPORT) {
                unsupported++;
                LOG_WARN(USER1, "Not listening to IPv6: unsupproted");
            }

            if (*count == 1 || unsupported) {
                /* Bind the IPv4 address as well. */
                fds[*count] = anetTcpServer(srv->errstr, port, NULL, sk.tcp_backlog, 1);
                if (fds[*count] != ANET_ERR) {
                    anetNonBlock(NULL, fds[*count]);
                    (*count)++;
                } else if (errno == EAFNOSUPPORT) {
                    unsupported++;
                    LOG_WARN(USER1, "Not listening to IPv4: unsupproted");
                }
            }
            /* Exit the loop if we were able to bind * on IPv4 and IPv6,
             * otherwise fds[*count] will be ANET_ERR and we'll print an
             * error and return to the caller with an error. */
            if (*count + unsupported == 2) break;
        } else if (strchr(bindaddr[j], ':')) {
            /* Bind IPv6 address. */
            fds[*count] = anetTcp6Server(srv->errstr, port, bindaddr[j], sk.tcp_backlog, 1);
        } else {
            /* Bind IPv4 address. */
            fds[*count] = anetTcpServer(srv->errstr, port, bindaddr[j], sk.tcp_backlog, 1);
        }
        if (fds[*count] == ANET_ERR) {
            LOG_WARN(USER1, "Creating Server TCP listening socket %s:%d: %s",
                     bindaddr[j] ? bindaddr[j] : "*",
                     port, srv->errstr);
            return ERR_CODE;
        }
        anetNonBlock(NULL, fds[*count]);
        (*count)++;
    }
    return OK_CODE;
}

static void tcpReadHandler(struct aeEventLoop *el, int fd,
                           void *privdata, int mask) {
    UNUSED(mask);
    size_t totalread = 0;
    ssize_t n = 0;
    size_t remain;
    tcpConn *conn = (tcpConn *) (privdata);
    assert(conn->fd == fd);
    tcpConnMoveTail(conn);

    while(1) {
        switch (conn->state) {
            case CONN_READ_LEN:
                remain = 2 - conn->nRead;
                n = read(conn->fd, conn->len + conn->nRead, remain);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) goto end;
                    LOG_WARN(USER1, "tcp read: %s", strerror(errno));
                    goto closing;
                } else if (n == 0) {
                    if (conn->nRead > 0) {
                        LOG_WARN(USER1, "the connection peer closed socket prematurely.");
                    }
                    goto closing;
                }
                conn->nRead += n;
                totalread += n;
                if (conn->nRead < 2) goto end;
                assert(conn->dnsPacketSize == 0);

                conn->dnsPacketSize = load16be(conn->len);
                conn->nRead = 0;
                conn->state = CONN_READ_N;
                if (conn->dnsPacketSize > MAX_UDP_SIZE) conn->data = zmalloc(conn->dnsPacketSize);
                else conn->data = conn->buf;
                // ignore break
            case CONN_READ_N:
                remain = conn->dnsPacketSize - conn->nRead;
                if (remain > 0) {
                    n = read(conn->fd, conn->data + conn->nRead, remain);
                    if (n < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) goto end;
                        LOG_WARN(USER1, "tcp read: %s", strerror(errno));
                        goto closing;
                    } else if (n == 0) {   // the peer close the socket prematurely.
                        LOG_WARN(USER1, "the connection peer closed socket prematurely.");
                        goto closing;
                    }
                }
                conn->nRead += n;
                totalread += n;
                if (conn->nRead == conn->dnsPacketSize) {
                    processTCPDnsQuery(conn, conn->data, conn->dnsPacketSize);
                    if (sk.force_quit) {
                        goto closing;
                    }
                    // reset conn status and prepare to read next dns packet.
                    tcpConnReset(conn);
                }
                break;
            default:
                LOG_FATAL(USER1, "BUG: invalid conn state");
        }
    }
closing:
    aeDeleteFileEvent(el, fd, AE_READABLE);
    if (conn->whead == NULL) {
        tcpConnDestroy(conn);
    }
end:
    return;
    // ATOM_ADD(&(server.nr_input_bytes), totalread);
}

static void tcpWriteHandler(struct aeEventLoop *el, int fd, void *privdata, int mask) {
    UNUSED(mask);
    size_t totalwrite = 0;
    size_t remain;
    ssize_t nwritten;
    struct tcpContext *ctx;
    tcpConn *c = privdata;
    // tcpServer *srv = c->srv;
    assert(fd == c->fd);
    tcpConnMoveTail(c);

    while (c->whead != NULL) {
        ctx = c->whead;
        remain = ctx->wsize - ctx->wcur;
        nwritten = write(c->fd, ctx->reply + ctx->wcur, remain);
        if (nwritten <= 0) {
            if ((nwritten < 0) && (errno == EAGAIN || errno == EWOULDBLOCK)) goto end;
            LOG_ERROR(USER1, "error writing to client: %s", strerror(errno));
            tcpConnDestroy(c);
            goto end;
        }
        ctx->wcur += nwritten;
        totalwrite += nwritten;

        if ((size_t )nwritten < remain) goto end;

        c->whead = ctx->next;
        if (c->wtail == ctx) c->wtail = NULL;

        tcpContextDestroy(ctx);
    }
    if (c->whead == NULL) {
        aeDeleteFileEvent(el, fd, AE_WRITABLE);
        if (sk.force_quit) {
            // only delete connection, event loop will be stopped in tcpCron when possible.
            tcpConnDestroy(c);
        }
    }
end:
    // ATOM_ADD(&(server.nr_output_bytes), totalwrite);
    return;
}

#define MAX_ACCEPTS_PER_CALL 1000

static void tcpAcceptHandler(struct aeEventLoop *el, int fd, void *privateData, int mask) {
    UNUSED(mask);

    int cport, cfd, max = MAX_ACCEPTS_PER_CALL;
    char cip[IP_STR_LEN];
    tcpServer *srv = (tcpServer *) (privateData);
    while(max--) {
        cfd = anetTcpAccept(srv->errstr, fd, cip, sizeof(cip), &cport);
        if (cfd == ANET_ERR) {
            if (errno != EWOULDBLOCK)
                LOG_ERROR(USER1, "Accepting client connection: %s", srv->errstr);
            return;
        }
        if (++sk.num_tcp_conn > sk.max_tcp_connections) {
            --sk.num_tcp_conn;
            // the number of connections reach the limit, just close it.
            close(cfd);
            ++sk.rejected_tcp_conn;
            continue;
        }
        LOG_INFO(USER1, "tcp server accepted %s:%d", cip, cport);
        anetNonBlock(NULL, cfd);
        anetEnableTcpNoDelay(NULL, cfd);
        if (sk.tcp_keepalive) {
            anetKeepAlive(NULL, cfd, sk.tcp_keepalive);
        }
        tcpConn *conn = tcpConnCreate(cfd, srv);
        strcpy(conn->cip, cip);
        conn->cport = cport;

        if (aeCreateFileEvent(el, cfd, AE_READABLE, tcpReadHandler, conn) == AE_ERR) {
            LOG_ERROR(USER1, "Can't create file event for client..");
            tcpConnDestroy(conn);
            return;
        }
        ++sk.total_tcp_conn;
    }
}
