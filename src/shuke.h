//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-05
//

#ifndef _SHUKE_H_
#define _SHUKE_H_ 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>

#include "defines.h"
#include "version.h"
#include "ae.h"
#include "anet.h"
#include "zmalloc.h"
#include "endianconv.h"
#include "list.h"
#include "log.h"
#include "dnspacket.h"
#include "ltree.h"
#include "dpdk_module.h"
#include "zparser.h"
#include "zone.h"
#include "sk_lua.h"

#include "himongo/async.h"

#define CONFIG_BINDADDR_MAX 16
#define TIME_INTERVAL 1000

#define CONN_READ_N     0     /**< reading in a fixed number of bytes */
#define CONN_READ_LEN   1     /**< reading length bytes */
#define CONN_SWALLOW    2     /**< swallowing unnecessary bytes w/o storing */
#define CONN_WRITE_N    3     /**< writing out fixed number of bytes */
#define CONN_WRITE_LEN  4     /**< writing out the length bytes */
#define CONN_CLOSING    5     /**< closing this connection */
#define CONN_CLOSED     6     /**< connection is closed */
#define CONN_MAX_STATE  7     /**< Max state value (used for assertion) */

#define MAX_NUMA_NODES  32

#define shukeAssert(_e)                              \
    do{                                         \
        if (unlikely(!(_e))) {                  \
            _shukeAssert(#_e,__FILE__,__LINE__); \
            _exit(1);                           \
        }                                       \
    } while(0)
#define shukePanic(_e) _shukePanic(#_e,__FILE__,__LINE__),_exit(1)

enum taskStates {
    TASK_PENDING = 0,
    TASK_RUNNING = 1,
    TASK_ERROR = 2,
};

typedef struct numaNode_s {
    int numa_id;
    int main_lcore_id;
    int nr_lcore_ids;           // enabled lcores belong this numa node;
    int *lcore_ids;
    int min_lcore_id;
    int max_lcore_id;
    ltree *lt;
} numaNode_t;

typedef struct _tcpServer {
    int ipfd[CONFIG_BINDADDR_MAX];  // only for tcp server(listening fd)
    int ipfd_count;

    aeEventLoop *el;
    pthread_t tid;
    struct list_head tcp_head;     // tcp connection list.

    char errstr[ERR_STR_LEN];
} tcpServer;

typedef struct _tcpConn {
    int fd;
    aeEventLoop *el;
    char buf[MAX_UDP_SIZE];
    size_t nRead;
    struct tcpContext *whead;
    struct tcpContext *wtail;
    struct _tcpServer *srv;

    char cip[IP_STR_LEN];
    int cport;

    char len[2];
    // when the query packet size is smaller than MAX_UDP_SIZE, data points to buf
    // otherwise it will point to dynamic allocated memory, in this case,
    // memory free is needed when finished.
    char *data;
    int state;

    long lastActiveTs;

    size_t dnsPacketSize;    // size of current dns query packet
    struct list_head node;     // for connection list
} tcpConn;

struct tcpContext {
    tcpConn *sock;

    struct tcpContext *next;

    size_t wcur;       // tcp write cursor.
    size_t wsize;      // total size of data size.
    char reply[];
};

typedef struct _zoneReloadContext {
    int status;

    char *dotOrigin;  // origin in <label dot> format, must be an absolute domain name
    uint32_t sn;      // serial number in current cache.
    int32_t refresh;
    int32_t expiry;
    // if refresh_ts is -1, then this a new zone.
    long refresh_ts;

    RRParser *psr;
    zone *new_zn;
    bool zone_exist;

    struct _zoneReloadContext *next;
}zoneReloadContext;

typedef struct {
    zoneReloadContext *head;
    zoneReloadContext *tail;
} zoneReloadContextList;

struct shuke {
    char errstr[ERR_STR_LEN];

    // config
    char *configfile;

    int master_lcore_id;
    int mem_channels;
    bool promiscuous_on;
    bool numa_on;
    bool jumbo_on;
    int max_pkt_len;
    char *queue_config;

    char *bindaddr[CONFIG_BINDADDR_MAX];
    int bindaddr_count;
    int port;
    bool only_udp;
    char *pidfile;
    bool daemonize;
    char *query_log_file;
    char *logLevelStr;
    char *logfile;
    bool logVerbose;

    int tcp_backlog;
    int tcp_keepalive;
    int tcp_idle_timeout;
    int max_tcp_connections;

    char *data_store;

    char *zone_files_root;
    dict *zone_files_dict;

    char *mongo_host;
    int mongo_port;
    char *mongo_dbname;

    long retry_interval;

    char *admin_host;
    int admin_port;

    int all_reload_interval;
    int max_resp_size;
    bool minimize_resp;

    char *access_by_lua_src;
    // end config

    /*
     * these fields will allocate using malloc
     */
    // MAP: lcore_id => lcore_conf_t
    lcore_conf_t lcore_conf[RTE_MAX_LCORE];
    // MAP: portid => port_info_t*
    port_info_t *port_info[RTE_MAX_ETHPORTS];

    //MAP: socketid => numaNode_t*
    numaNode_t *nodes[MAX_NUMA_NODES];
    int numa_ids[MAX_NUMA_NODES];
    int nr_numa_id;

    int master_numa_id;

    int *lcore_ids;
    int nr_lcore_ids;

    int *port_ids;
    int nr_ports;
    // char *total_coremask;
    char *total_lcore_list;
    // end

    // pointer to master numa node's zoneDict instance
    ltree *lt;
    struct rb_root rbroot;

    volatile bool force_quit;
    FILE *query_log_fp;
    FILE *log_fp;

    int (*syncGetAllZone)(void);
    /*
     * create a asyncContext.
     */
    int (*initAsyncContext)(void);
    /*
     * this function is used to check if the context is ready to submit command.
     * for mongodb, it returns OK_CODE only when the context is in connected state.
     */
    int (*checkAsyncContext)(void);
    /*
     * these two functions should be called only in mainThreadCron.
     *
     * if zone reloading is needed, just enqueue an zoneReloadContext to task queue.
     * if all zone reloading is needed, just set `last_all_reload_ts` to `now-all_reload_interval`
     * then mainThreadCron will do reloading automatically.
     */
    int (*asyncReloadAllZone)(void);
    int (*asyncReloadZone)(zoneReloadContext *t);

    // pending zone reload task
    zoneReloadContextList tasks;
    // mongo context
    // it will be NULL when shuke is disconnected with mongodb
    mongoAsyncContext *mongo_ctx;
    long last_retry_ts;

    // admin server
    int fd;
    dict *commands;
    struct list_head head;

    // dns tcp server
    tcpServer *tcp_srv;

    int arch_bits;
    long last_all_reload_ts; // timestamp of last all reload


    aeEventLoop *el;      // event loop for main thread.

    long unixtime;
    long long mstime;

    time_t    starttime;     // server start time
    long long zone_load_time;


    uint64_t hz;		/**< Number of events per seconds */

    // statistics
    int64_t nr_req;                   // number of processed requests
    int64_t nr_dropped;
    long long last_collect_ms;

    uint64_t num_tcp_conn;
    uint64_t total_tcp_conn;
    uint64_t rejected_tcp_conn;
};

/*----------------------------------------------
 *     Extern declarations
 *---------------------------------------------*/
extern struct shuke sk;
extern dictType commandTableDictType;
extern dictType zoneFileDictType;

int snpack(char *buf, int offset, size_t size, char const *fmt, ...);
/*----------------------------------------------
 *     zoneReloadContext
 *---------------------------------------------*/
zoneReloadContext *zoneReloadContextCreate(char *dotOrigin);
void zoneReloadContextReset(zoneReloadContext *t);
void zoneReloadContextDestroy(zoneReloadContext *t);

int asyncReloadZoneRaw(char *dotOrigin);
int asyncRereloadZone(zoneReloadContext *ctx);
int triggerReloadAllZone();
/*----------------------------------------------
 *     admin server
 *---------------------------------------------*/
int initAdminServer(void);
void releaseAdminServer(void);

/*----------------------------------------------
 *     tcp server
 *---------------------------------------------*/
tcpServer *tcpServerCreate();
int tcpServerCron(struct aeEventLoop *el, long long id, void *clientData);
void tcpConnAppendDnsResponse(tcpConn *conn, char *resp, size_t respLen);

/*----------------------------------------------
 *     mongo
 *---------------------------------------------*/
int initMongo(void);
int checkMongo(void);
int mongoGetAllZone(void);
int mongoAsyncReloadZone(zoneReloadContext *t);
int mongoAsyncReloadAllZone(void);

int processUDPDnsQuery(struct rte_mbuf *m, char *udp_data, size_t udp_data_len, char *src_addr, uint16_t src_port,
                       bool is_ipv4, numaNode_t *node, int lcore_id);

int processTCPDnsQuery(tcpConn *conn, char *buf, size_t sz);

void addZoneOtherNuma(zone *z);
void deleteZoneOtherNuma(char *origin);
void replaceZoneOtherNuma(zone *z);

int replaceZoneAllNumaNodes(zone *z);
int addZoneAllNumaNodes(zone *z);
int deleteZoneAllNumaNodes(char *origin);
void masterRefreshZone(char *origin);

void config_log();
void collectStats();
/*----------------------------------------------
 *     debug utils
 *---------------------------------------------*/
void sigsegvHandler(int sig, siginfo_t *info, void *secret);
void _shukeAssert(char *estr, char *file, int line);
void _shukePanic(char *msg, char *file, int line);

/*----------------------------------------------
 *     config
 *---------------------------------------------*/
sds configToStr();
void initConfigFromTomlFile(char *conffile);

#endif /* _SHUKE_H_ */
