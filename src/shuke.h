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
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>

#include "defines.h"
#include "log.h"

struct config {
    char *configfile;

    char *coremask;
    char *mem_channels;
    int portmask;
    bool promiscuous_on;
    bool numa_on;
    bool jumbo_on;
    bool parse_ptype;
    int max_pkt_len;
    char *rx_queue_config;

    int port;
    char *pidfile;
    bool daemonize;
    bool enable_query_log;
    char *query_log_file;
    char *logLevelStr;
    char *logfile;
    bool logVerbose;
    int tcp_backlog;
    int tcp_keepalive;
    int tcp_idle_timeout;
    int max_tcp_connections;
    int num_threads;
    char *thread_affinity;

    char *redis_host;
    int redis_port;
    char *redis_zone_prefix;
    char *redis_soa_prefix;
    char *redis_origins_key;
    long redis_retry_interval;

    char *mongo_host;
    int mongo_port;
    char *admin_host;
    int admin_port;

    char *data_store;
    int all_reload_interval;
    bool minimize_resp;
};

struct shuke {
    char errstr[ERR_STR_LEN];

    struct config cfg;
    volatile bool force_quit;
};

extern struct shuke sk;

#endif /* _SHUKE_H_ */
