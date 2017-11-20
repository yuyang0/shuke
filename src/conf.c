/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "fmacros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include "defines.h"
#include "str.h"
#include "shuke.h"
#include "utils.h"
#include "toml.h"

#define CHECK_CONFIG(name, exp, msg)                                    \
    do{                                                                 \
        if (!(exp)) {                                                   \
            char *temp = msg;                                           \
            if (temp) fprintf(stderr, "%s\n", temp);                    \
            else fprintf(stderr, "Config Error: invalid value for %s config\n", name); \
            exit(1);                                                    \
        }                                                               \
    }while(0)

#define GET_STR_CONFIG(name, v, t)                                  \
    do{                                                             \
        const char *raw;                                            \
        if ((raw = toml_raw_in(t, name))) {                         \
            if (toml_rtos(raw, &(v)) < 0) {                         \
                fprintf(stderr, "ERROR: bad value in %s\n", name);  \
                exit(EXIT_FAILURE);                                 \
            }                                                       \
        }                                                           \
    } while(0)

#define GET_INT_CONFIG(name, v, t)                                  \
    do{                                                             \
        const char *raw;                                            \
        int64_t tmp;                                                \
        if ((raw = toml_raw_in(t, name))) {                         \
            if (toml_rtoi(raw, &tmp) < 0) {                         \
                fprintf(stderr, "ERROR: bad value in %s\n", name);  \
                exit(EXIT_FAILURE);                                 \
            }                                                       \
            (v) = (int)tmp;                                         \
        }                                                           \
    } while(0)

#define GET_BOOL_CONFIG(name, v, t)                                 \
    do{                                                             \
        const char *raw;                                            \
        int tmp;                                                    \
        if ((raw = toml_raw_in(t, name))) {                         \
            if (toml_rtob(raw, &tmp) < 0) {                         \
                fprintf(stderr, "ERROR: bad value in %s\n", name);  \
                exit(EXIT_FAILURE);                                 \
            }                                                       \
            (v) = (bool)tmp;                                        \
        }                                                           \
    } while(0)

static int addZoneFileToConf(char *k, char *v) {
    dict *d = sk.zone_files_dict;
    if (isAbsDotDomain(k) == false) {
        fprintf(stderr, "%s is not absolute domain name.", k);
        exit(EXIT_FAILURE);
    }
    v = toAbsPath(v, sk.zone_files_root);
    if (access(v, F_OK) == -1) {
        fprintf(stderr, "%s doesn't exist.", v);
        exit(EXIT_FAILURE);
    }
    if (dictAdd(d, k, v) != DICT_OK) {
        fprintf(stderr, "duplicate zone file %s", k);
        exit(EXIT_FAILURE);
    }
    // don't use zfree.
    free(v);
    return 0;
}

static int _parse_toml_config(FILE *fp) {
    toml_table_t *conf;
    toml_table_t *dpdk, *core, *zone_source;
    char errbuf[200];
    conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
    if (conf == NULL) {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    if ((dpdk = toml_table_in(conf, "dpdk")) == NULL) {
        fprintf(stderr, "ERROR: missing [dpdk]\n");
        toml_free(conf);
        exit(EXIT_FAILURE);
    }

    if ((core = toml_table_in(conf, "core")) == NULL) {
        fprintf(stderr, "ERROR: missing [core]\n");
        toml_free(conf);
        exit(EXIT_FAILURE);
    }

    if ((zone_source = toml_table_in(conf, "zone_source")) == NULL) {
        fprintf(stderr, "ERROR: missing [zone_source]\n");
        toml_free(conf);
        exit(EXIT_FAILURE);
    }

    // dpdk related config
    GET_STR_CONFIG("coremask", sk.coremask, dpdk);
    GET_INT_CONFIG("master_lcore_id", sk.master_lcore_id, dpdk);
    GET_INT_CONFIG("mem_channels", sk.mem_channels, dpdk);
    GET_BOOL_CONFIG("promiscuous_on", sk.promiscuous_on, dpdk);
    GET_BOOL_CONFIG("numa_on", sk.numa_on, dpdk);
    GET_BOOL_CONFIG("jumbo_on", sk.jumbo_on, dpdk);
    GET_INT_CONFIG("max_pkt_len", sk.max_pkt_len, dpdk);
    GET_STR_CONFIG("queue_config", sk.queue_config, dpdk);
    char *portmask_str = NULL;
    long portmask;
    GET_STR_CONFIG("portmask", portmask_str, dpdk);
    if (portmask_str == NULL) {
        fprintf(stderr, "portmask can't be empty\n");
        exit(EXIT_FAILURE);
    }
    if (str2long(portmask_str, &portmask) < 0) {
        fprintf(stderr, "portmask should be a hex number.\n");
        exit(-1);
    }
    sk.portmask = (int)portmask;

    // core config
    toml_array_t *bind;
    if ((bind = toml_array_in(core, "bind")) != NULL) {
        if (toml_array_kind(bind) != 'v') {
            fprintf(stderr, "the value of bind should be an array of string.\n");
            exit(EXIT_FAILURE);
        }
        sk.bindaddr_count = 0;
        int i = 0;
        char *bindaddr;
        const char *raw;
        while ((raw = toml_raw_at(bind, i++)) != NULL) {
            if (toml_rtos(raw, &bindaddr) < 0) {
                fprintf(stderr, "the value of bind should be an array of string.\n");
                exit(EXIT_FAILURE);
            }
            if (sk.bindaddr_count >= CONFIG_BINDADDR_MAX) {
                fprintf(stderr, "too many address\n");
                exit(-1);
            }
            sk.bindaddr[sk.bindaddr_count++] = bindaddr;
        }
    }

    GET_INT_CONFIG("port", sk.port, core);
    GET_BOOL_CONFIG("only_udp", sk.only_udp, core);
    GET_INT_CONFIG("tcp_backlog", sk.tcp_backlog, core);
    GET_INT_CONFIG("tcp_keepalive", sk.tcp_keepalive, core);
    GET_INT_CONFIG("tcp_idle_timeout", sk.tcp_idle_timeout, core);
    GET_INT_CONFIG("max_tcp_connections", sk.max_tcp_connections, core);
    GET_STR_CONFIG("pidfile", sk.pidfile, core);
    GET_STR_CONFIG("query_log_file", sk.query_log_file, core);
    GET_STR_CONFIG("logfile", sk.logfile, core);
    GET_BOOL_CONFIG("log_verbose", sk.logVerbose, core);
    GET_BOOL_CONFIG("daemonize", sk.daemonize, core);
    GET_STR_CONFIG("loglevel", sk.logLevelStr, core);
    GET_STR_CONFIG("admin_host", sk.admin_host, core);
    GET_INT_CONFIG("admin_port", sk.admin_port, core);
    GET_BOOL_CONFIG("minimize_resp", sk.minimize_resp, core);

    // zone_source related config
    GET_INT_CONFIG("retry_interval", sk.retry_interval, zone_source);
    GET_INT_CONFIG("all_reload_interval", sk.all_reload_interval, zone_source);
    GET_STR_CONFIG("type", sk.data_store, zone_source);
    if (strcasecmp(sk.data_store, "file") == 0) {
        toml_table_t *file;
        toml_array_t *file_list;
        toml_table_t *entry;

        if ((file = toml_table_in(zone_source, "file")) == NULL) {
            fprintf(stderr, "ERROR: missing [zone_source.file]\n");
            toml_free(conf);
            exit(EXIT_FAILURE);
        }
        if ((file_list= toml_array_in(file, "files")) == NULL) {
            fprintf(stderr, "ERROR: missing [zone_source.file.files]\n");
            toml_free(conf);
            exit(EXIT_FAILURE);
        }
        GET_STR_CONFIG("zone_files_root", sk.zone_files_root, file);

        if (sk.zone_files_root == NULL) {
            char cwd[MAXLINE];
            if (getcwd(cwd, MAXLINE) == NULL) {
                fprintf(stderr, "getcwd: %s.\n", strerror(errno));
                exit(1);
            }
            sk.zone_files_root = strdup(cwd);
        }
        if (*(sk.zone_files_root) != '/') {
            fprintf(stderr, "Config Error: zone_files_root must be an absolute path.\n");
            exit(1);
        }
        sk.zone_files_dict = dictCreate(&zoneFileDictType, NULL, SOCKET_ID_HEAP);
        for (int i = 0; ; i++) {
            if ((entry = toml_table_at(file_list, i)) == NULL) break;
            char *k=NULL, *v=NULL;
            GET_STR_CONFIG("name", k, entry);
            GET_STR_CONFIG("file", v, entry);
            if (k == NULL || v == NULL) {
                fprintf(stderr, "name and file can't be empty\n");
                exit(EXIT_FAILURE);
            }
            addZoneFileToConf(k, v);
            free(k);
            free(v);
        }
    } else if (strcasecmp(sk.data_store, "mongo") == 0) {
        toml_table_t *mongo;

        if ((mongo = toml_table_in(zone_source, "mongo")) == NULL) {
            fprintf(stderr, "ERROR: missing [zone_source.mongo]\n");
            toml_free(conf);
            exit(EXIT_FAILURE);
        }
        GET_STR_CONFIG("host", sk.mongo_host, mongo);
        GET_INT_CONFIG("port", sk.mongo_port, mongo);
        GET_STR_CONFIG("dbname", sk.mongo_dbname, mongo);

        CHECK_CONFIG("mongo_host", sk.mongo_host != NULL, NULL);
        CHECK_CONFIG("mongo_dbname", sk.mongo_dbname != NULL, NULL);
    } else {
        fprintf(stderr, "Unknown zone source type\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}


void initConfigFromTomlFile(char *conffile) {
    FILE *fp = fopen(conffile, "r");
    if (fp == NULL) {
        fprintf(stderr, "Can't open configure file(%s)\n", conffile);
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
    sk.pidfile = strdup("/var/run/shuke.pid");
    sk.logLevelStr = strdup("info");

    _parse_toml_config(fp);

    CHECK_CONFIG("coremask", sk.coremask != NULL,
                 "Config Error: coremask can't be empty");
    CHECK_CONFIG("mem_channels", sk.mem_channels > 0,
                 "Config Error: mem_channels can't be empty");

    CHECK_CONFIG("data_store", sk.data_store != NULL,
                 "Config Error: data_store can't be empty");

    fclose(fp);
}

sds configToStr() {
    sds s = sdsnewprintf(
            "conffile: %s\n"
            "coremask: %s\n"
            "master_lcore_id: %d\n"
            "mem_channels: %d\n"
            "portmask: %d\n"
            "promiscuous_on: %d\n"
            "numa_on: %d\n"
            "jumbo_on: %d\n"
            "max_pkt_len: %d\n"
            "queue_config: %s\n"
            "port: %d\n"
            "only_udp: %d\n"
            "pidfile: %s\n"
            "daemonize: %d\n"
            "query_log_file: %s\n"
            "logLevelStr: %s\n"
            "logfile: %s\n"
            "logVerbose: %d\n"
            "tcp_backlog: %d\n"
            "tcp_keepalive: %d\n"
            "tcp_idle_timeout: %d\n"
            "max_tcp_connections: %d\n"
            "data_store: %s\n"
            "zone_files_root: %s\n"
            "mongo_host: %s\n"
            "mongo_port: %d\n"
            "mongo_dbname: %s\n"
            "retry_interval: %ld\n"
            "admin_host: %s\n"
            "admin_port: %d\n"
            "all_reload_interval: %d\n"
            "minimize_resp: %d\n",
            sk.configfile,
            sk.coremask,
            sk.master_lcore_id,
            sk.mem_channels,
            sk.portmask,
            sk.promiscuous_on,
            sk.numa_on,
            sk.jumbo_on,
            sk.max_pkt_len,
            sk.queue_config,
            sk.port,
            sk.only_udp,
            sk.pidfile,
            sk.daemonize,
            sk.query_log_file,
            sk.logLevelStr,
            sk.logfile,
            sk.logVerbose,
            sk.tcp_backlog,
            sk.tcp_keepalive,
            sk.tcp_idle_timeout,
            sk.max_tcp_connections,
            sk.data_store,
            sk.zone_files_root,
            sk.mongo_host,
            sk.mongo_port,
            sk.mongo_dbname,
            sk.retry_interval,
            sk.admin_host,
            sk.admin_port,
            sk.all_reload_interval,
            sk.minimize_resp
    );
    s = sdscat(s, "bind: \n");
    for (int i = 0; i < sk.bindaddr_count; ++i) {
        s = sdscatfmt(s, "  - %s\n", sk.bindaddr[i]);
    }
    return s;
}

#if defined(SK_TEST)
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"
#include "testhelp.h"

#define UNUSED(x) (void)(x)

int confTest(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "need conf file");
        exit(1);
    }
    initConfigFromTomlFile(argv[3]);
    test_cond("loglevel: ", strcmp(sk.logLevelStr, "info") == 0);
    test_cond("logfile: ", strcmp(sk.logfile, "") == 0);
    test_cond("pidfile: ", strcmp(sk.pidfile, "/var/run/shuke.pid") == 0);
    test_cond("port: ", sk.port == 53);

    test_report();
    return 0;
}
#endif
