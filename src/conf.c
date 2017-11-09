/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "fmacros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <libyaml/include/yaml.h>

#include "yaml.h"

#include "defines.h"
#include "str.h"
#include "shuke.h"
#include "utils.h"

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
        CHECK_CONFIG(name, (t).type == YAML_SCALAR_EVENT,           \
                     "Config Error: " name "should be a string");   \
        if((v) != NULL) free(v);                                    \
        (v) = strdup((char*)(t).data.scalar.value);                 \
    } while(0)

#define GET_INT_CONFIG(name, v, t)                                      \
    do{                                                                 \
        CHECK_CONFIG(name, (t).type == YAML_SCALAR_EVENT,               \
                     "Config Error: " name "should be a string");       \
        char *end = NULL;                                               \
        long lval;                                                      \
        int base = 10;                                                  \
        char *str_val = (char*)(t).data.scalar.value;                   \
        if (str_val[0] == '0') base = 16;                               \
        lval = strtol(str_val, &end, base);                             \
        if (*end == '\0') {                                             \
            (v) = lval;                                                 \
        } else {                                                        \
            fprintf(stderr, "invalid character for config %s", name);   \
            exit(-1);                                                   \
        }                                                               \
    } while(0)

#define GET_BOOL_CONFIG(name, v, t)                                     \
    do{                                                                 \
        CHECK_CONFIG(name, (t).type == YAML_SCALAR_EVENT,               \
                     "Config Error: " name "should be a string");       \
        char *str_val = (char*)(t).data.scalar.value;                   \
        if (!strcasecmp(str_val, "on") ||                               \
            !strcasecmp(str_val, "yes") ||                              \
            !strcasecmp(str_val, "true")) {                             \
            (v) = true;                                                 \
        } else if (!strcasecmp(str_val, "off") ||                       \
                   !strcasecmp(str_val, "no") ||                        \
                   !strcasecmp(str_val, "false")) {                     \
            (v) = false;                                                \
        } else {                                                        \
            fprintf(stderr, "only on/true/yes and off/false/no is valid for the key %s.", name); \
            exit(-1);                                                   \
        }                                                               \
    } while(0)

/*!
 * convert all the zone file name to absolute path
 * @return
 */
static int refineZoneFileConfig() {
    dictIterator *it = dictGetIterator(sk.zone_files_dict);
    dictEntry *de;
    char *dotOrigin, *fname;
    while((de = dictNext(it)) != NULL) {
        dotOrigin = dictGetKey(de);
        fname = dictGetVal(de);
        if (isAbsDotDomain(dotOrigin) == false) {
            snprintf(sk.errstr, ERR_STR_LEN, "%s is not absolute domain name.", dotOrigin);
            return ERR_CODE;
        }
        fname = toAbsPath(fname, sk.zone_files_root);
        if (access(fname, F_OK) == -1) {
            snprintf(sk.errstr, ERR_STR_LEN, "%s doesn't exist.", fname);
            free(fname);
            return ERR_CODE;
        }
        dictReplace(sk.zone_files_dict, dotOrigin, fname);
        free(fname);
    }
    dictReleaseIterator(it);
    return OK_CODE;
}

static int _parse_yaml_config(FILE *fh) {
    char key[4096];
    yaml_parser_t parser;
    yaml_event_t  event, t;   /* New variable */

    /* Initialize parser */
    if(!yaml_parser_initialize(&parser))
        fputs("Failed to initialize parser!\n", stderr);
    if(fh == NULL)
        fputs("Failed to open file!\n", stderr);

    /* Set input file */
    yaml_parser_set_input_file(&parser, fh);

    do {
        if (!yaml_parser_parse(&parser, &event)) {
            fprintf(stderr, "Parser error %d\n", parser.error);
            exit(EXIT_FAILURE);
        }

        switch(event.type)
        {
            case YAML_NO_EVENT:
                /* puts("No event!"); */
                break;
            case YAML_STREAM_START_EVENT:
                /* puts("STREAM START"); */
                break;
            case YAML_STREAM_END_EVENT:
                /* puts("STREAM END"); */
                break;
                /* Block delimeters */
            case YAML_DOCUMENT_START_EVENT:
                /* puts("<b>Start Document</b>"); */
                break;
            case YAML_DOCUMENT_END_EVENT:
                /* puts("<b>End Document</b>"); */
                break;
            case YAML_SEQUENCE_START_EVENT:
                /* puts("<b>Start Sequence</b>"); */
                break;
            case YAML_SEQUENCE_END_EVENT:
                /* puts("<b>End Sequence</b>"); */
                break;
            case YAML_MAPPING_START_EVENT:
                /* puts("<b>Start Mapping</b>"); */
                break;
            case YAML_MAPPING_END_EVENT:
                /* puts("<b>End Mapping</b>"); */
                break;
                /* Data */
            case YAML_ALIAS_EVENT:
                /* printf("Got alias (anchor %s)\n", event.data.alias.anchor); */
                break;
            case YAML_SCALAR_EVENT:
                strncpy(key, (char*)event.data.scalar.value, 4096);
                if (!yaml_parser_parse(&parser, &t)) {
                    fprintf(stderr, "Parser error %d\n", parser.error);
                    exit(EXIT_FAILURE);
                }
                if (! strcasecmp(key, "coremask")) {
                    GET_STR_CONFIG("coremask", sk.coremask, t);
                } else if (! strcasecmp(key, "master_lcore_id")) {
                    GET_INT_CONFIG("master_lcore_id", sk.master_lcore_id, t);
                } else if (! strcasecmp(key, "mem_channels")) {
                    GET_STR_CONFIG("mem_channels", sk.mem_channels, t);
                } else if (! strcasecmp(key, "promiscuous_on")) {
                    GET_BOOL_CONFIG("promiscuous_on", sk.promiscuous_on, t);
                } else if (! strcasecmp(key, "portmask")) {
                    GET_INT_CONFIG("portmask", sk.portmask, t);
                } else if (! strcasecmp(key, "numa_on")) {
                    GET_BOOL_CONFIG("numa_on", sk.numa_on, t);
                } else if (! strcasecmp(key, "jumbo_on")) {
                    GET_BOOL_CONFIG("jumbo_on", sk.jumbo_on, t);
                } else if (! strcasecmp(key, "max_pkt_len")) {
                    GET_INT_CONFIG("max_pkt_len", sk.max_pkt_len, t);
                } else if (! strcasecmp(key, "queue_config")) {
                    GET_STR_CONFIG("queue_config", sk.queue_config, t);
                } else if (! strcasecmp(key, "bind")) {
                    yaml_event_t ev;
                    if (t.type != YAML_SEQUENCE_START_EVENT) {
                        fprintf(stderr, "config value of bind must be an array\n");
                        exit(-1);
                    }
                    sk.bindaddr_count = 0;
                    while (1) {
                        if (!yaml_parser_parse(&parser, &ev)) {
                            fprintf(stderr, "Parser error %d\n", parser.error);
                            exit(EXIT_FAILURE);
                        }
                        if (ev.type == YAML_SEQUENCE_END_EVENT) {
                            yaml_event_delete(&ev);
                            break;
                        }
                        if (ev.type != YAML_SCALAR_EVENT) {
                            fprintf(stderr, "config value of bind must be an array of string\n");
                            exit(-1);
                        }
                        if (sk.bindaddr_count >= CONFIG_BINDADDR_MAX) {
                            fprintf(stderr, "too many address\n");
                            exit(-1);
                        }
                        sk.bindaddr[sk.bindaddr_count++] = strdup((char*)ev.data.scalar.value);
                        yaml_event_delete(&ev);
                    }
                } else if (! strcasecmp(key, "port")) {
                    GET_INT_CONFIG("port", sk.port, t);
                } else if (! strcasecmp(key, "only_udp")) {
                    GET_BOOL_CONFIG("only_udp", sk.only_udp, t);
                } else if (! strcasecmp(key, "data_store")) {
                    GET_STR_CONFIG("data_store", sk.data_store, t);
                } else if (! strcasecmp(key, "tcp_backlog")) {
                    GET_INT_CONFIG("tcp_backlog", sk.tcp_backlog, t);
                } else if (! strcasecmp(key, "tcp_keepalive")) {
                    GET_INT_CONFIG("tcp_keepalive", sk.tcp_keepalive, t);
                } else if (! strcasecmp(key, "tcp_idle_timeout")) {
                    GET_INT_CONFIG("tcp_idle_timeout", sk.tcp_idle_timeout, t);
                } else if (! strcasecmp(key, "max_tcp_connections")) {
                    GET_INT_CONFIG("max_tcp_connections", sk.max_tcp_connections, t);
                } else if (! strcasecmp(key, "pidfile")) {
                    GET_STR_CONFIG("pidfile", sk.pidfile, t);
                } else if (! strcasecmp(key, "query_log_file")) {
                    GET_STR_CONFIG("query_log_file", sk.query_log_file, t);
                } else if (! strcasecmp(key, "logfile")) {
                    GET_STR_CONFIG("logfile", sk.logfile, t);
                } else if (! strcasecmp(key, "log_verbose")) {
                    GET_BOOL_CONFIG("log_verbose", sk.logVerbose, t);
                } else if (! strcasecmp(key, "daemonize")) {
                    GET_BOOL_CONFIG("daemonize", sk.daemonize, t);
                } else if (! strcasecmp(key, "loglevel")) {
                    GET_STR_CONFIG("loglevel", sk.logLevelStr, t);
                } else if (! strcasecmp(key, "admin_host")) {
                    GET_STR_CONFIG("admin_host", sk.admin_host, t);
                } else if (! strcasecmp(key, "admin_port")) {
                    GET_INT_CONFIG("admin_port", sk.admin_port, t);
                } else if (! strcasecmp(key, "all_reload_interval")) {
                    GET_INT_CONFIG("all_reload_interval", sk.all_reload_interval, t);
                } else if (! strcasecmp(key, "minimize_resp")) {
                    GET_BOOL_CONFIG("minimize_resp", sk.minimize_resp, t);
                } else if (! strcasecmp(key, "zone_files_root")) {
                    GET_STR_CONFIG("zone_files_root", sk.zone_files_root, t);
                } else if (! strcasecmp(key, "zone_files")) {
                    sk.zone_files_dict = dictCreate(&zoneFileDictType, NULL, SOCKET_ID_HEAP);
                    if (t.type != YAML_MAPPING_START_EVENT) {
                        fprintf(stderr, "config value of zone_files must be a map\n");
                        exit(-1);
                    }
                    yaml_event_t k, v;
                    while (1) {
                        if (!yaml_parser_parse(&parser, &k)) {
                            fprintf(stderr, "Parser error %d\n", parser.error);
                            exit(EXIT_FAILURE);
                        }
                        if (k.type == YAML_MAPPING_END_EVENT) {
                            yaml_event_delete(&k);
                            break;
                        }
                        if (!yaml_parser_parse(&parser, &v)) {
                            fprintf(stderr, "Parser error %d\n", parser.error);
                            exit(EXIT_FAILURE);
                        }
                        if (k.type != YAML_SCALAR_EVENT || v.type != YAML_SCALAR_EVENT) {
                            fprintf(stderr, "config value of zone_files must be a map of <zname, fname>\n");
                            exit(-1);
                        }

                        if (dictAdd(sk.zone_files_dict, (char*)k.data.scalar.value, (char*)v.data.scalar.value) != DICT_OK) {
                            fprintf(stderr, "duplicate zone file %s", (char*)k.data.scalar.value);
                            exit(EXIT_FAILURE);
                        }
                        yaml_event_delete(&k);
                        yaml_event_delete(&v);
                    }
                } else if (! strcasecmp(key, "mongo_host")) {
                    GET_STR_CONFIG("mongo_host", sk.mongo_host, t);
                } else if (! strcasecmp(key, "mongo_port")) {
                    GET_INT_CONFIG("mongo_port", sk.mongo_port, t);
                } else if (! strcasecmp(key, "mongo_dbname")) {
                    GET_STR_CONFIG("mongo_dbname", sk.mongo_dbname, t);
                } else if (! strcasecmp(key, "retry_interval")) {
                    GET_INT_CONFIG("retry_interval", sk.retry_interval, t);
                } else {
                    fprintf(stderr, "invalid config name %s.\n", key);
                    exit(1);
                }
                yaml_event_delete(&t);
                break;
        }
        if(event.type != YAML_STREAM_END_EVENT)
            yaml_event_delete(&event);
    } while(event.type != YAML_STREAM_END_EVENT);
    yaml_event_delete(&event);

    /* Cleanup */
    yaml_parser_delete(&parser);
    return 0;
}


void initConfigFromYamlFile(char *conffile) {
    char cwd[MAXLINE];

    FILE *fp = fopen(conffile, "r");
    if (fp == NULL) {
        fprintf(stderr, "Can't open configure file(%s)\n", conffile);
        exit(1);
    }
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
    sk.pidfile = strdup("/var/run/shuke.pid");
    sk.logLevelStr = strdup("info");

    _parse_yaml_config(fp);

    CHECK_CONFIG("coremask", sk.coremask != NULL,
                 "Config Error: coremask can't be empty");
    CHECK_CONFIG("mem_channels", sk.mem_channels != NULL,
                 "Config Error: mem_channels can't be empty");

    CHECK_CONFIG("data_store", sk.data_store != NULL,
                 "Config Error: data_store can't be empty");
    if (strcasecmp(sk.data_store, "file") == 0) {
        if (sk.zone_files_root == NULL) {
            sk.zone_files_root = strdup(cwd);
        }
        if (*(sk.zone_files_root) != '/') {
            fprintf(stderr, "Config Error: zone_files_root must be an absolute path.\n");
            exit(1);
        }
        if (refineZoneFileConfig() != OK_CODE) {
            fprintf(stderr, "Config Error: %s.\n", sk.errstr);
            exit(1);
        }
    } else if (strcasecmp(sk.data_store, "mongo") == 0) {
        CHECK_CONFIG("mongo_host", sk.mongo_host != NULL, NULL);
        CHECK_CONFIG("mongo_dbname", sk.mongo_dbname != NULL, NULL);
    } else {
        fprintf(stderr, "invalid data_store config.\n");
        exit(1);
    }
    fclose(fp);
}

sds configToStr() {
    sds s = sdsnewprintf(
            "conffile: %s\n"
            "coremask: %s\n"
            "master_lcore_id: %d\n"
            "mem_channels: %s\n"
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
    initConfigFromYamlFile(argv[3]);
    test_cond("loglevel: ", strcmp(sk.logLevelStr, "info") == 0);
    test_cond("logfile: ", strcmp(sk.logfile, "") == 0);
    test_cond("pidfile: ", strcmp(sk.pidfile, "/var/run/shuke.pid") == 0);
    test_cond("port: ", sk.port == 53);

    test_report();
    return 0;
}
#endif
