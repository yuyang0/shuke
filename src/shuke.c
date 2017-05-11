//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-05-05
//

#include "dpdk_module.h"

#include "conf.h"
#include "utils.h"
#include "version.h"

#include "shuke.h"
#include <getopt.h>

struct shuke sk;

static void usage() {
    printf("-c /path/to/cdns.conf    configure file.\n"
           "-h                       print this help and exit. \n"
           "-v                       print version. \n");
}

static void version() {
    printf("shuke version: %s\n", SHUKE_VERSION);
}

static void initConfig(int argc, char **argv) {
    int c;
    char *conffile = NULL;
    char *cbuf;
    char cwd[MAXLINE];
    int conf_err;
    if (getcwd(cwd, MAXLINE) == NULL) {
        fprintf(stderr, "getcwd: %s.\n", strerror(errno));
        exit(1);
    }

    // set default values
    sk.cfg.promiscuous_on = false;
    sk.cfg.numa_on = false;
    sk.cfg.parse_ptype = false;

    sk.cfg.port = 53;
    sk.cfg.daemonize = false;
    sk.cfg.logVerbose = false;

    sk.cfg.tcp_backlog = 511;
    sk.cfg.tcp_keepalive = 300;
    sk.cfg.tcp_idle_timeout = 120;
    sk.cfg.max_tcp_connections = 1024;

    sk.cfg.redis_port = 6379;
    sk.cfg.redis_retry_interval = 120;
    sk.cfg.mongo_port = 27017;

    sk.cfg.admin_port = 14141;
    sk.cfg.all_reload_interval = 36000;
    sk.cfg.minimize_resp = true;

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
    sk.cfg.configfile = toAbsPath(conffile, cwd);

    sk.cfg.coremask = getStrVal(cbuf, "coremask", NULL);
    CHECK_CONFIG("coremask", sk.cfg.coremask != NULL,
                 "Config Error: coremask can't be empty");
    sk.cfg.mem_channels = getStrVal(cbuf, "mem_channels", NULL);
    CHECK_CONFIG("mem_channels", sk.cfg.mem_channels != NULL,
                 "Config Error: mem_channels can't be empty");
    conf_err = getBoolVal(sk.errstr, cbuf, "promiscuous_on", &sk.cfg.promiscuous_on);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getIntVal(sk.errstr, cbuf, "portmask", &sk.cfg.portmask);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getBoolVal(sk.errstr, cbuf, "parse_ptype", &sk.cfg.parse_ptype);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getBoolVal(sk.errstr, cbuf, "numa_on", &sk.cfg.numa_on);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getBoolVal(sk.errstr, cbuf, "jumbo_on", &sk.cfg.jumbo_on);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getIntVal(sk.errstr, cbuf, "max_pkt_len", &sk.cfg.max_pkt_len);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    sk.cfg.rx_queue_config = getStrVal(cbuf, "rx_queue_config", NULL);
    CHECK_CONFIG("rx_queue_config", sk.cfg.rx_queue_config != NULL,
                 "Config Error: rx_queue_config can't be empty");

    conf_err = getIntVal(sk.errstr, cbuf, "port", &sk.cfg.port);
    CHECK_CONF_ERR(conf_err, sk.errstr);

    sk.cfg.data_store = getStrVal(cbuf, "data_store", NULL);
    CHECK_CONFIG("data_store", sk.cfg.data_store != NULL,
                 "Config Error: data_store can't be empty");

    /* if (strcasecmp(sk.cfg.data_store, "file") == 0) { */
    /*     sk.cfg.zone_files_root = getStrVal(cbuf, "zone_files_root", cwd); */
    /*     if (*(sk.cfg.zone_files_root) != '/') { */
    /*         fprintf(stderr, "Config Error: zone_files_root must be an absolute path.\n"); */
    /*         exit(1); */
    /*     } */
    /*     sk.cfg.zone_files_dict = dictCreate(&zoneFileDictType, NULL); */
    /*     if (getBlockVal(sk.errstr, cbuf, "zone_files", &handleZoneFileConf, sk.cfg.zone_files_dict) != CONF_OK) { */
    /*         fprintf(stderr, "Config Error: %s.\n", sk.errstr); */
    /*         exit(1); */
    /*     } */
    /* } else if (strcasecmp(sk.cfg.data_store, "redis") == 0) { */
    /*     sk.cfg.redis_host = getStrVal(cbuf, "redis_host", NULL); */
    /*     conf_err = getIntVal(sk.errstr, cbuf, "redis_port", &sk.cfg.redis_port); */
    /*     CHECK_CONF_ERR(conf_err, sk.errstr); */

    /*     sk.cfg.redis_zone_prefix = getStrVal(cbuf, "redis_zone_prefix", NULL); */
    /*     sk.cfg.redis_soa_prefix = getStrVal(cbuf, "redis_soa_prefix", NULL); */
    /*     sk.cfg.redis_origins_key = getStrVal(cbuf, "redis_origins_key", NULL); */
    /*     conf_err = getLongVal(sk.errstr, cbuf, "redis_retry_interval", &sk.cfg.redis_retry_interval); */
    /*     CHECK_CONF_ERR(conf_err, sk.errstr); */

    /*     CHECK_CONFIG("redis_host", sk.cfg.redis_host != NULL, "redis_host can't be empty"); */
    /*     CHECK_CONFIG("redis_zone_prefix", sk.cfg.redis_zone_prefix != NULL, "redis_zone_prefix can't be empty"); */
    /*     CHECK_CONFIG("redis_soa_prefix", sk.cfg.redis_soa_prefix != NULL, "redis_soa_prefix can't be empty"); */
    /*     CHECK_CONFIG("redis_origins_key", sk.cfg.redis_origins_key != NULL, "redis_origins_key can't be empty"); */

    /* } else if (strcasecmp(sk.cfg.data_store, "mongo") == 0) { */
    /*     sk.cfg.mongo_host = getStrVal(cbuf, "mongo_host", NULL); */
    /*     conf_err = getIntVal(sk.errstr, cbuf, "mongo_port", &sk.cfg.mongo_port); */
    /*     CHECK_CONF_ERR(conf_err, sk.errstr); */

    /*     CHECK_CONFIG("mongo_host", sk.cfg.mongo_host != NULL, NULL); */
    /* } else { */
    /*     fprintf(stderr, "invalid data_store config.\n"); */
    /*     exit(1); */
    /* } */

    conf_err = getIntVal(sk.errstr, cbuf, "tcp_backlog", &sk.cfg.tcp_backlog);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getIntVal(sk.errstr, cbuf, "tcp_keepalive", &sk.cfg.tcp_keepalive);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getIntVal(sk.errstr, cbuf, "tcp_idle_timeout", &sk.cfg.tcp_idle_timeout);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getIntVal(sk.errstr, cbuf, "max_tcp_connections", &sk.cfg.max_tcp_connections);
    CHECK_CONF_ERR(conf_err, sk.errstr);

    conf_err = getIntVal(sk.errstr, cbuf, "num_threads", &sk.cfg.num_threads);
    CHECK_CONF_NOT_OK(conf_err, sk.errstr);
    CHECK_CONFIG("num_threads", sk.cfg.num_threads > 0,
                 "num_thread must be a positive integer.");

    sk.cfg.thread_affinity = getStrVal(cbuf, "thread_affinity", NULL);

    sk.cfg.pidfile = getStrVal(cbuf, "pidfile", "/var/run/cdns.pid");
    conf_err = getBoolVal(sk.errstr, cbuf, "enable_query_log", &sk.cfg.enable_query_log);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    sk.cfg.query_log_file = getStrVal(cbuf, "query_log_file", NULL);
    sk.cfg.logfile = getStrVal(cbuf, "logfile", "");

    conf_err = getBoolVal(sk.errstr, cbuf, "log_verbose", &sk.cfg.logVerbose);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getBoolVal(sk.errstr, cbuf, "daemonize", &sk.cfg.daemonize);
    CHECK_CONF_ERR(conf_err, sk.errstr);

    sk.cfg.logLevelStr = getStrVal(cbuf, "loglevel", "info");

    sk.cfg.admin_host = getStrVal(cbuf, "admin_host", NULL);
    conf_err = getIntVal(sk.errstr, cbuf, "admin_port", &sk.cfg.admin_port);
    CHECK_CONF_ERR(conf_err, sk.errstr);

    conf_err = getIntVal(sk.errstr, cbuf, "all_reload_interval", &sk.cfg.all_reload_interval);
    CHECK_CONF_ERR(conf_err, sk.errstr);
    conf_err = getBoolVal(sk.errstr, cbuf, "minimize_resp", &sk.cfg.minimize_resp);
    CHECK_CONF_ERR(conf_err, sk.errstr);

    free(cbuf);
}

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
               signum);
        sk.force_quit = true;
    }
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    sk.force_quit = false;
    initConfig(argc, argv);
    initDpdkModule();
    cleanupDpdkModule();
}
