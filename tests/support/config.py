default_cfg = {
    "coremask":  "0xf0f",
    "master_lcore_id":  0,

    "mem_channels":  4,
    "portmask":  0x3,
    "promiscuous_on": "no",
    "numa_on": "yes",
    "jumbo_on": "no",
    "max_pkt_len": 2048,
    # Rx queue configuration (port, queue, lcore)
    "rx_queue_config": "(0,0,1),(0,1,2),(0,2,3),(0,3,8),(0,4,9)(0,5,10),(0,6,11),(1,0,1),(1,1,2),(1,2,3),(1,3,8),(1,4,9)(1,5,10),(1,6,11)",

    # kni tx config (port,lcore)
    "kni_tx_config": "(0,14),(1,14)",

    # core for kni kernel (port,lcore). optional
    "kni_kernel_config": "(0,15),(1,15)",

    "bind":  [
        "192.168.0.110",
        "192.168.10.110"
    ],
    # in production environment, use 53
    "port": 19899,

    "tcp_backlog":    511,
    "tcp_keepalive":    300,

    # timeout used to close idle tcp connection.
    "tcp_idle_timeout": 120,

    "daemonize": "yes",

    "pidfile": "/var/run/shuke_53.pid",

    "query_log_file": "stdout",

    "loglevel":  "debug",
    "logfile":   "/tmp/shuke.log",
    # logging the file and line information.
    "log_verbose": "no",

    # zone_files_root "/usr/"
    "zone_files": {
        # "example.com.":  "../tests/assets/example.z",
    },

    # interval between the connect retry to mongo
    # used to avoid connecting to mongo too often when mongo fails.
    "retry_interval": 120,

    # the valid values are "file", "mongo"
    "data_store":  "mongo",
    "mongo_host": "127.0.0.1",
    "mongo_port": 27017,
    "mongo_dbname": "zone",

    # address for tcp server runs in main thread,
    # this server mainly used to debug or perform admin.
    "admin_host": "127.0.0.1",
    "admin_port": 14141,

    "all_reload_interval": 36000,  # 10 hours
    "minimize_resp": "yes"
}
