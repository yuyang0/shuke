# SHUKE
An authority dns server implemented with DPDK

# Features
1. support storing RR in mongodb
2. high performance

# buid
1. build dpdk, shuke is only tested in dpdk-16.11.1.
2. run `make` at the top of source tree, then you will get a binary file named `build/shuke-server`.

# run
just run `build/shuke-server -c conf/shuke.conf`, 
you may need to change the config in the config file.

# redis data schema
redis should contain four type of map: origin map, zone map,
SOA map and rrset map.

## origin map
this map is used to track all the zone origins

1. `key` is `redis_origins_key`, you can change its value using `redis_origins_key` option in config file.
2. `value` is a **set** of origin names. origin name is in
    `<label dot>` format and should be absolute domain name.

## zone map
this map is used to track the subdomains of every zone.

1. `key` is `redis_zone_prefix:origin`, origin should in `<label dot>`
    format and should be an absolute domain name(ends with dot),
    `redis_zone_prefix` is used to avoid duplication, you
    can specify its value using `redis_zone_prefix` option in
    configure file.
2. `value` should be a **set** of absolute or relative domain
    names belong to this zone.

## SOA map
in order to quickly check if a zone needs reload, redis should store
a special k/v pair for every zone.

1. `key` is `redis_soa_prefix:origin`. you can change the value of `redis_soa_prefix`
   using `redis_soa_prefix` option in configure file.
2. `value` is the SOA record of zone.

## RRSet map
this map is used to track the resource records associated with domain names.

1. `key` should be the domain name, must be absolute domain name,
    it also should in <label dot> format and should be a absolute name.
2. `value` should be an array of bulk string,
    every bulk string should has the format like following:

         ttl class type rdata

    the format is same with the zone file. **ttl is required, class is optional**.

**NOTICE: since data consistency is very important, so it is recommended to use redis transaction to update these maps**

# mongo data schema
every zone should have a collection in mongodb.

## zone collection
this collection used to track the RR of a zone, 
the collection name is the domain of the zone, since mongodb's
collection name can't end with dot, so the domain should be the
absolute domain name except the last dot.
the collection should contain the following fields

    {
        name: "the absulute owner name,
        ttl: 1234567,
        type: "DNS type",
        rdata: "rdata"
    }
    
the meaning of fields is clear. just like the zone file.

# Admin Commands
SHUKE has admin tcp server used to execute admin operations
 
1. `zone`: this command used to manipulate the zone data in memory, it has many subcommands.
    1. `get`: get a zone
    2. `getall`: get all zones
    3. `set`: set a zone
    4. `delete`: delete a zone
    5. `flushall`: delete all zone
    6. `reload`: reload  multiple zone
    7. `reloadall`: reload all zone
    8. `get_numzones`: return the number of zones in memory cache.
2. `config`: this command is used to manipulate the config of server.
3. `version`: return version of shuke
4. `debug`: mainly for debug
    1. `segfault`: cause a segement fault
    2. `oom`: trigger a OOM error.
5. `info`: print information of server, including statistics. subcommands
    1. `all` or `default` or empty: return all information
    2. `server`: return the server information
    3. `memory`: return memory usage information
    4. `cpu`: return cpu usage information
    5. `stats`: statistics information
