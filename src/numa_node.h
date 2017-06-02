//
// Created by yangyu on 17-6-2.
//

#ifndef SHUKE_NUMA_NODE_H
#define SHUKE_NUMA_NODE_H

#include <rte_ring.h>

#include "ds.h"

#define MAX_NUMA_NODES 32

typedef struct numaNode_s {
    zoneDict *zd;
    struct rte_ring *tq;            // task queue, used for async tasks
} numaNode_t;


#endif //SHUKE_NUMA_NODE_H
