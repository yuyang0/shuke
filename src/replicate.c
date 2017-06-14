//
// Created by yangyu on 6/11/17.
//
#include <assert.h>
#include "shuke.h"

replicateLog *replicateLogCreate(int type, char *origin, zone *z) {
    replicateLog *l = zmalloc(sizeof(*l));
    l->type = type;
    l->z = z;
    snprintf(l->origin, sizeof(l->origin), "%s", origin);
    return l;
}

void replicateDestroy(replicateLog *l) {
    if (!l) return;
    zfree(l);
}

void processReplicateLog() {
    replicateLog *l;
    while (rte_ring_sc_dequeue(CUR_NODE->tq, (void **)&l) == 0) {
        switch (l->type) {
            case REPLICATE_ADD:
                assert(l->z != NULL);
                zoneDictReplace(CUR_NODE->zd, l->z);
                break;
            case REPLICATE_DEL:
                zoneDictDelete(CUR_NODE->zd, l->origin);
                break;
        }
        replicateDestroy(l);
    }
}
