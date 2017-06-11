//
// Created by yangyu on 6/11/17.
//
#include "shuke.h"

replicateLog *replicateLogCreate(int type, char *origin, zone *z) {
    replicateLog *l = zmalloc(sizeof(*l));
    l->type = type;
    l->z = z;
    l->origin = origin;
    return l;
}

void replicateDestroy(replicateLog *l) {
    if (!l) return;
    zfree(l);
}

void processReplicateLog() {
    zone *new_z;
    replicateLog *l;
    while (rte_ring_sc_dequeue(CUR_NODE->tq, (void **)&l) == 0) {
        switch (l->type) {
            case REPLICATE_ADD:
                new_z = zoneCopy(l->z);
                zoneDictReplace(CUR_NODE->zd, new_z);
                break;
            case REPLICATE_DEL:
                zoneDictDelete(CUR_NODE->zd, l->origin);
                break;
        }
    }
}
