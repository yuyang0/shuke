//
// Created by yangyu on 17-11-14.
//

#ifndef SHUKE_ZTREE_H
#define SHUKE_ZTREE_H

struct dname {
    uint8_t name_size;   // doesn't include last '\0'
    uint8_t label_count;
    char *name;
    uint8_t label_offset[64];
};

typedef struct _ztreeNode {
    int socket_id;
    char *label;
    zone *z;
    struct cds_lfht *children;

    struct cds_lfht_node htnode;
    struct rcu_head rcu_head;
    struct _ztreeNode *parent;
} ztreeNode;

typedef struct _ztree {
    int socket_id;
    int nb_zone;

    ztreeNode *root;
} ztree;

#define ztreeRLock(zt) rcu_read_lock()
#define ztreeRUnlock(zt) rcu_read_unlock()
#define ztreeWLock(zt) rcu_read_lock()
#define ztreeWUnlock(zt) rcu_read_unlock()


static inline void
makeDname(char *name, struct dname *dn) {
    dn->name = name;
    dn->label_count = 0;
    char *ptr;
    for (ptr = name; *ptr != 0; ptr += (*ptr+1)) {
        dn->label_offset[dn->label_count++] = (uint8_t )(ptr-name);
    }
    dn->name_size = (uint8_t)(ptr-name);
}

/*----------------------------------------------
 *     zone tree declaration
 *---------------------------------------------*/
int ztreeHtMatch(struct cds_lfht_node *ht_node, const void *_key);
void ztreeFreeCallback(struct rcu_head *head);

unsigned int ztreeHash(char *buf, size_t len);
ztree *ztreeCreate(int socket_id);

void ztreeDestroy(ztree *zt);

zone *ztreeGetZone(ztree *zt, struct dname *dn);
zone *ztreeGetZoneExact(ztree *zt, struct dname *dn);

static inline zone *
ztreeGetZoneRaw(ztree *zt, char *origin) {
    struct dname dn;
    makeDname(origin, &dn);
    return ztreeGetZone(zt, &dn);
}

static inline zone *
ztreeGetZoneExactRaw(ztree *zt, char *origin) {
    struct dname dn;
    makeDname(origin, &dn);
    return ztreeGetZoneExact(zt, &dn);
}

int ztreeReplaceNoLock(ztree *zt, zone *z);
int ztreeReplace(ztree *zt, zone *z);

int ztreeAdd(ztree *zt, zone *z);

int ztreeDeleteNoLock(ztree *zt, char *origin);
int ztreeDelete(ztree *zt, char *origin);

size_t ztreeGetNumZones(ztree *zt);
int ztreeExistZone(ztree *zt, char *origin);
sds ztreeToStr(ztree *zt);

#endif //SHUKE_ZTREE_H
