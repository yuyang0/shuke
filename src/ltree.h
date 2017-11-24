//
// Created by yangyu on 17-11-14.
//

#ifndef SHUKE_LTREE_H
#define SHUKE_LTREE_H

/*
 * label tree implementation
 * every node contains an hash table to track the children.
 */
struct dname {
    uint8_t name_size;   // doesn't include last '\0'
    uint8_t label_count;
    char *name;
    uint8_t label_offset[64];
};

typedef struct _ltreeNode {
    int socket_id;
    char *label;
    zone *z;
    struct cds_lfht *children;

    struct cds_lfht_node htnode;
    struct rcu_head rcu_head;
    struct _ltreeNode *parent;
} ltreeNode;

typedef struct _ltree {
    int socket_id;
    int nb_zone;

    ltreeNode *root;
} ltree;

#define ltreeRLock(zt) rcu_read_lock()
#define ltreeRUnlock(zt) rcu_read_unlock()
#define ltreeWLock(zt) rcu_read_lock()
#define ltreeWUnlock(zt) rcu_read_unlock()


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
 *     label tree declaration
 *---------------------------------------------*/
int ltreeHtMatch(struct cds_lfht_node *ht_node, const void *_key);
void ltreeFreeCallback(struct rcu_head *head);

unsigned int ltreeHash(char *buf, size_t len);
ltree *ltreeCreate(int socket_id);

void ltreeDestroy(ltree *lt);

zone *ltreeGetZone(ltree *lt, struct dname *dn);
zone *ltreeGetZoneExact(ltree *lt, struct dname *dn);

static inline zone *
ltreeGetZoneRaw(ltree *lt, char *origin) {
    struct dname dn;
    makeDname(origin, &dn);
    return ltreeGetZone(lt, &dn);
}

static inline zone *
ltreeGetZoneExactRaw(ltree *lt, char *origin) {
    struct dname dn;
    makeDname(origin, &dn);
    return ltreeGetZoneExact(lt, &dn);
}

int ltreeReplaceNoLock(ltree *lt, zone *z);
int ltreeReplace(ltree *lt, zone *z);

int ltreeAdd(ltree *lt, zone *z);

int ltreeDeleteNoLock(ltree *lt, char *origin);
int ltreeDelete(ltree *lt, char *origin);

size_t ltreeGetNumZones(ltree *lt);
int ltreeExistZone(ltree *lt, char *origin);
sds ltreeToStr(ltree *lt);

#endif //SHUKE_LTREE_H
