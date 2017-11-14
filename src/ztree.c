//
// Created by yangyu on 17-11-14.
//
#include <string.h>
#include "log.h"
#include "ds.h"
#include "ztree.h"
#include "zmalloc.h"


/*----------------------------------------------
 *     zone tree definition
 *---------------------------------------------*/
static ztreeNode *ztreeNodeCreate(int socket_id, char *label) {
    ztreeNode *znode = socket_calloc(socket_id, 1, sizeof(*znode));
    long l_socket_id = (long)socket_id;
    int max_table_order = (sizeof(long) == 8)? 64 : 32;
    znode->children = cds_lfht_new_priv(1, 1, 1UL << (max_table_order - 1),
                                        CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
                                        &cds_lfht_mm_socket, NULL, (void*)l_socket_id);
    int label_len = *label;
    znode->label = socket_calloc(socket_id, 1, label_len+2);
    rte_memcpy(znode->label, label, label_len+1);
    znode->socket_id = socket_id;
    return znode;
}

static void ztreeNodeDestroy(ztreeNode *znode) {
    if (znode->label) {
        socket_free(znode->socket_id, znode->label);
    }
    if (znode->z) {
        zoneDestroy(znode->z);
    }
    if (znode->children) {
        int ret;
        struct cds_lfht_iter iter;	/* For iteration on hash table */
        struct cds_lfht_node *ht_node;
        struct cds_lfht *ht = znode->children;
        ztreeNode *child;
        cds_lfht_for_each_entry(ht, &iter, child, htnode) {
            ht_node = cds_lfht_iter_get_node(&iter);
            ret = cds_lfht_del(ht, ht_node);
            if (!ret) {
                call_rcu(&child->rcu_head, ztreeFreeCallback);
            }
        }
        int err = cds_lfht_destroy(znode->children, NULL);
        if (err) {
            LOG_ERR(USER1, "destroy cru hash table failed.");
        }
    }
    socket_free(znode->socket_id, znode);
}

static void ztreeNodeSetParent(ztreeNode *znode, ztreeNode *parent) {
    znode->parent = parent;
}

int ztreeHtMatch(struct cds_lfht_node *ht_node, const void *_key)
{
    ztreeNode *znode = caa_container_of(ht_node, ztreeNode, htnode);
    const char *key = _key;
    uint8_t label_len = (uint8_t)*key;
    return strncasecmp(znode->label, key, label_len+1) == 0;
}

void ztreeFreeCallback(struct rcu_head *head)
{
    ztreeNode *znode = caa_container_of(head, ztreeNode, rcu_head);
    ztreeNodeDestroy(znode);
}

static void *rcu_ht_fetch_value(struct cds_lfht *ht, void *_key) {
    struct cds_lfht_iter iter;	/* For iteration on hash table */
    struct cds_lfht_node *ht_node;
    char *label = _key;
    uint8_t label_len = (uint8_t )*label;
    unsigned int hash = ztreeHash(label, label_len+1);
    cds_lfht_lookup(ht, hash, ztreeHtMatch, label, &iter);
    ht_node = cds_lfht_iter_get_node(&iter);
    if (!ht_node) {
        return NULL;
    } else {
        return caa_container_of(ht_node, ztreeNode, htnode);
    }
}

/* case insensitive hash function (based on djb hash) */
unsigned int ztreeHash(char *buf, size_t len) {
    unsigned int hash = (unsigned int)5381;

    while (len--)
        hash = ((hash << 5) + hash) + (tolower(*buf++)); /* hash * 33 + c */
    return hash;
}

ztree *ztreeCreate(int socket_id) {
    ztree *zt = socket_calloc(socket_id, 1, sizeof(*zt));
    zt->root = ztreeNodeCreate(socket_id, "");
    ztreeNodeSetParent(zt->root, zt->root);
    zt->socket_id = socket_id;
    return zt;
}

void ztreeDestroy(ztree *zt) {
    ztreeWLock(zt);
    ztreeNodeDestroy(zt->root);
    ztreeWUnlock(zt);

    socket_free(zt->socket_id, zt);
}

/*!
 * this function fetch the zone this name belongs to, so it will iterate parent domain.
 *
 * Notice: since this function didn't acquire rlock,
 *         so the rlock must be acquired in caller.
 *
 * @param zt : ztree instance
 * @param dn : nane in len label format
 * @return
 */
zone *ztreeGetZone(ztree *zt, struct dname *dn) {
    ztreeNode *znode = NULL, *parent_znode;
    zone *z = NULL;
    int max_count = dn->label_count;
    parent_znode = zt->root;

    for (int i = max_count-1; i >= 0; i--) {
        char *label = dn->name + dn->label_offset[i];
        LOG_DEBUG(USER1, "get zone exact: label %s, %d", label, label[0]);

        znode = rcu_ht_fetch_value(parent_znode->children, label);
        if (znode == NULL) break;
        if (znode->z != NULL) z = znode->z;
        parent_znode = znode;
    }
    return z;
}

/*!
 * same as ztreeGetZone, except this function fetches the zone whose origin is equal to dname exactly,
 *
 * Notice: since this function didn't acquire rlock,
 *         so the rlock must be acquired in caller.
 * @param zt
 * @param dn
 * @return
 */
zone *ztreeGetZoneExact(ztree *zt, struct dname *dn) {
    ztreeNode *znode = NULL, *parent_znode;
    zone *z = NULL;
    int max_count = dn->label_count;

    parent_znode = zt->root;
    for (int i = max_count-1; i >= 0; i--) {
        char *label = dn->name + dn->label_offset[i];

        LOG_DEBUG(USER1, "get zone exact: label %s, %d", label, label[0]);
        znode = rcu_ht_fetch_value(parent_znode->children, label);
        if (znode == NULL) break;
        parent_znode = znode;
        if (i == 0) {
            z = znode->z;
        }
    }
    return z;
}

/* Add a zone, discarding the old if the key already exists.
 * Return 1 if the key was added from scratch, 0 if there was already an
 * element with such key and dictReplace() just performed a value update
 * operation. */
int ztreeReplaceNoLock(ztree *zt, zone *z) {
    struct dname dn;
    makeDname(z->origin, &dn);
    int err = 1;
    int max_count = dn.label_count;


    struct cds_lfht *ht = NULL;
    ztreeNode *znode = NULL;
    ztreeNode *parent_znode = zt->root;
    for (int i = max_count-1; i >= 0; i--) {
        char *label = dn.name + dn.label_offset[i];
        ht = parent_znode->children;
        znode = rcu_ht_fetch_value(ht, label);
        if (znode == NULL) {
            struct cds_lfht_node *htnode;
            int label_len = *label;
            unsigned int hash = ztreeHash(label, label_len+1);
            znode = ztreeNodeCreate(zt->socket_id, label);
            ztreeNodeSetParent(znode, parent_znode);

            htnode = cds_lfht_add_unique(ht, hash, ztreeHtMatch, label, &znode->htnode);
            if (htnode != &znode->htnode) {
                return DICT_ERR;
            }
        }
        if (i == 0) {
            if (znode->z == NULL) {
                znode->z = z;
                zt->nb_zone++;
            } else {
                struct cds_lfht_node *ht_node;
                int label_len = *label;
                unsigned int hash = ztreeHash(label, label_len+1);
                ztreeNode *new_znode = socket_malloc(zt->socket_id, sizeof(ztreeNode));
                memcpy(new_znode, znode, sizeof(ztreeNode));
                new_znode->z = z;
                cds_lfht_node_init(&new_znode->htnode);

                ht_node = cds_lfht_add_replace(ht, hash, ztreeHtMatch, label, &new_znode->htnode);
                ztreeNode *old_node = caa_container_of(ht_node, ztreeNode, htnode);
                assert(old_node == znode);
                old_node->label = NULL;
                old_node->children = NULL;
                call_rcu(&old_node->rcu_head, ztreeFreeCallback);
                err = 0;
            }
        }
        parent_znode = znode;
    }
    return err;
}

int ztreeReplace(ztree *zt, zone *z) {
    ztreeWLock(zt);
    int err = ztreeReplaceNoLock(zt, z);
    ztreeWUnlock(zt);
    return err;
}

int ztreeAdd(ztree *zt, zone *z) {
    struct dname dn;
    makeDname(z->origin, &dn);
    int err = DICT_OK;
    ztreeNode *znode = NULL, *parent_znode = NULL;
    struct cds_lfht *ht;
    int max_count = dn.label_count;

    ztreeWLock(zt);

    parent_znode = zt->root;
    for (int i = max_count-1; i >= 0; i--) {
        char *label = dn.name + dn.label_offset[i];
        ht = parent_znode->children;

        znode = rcu_ht_fetch_value(ht, label);
        if (znode == NULL) {
            struct cds_lfht_node *htnode;
            int label_len = *label;
            unsigned int hash = ztreeHash(label, label_len+1);
            znode = ztreeNodeCreate(zt->socket_id, label);
            ztreeNodeSetParent(znode, parent_znode);

            htnode = cds_lfht_add_unique(ht, hash, ztreeHtMatch, label, &znode->htnode);
            assert(htnode == &znode->htnode);
        }
        parent_znode = znode;
        if (i == 0) {
            if (znode->z == NULL) {
                znode->z = z;
                zt->nb_zone++;
            } else {
                err = DICT_ERR;
            }
        }
    }
    ztreeWUnlock(zt);
    return err;
}

int ztreeDeleteNoLock(ztree *zt, char *origin) {
    struct dname dn;
    makeDname(origin, &dn);
    int err = DICT_OK;
    ztreeNode *znode = NULL, *parent_znode=NULL;
    struct cds_lfht *ht;
    int max_count = dn.label_count;

    parent_znode = zt->root;
    for (int i = max_count-1; i >= 0; i--) {
        char *label = dn.name + dn.label_offset[i];
        ht = parent_znode->children;

        znode = rcu_ht_fetch_value(ht, label);
        if (znode == NULL) {
            err = DICT_ERR;
            break;
        }
        if (i == 0) {
            if (znode->z == NULL) {
                err = DICT_ERR;
            } else {
                struct cds_lfht_node *ht_node;
                int label_len = *label;
                unsigned int hash = ztreeHash(label, label_len+1);
                ztreeNode *new_znode = socket_malloc(zt->socket_id, sizeof(ztreeNode));
                memcpy(new_znode, znode, sizeof(ztreeNode));
                new_znode->z = NULL;
                cds_lfht_node_init(&new_znode->htnode);

                ht_node = cds_lfht_add_replace(ht, hash, ztreeHtMatch, label, &new_znode->htnode);
                ztreeNode *old_node = caa_container_of(ht_node, ztreeNode, htnode);
                assert(old_node == znode);
                old_node->label = NULL;
                old_node->children = NULL;
                call_rcu(&old_node->rcu_head, ztreeFreeCallback);
                zt->nb_zone--;
                err = DICT_OK;
            }
        }
        parent_znode = znode;
    }
    return err;
}

int ztreeDelete(ztree *zt, char *origin) {
    ztreeWLock(zt);
    int err = ztreeDeleteNoLock(zt, origin);
    ztreeWUnlock(zt);
    return err;
}

int ztreeExistZone(ztree *zt, char *origin) {
    int ret;
    struct dname dn;
    makeDname(origin, &dn);

    ztreeRLock(zt);
    ret = (ztreeGetZoneExact(zt, &dn) != NULL);
    ztreeRUnlock(zt);
    return ret;
}

size_t ztreeGetNumZones(ztree *zt) {
    int count;
    ztreeRLock(zt);
    count = zt->nb_zone;
    ztreeRUnlock(zt);
    return (size_t)count;
}

// may lock the dict long time, mainly for debug.
static sds ztreeNodeToStr(ztreeNode *znode, sds s) {
    struct cds_lfht_iter iter;	/* For iteration on hash table */
    sds zone_s;
    struct cds_lfht *ht = znode->children;
    cds_lfht_for_each_entry(ht, &iter, znode, htnode) {
        if (znode->z) {
            zone_s = zoneToStr(znode->z);
            s = sdscatsds(s, zone_s);
            sdsfree(zone_s);
            LOG_DEBUG(USER1, "label: %s %d", znode->label, strlen(znode->label));
        }
        s = ztreeNodeToStr(znode, s);
    }
    return s;
}

sds ztreeToStr(ztree *zt) {
    sds s = sdsempty();

    ztreeRLock(zt);
    s = ztreeNodeToStr(zt->root, s);
    ztreeRUnlock(zt);
    return s;
}
