//
// Created by yangyu on 17-11-14.
//
#include <string.h>
#include "log.h"
#include "dnspacket.h"
#include "ltree.h"
#include "zmalloc.h"


/*----------------------------------------------
 *     label tree definition
 *---------------------------------------------*/
static ltreeNode *ltreeNodeCreate(int socket_id, char *label) {
    ltreeNode *lnode = socket_calloc(socket_id, 1, sizeof(*lnode));
    long l_socket_id = (long)socket_id;
    int max_table_order = (sizeof(long) == 8)? 64 : 32;
    lnode->children = cds_lfht_new_priv(1, 1, 1UL << (max_table_order - 1),
                                        CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
                                        &cds_lfht_mm_socket, NULL, (void*)l_socket_id);
    int label_len = *label;
    lnode->label = socket_calloc(socket_id, 1, label_len+2);
    rte_memcpy(lnode->label, label, label_len+1);
    lnode->socket_id = socket_id;
    return lnode;
}

static void ltreeNodeDestroy(ltreeNode *lnode) {
    if (lnode->label) {
        socket_free(lnode->socket_id, lnode->label);
    }
    if (lnode->z) {
        zoneDestroy(lnode->z);
    }
    if (lnode->children) {
        int ret;
        struct cds_lfht_iter iter;	/* For iteration on hash table */
        struct cds_lfht_node *ht_node;
        struct cds_lfht *ht = lnode->children;
        ltreeNode *child;
        cds_lfht_for_each_entry(ht, &iter, child, htnode) {
            ht_node = cds_lfht_iter_get_node(&iter);
            ret = cds_lfht_del(ht, ht_node);
            if (!ret) {
                call_rcu(&child->rcu_head, ltreeFreeCallback);
            }
        }
        int err = cds_lfht_destroy(lnode->children, NULL);
        if (err) {
            LOG_ERR(USER1, "destroy cru hash table failed.");
        }
    }
    socket_free(lnode->socket_id, lnode);
}

static void ltreeNodeSetParent(ltreeNode *lnode, ltreeNode *parent) {
    lnode->parent = parent;
}

int ltreeHtMatch(struct cds_lfht_node *ht_node, const void *_key)
{
    ltreeNode *lnode = caa_container_of(ht_node, ltreeNode, htnode);
    const char *key = _key;
    uint8_t label_len = (uint8_t)*key;
    return strncasecmp(lnode->label, key, label_len+1) == 0;
}

void ltreeFreeCallback(struct rcu_head *head)
{
    ltreeNode *lnode = caa_container_of(head, ltreeNode, rcu_head);
    ltreeNodeDestroy(lnode);
}

static void *rcu_ht_fetch_value(struct cds_lfht *ht, void *_key) {
    struct cds_lfht_iter iter;	/* For iteration on hash table */
    struct cds_lfht_node *ht_node;
    char *label = _key;
    uint8_t label_len = (uint8_t )*label;
    unsigned int hash = ltreeHash(label, label_len + 1);
    cds_lfht_lookup(ht, hash, ltreeHtMatch, label, &iter);
    ht_node = cds_lfht_iter_get_node(&iter);
    if (!ht_node) {
        return NULL;
    } else {
        return caa_container_of(ht_node, ltreeNode, htnode);
    }
}

/* case insensitive hash function (based on djb hash) */
unsigned int ltreeHash(char *buf, size_t len) {
    unsigned int hash = (unsigned int)5381;

    while (len--)
        hash = ((hash << 5) + hash) + (tolower(*buf++)); /* hash * 33 + c */
    return hash;
}

ltree *ltreeCreate(int socket_id) {
    ltree *lt = socket_calloc(socket_id, 1, sizeof(*lt));
    lt->root = ltreeNodeCreate(socket_id, "");
    ltreeNodeSetParent(lt->root, lt->root);
    lt->socket_id = socket_id;
    return lt;
}

void ltreeDestroy(ltree *lt) {
    ltreeWLock(lt);
    ltreeNodeDestroy(lt->root);
    ltreeWUnlock(lt);

    socket_free(lt->socket_id, lt);
}

/*!
 * this function fetch the zone this name belongs to, so it will iterate parent domain.
 *
 * Notice: since this function didn't acquire rlock,
 *         so the rlock must be acquired in caller.
 *
 * @param lt : ltree instance
 * @param dn : nane in len label format
 * @return
 */
zone *ltreeGetZone(ltree *lt, struct dname *dn) {
    ltreeNode *lnode = NULL, *parent_lnode;
    zone *z = NULL;
    int max_count = dn->label_count;
    parent_lnode = lt->root;

    for (int i = max_count-1; i >= 0; i--) {
        char *label = dn->name + dn->label_offset[i];
        LOG_DEBUG(USER1, "get zone exact: label %s, %d", label, label[0]);

        lnode = rcu_ht_fetch_value(parent_lnode->children, label);
        if (lnode == NULL) break;
        if (lnode->z != NULL) z = lnode->z;
        parent_lnode = lnode;
    }
    return z;
}

/*!
 * same as ltreeGetZone, except this function fetches the zone whose origin is equal to dname exactly,
 *
 * Notice: since this function didn't acquire rlock,
 *         so the rlock must be acquired in caller.
 * @param lt
 * @param dn
 * @return
 */
zone *ltreeGetZoneExact(ltree *lt, struct dname *dn) {
    ltreeNode *lnode = NULL, *parent_lnode;
    zone *z = NULL;
    int max_count = dn->label_count;

    parent_lnode = lt->root;
    for (int i = max_count-1; i >= 0; i--) {
        char *label = dn->name + dn->label_offset[i];

        LOG_DEBUG(USER1, "get zone exact: label %s, %d", label, label[0]);
        lnode = rcu_ht_fetch_value(parent_lnode->children, label);
        if (lnode == NULL) break;
        parent_lnode = lnode;
        if (i == 0) {
            z = lnode->z;
        }
    }
    return z;
}

/* Add a zone, discarding the old if the key already exists.
 * Return 1 if the key was added from scratch, 0 if there was already an
 * element with such key and dictReplace() just performed a value update
 * operation. */
int ltreeReplaceNoLock(ltree *lt, zone *z) {
    struct dname dn;
    makeDname(z->origin, &dn);
    int err = 1;
    int max_count = dn.label_count;


    struct cds_lfht *ht = NULL;
    ltreeNode *lnode = NULL;
    ltreeNode *parent_lnode = lt->root;
    for (int i = max_count-1; i >= 0; i--) {
        char *label = dn.name + dn.label_offset[i];
        ht = parent_lnode->children;
        lnode = rcu_ht_fetch_value(ht, label);
        if (lnode == NULL) {
            struct cds_lfht_node *htnode;
            int label_len = *label;
            unsigned int hash = ltreeHash(label, label_len + 1);
            lnode = ltreeNodeCreate(lt->socket_id, label);
            ltreeNodeSetParent(lnode, parent_lnode);

            htnode = cds_lfht_add_unique(ht, hash, ltreeHtMatch, label, &lnode->htnode);
            if (htnode != &lnode->htnode) {
                return DICT_ERR;
            }
        }
        if (i == 0) {
            if (lnode->z == NULL) {
                lnode->z = z;
                lt->nb_zone++;
            } else {
                struct cds_lfht_node *ht_node;
                int label_len = *label;
                unsigned int hash = ltreeHash(label, label_len + 1);
                ltreeNode *new_lnode = socket_malloc(lt->socket_id, sizeof(ltreeNode));
                memcpy(new_lnode, lnode, sizeof(ltreeNode));
                new_lnode->z = z;
                cds_lfht_node_init(&new_lnode->htnode);

                ht_node = cds_lfht_add_replace(ht, hash, ltreeHtMatch, label, &new_lnode->htnode);
                ltreeNode *old_node = caa_container_of(ht_node, ltreeNode, htnode);
                assert(old_node == lnode);
                old_node->label = NULL;
                old_node->children = NULL;
                call_rcu(&old_node->rcu_head, ltreeFreeCallback);
                err = 0;
            }
        }
        parent_lnode = lnode;
    }
    return err;
}

int ltreeReplace(ltree *lt, zone *z) {
    ltreeWLock(lt);
    int err = ltreeReplaceNoLock(lt, z);
    ltreeWUnlock(lt);
    return err;
}

int ltreeAdd(ltree *lt, zone *z) {
    struct dname dn;
    makeDname(z->origin, &dn);
    int err = DICT_OK;
    ltreeNode *lnode = NULL, *parent_lnode = NULL;
    struct cds_lfht *ht;
    int max_count = dn.label_count;

    ltreeWLock(lt);

    parent_lnode = lt->root;
    for (int i = max_count-1; i >= 0; i--) {
        char *label = dn.name + dn.label_offset[i];
        ht = parent_lnode->children;

        lnode = rcu_ht_fetch_value(ht, label);
        if (lnode == NULL) {
            struct cds_lfht_node *htnode;
            int label_len = *label;
            unsigned int hash = ltreeHash(label, label_len + 1);
            lnode = ltreeNodeCreate(lt->socket_id, label);
            ltreeNodeSetParent(lnode, parent_lnode);

            htnode = cds_lfht_add_unique(ht, hash, ltreeHtMatch, label, &lnode->htnode);
            assert(htnode == &lnode->htnode);
        }
        parent_lnode = lnode;
        if (i == 0) {
            if (lnode->z == NULL) {
                lnode->z = z;
                lt->nb_zone++;
            } else {
                err = DICT_ERR;
            }
        }
    }
    ltreeWUnlock(lt);
    return err;
}

int ltreeDeleteNoLock(ltree *lt, char *origin) {
    struct dname dn;
    makeDname(origin, &dn);
    int err = DICT_OK;
    ltreeNode *lnode = NULL, *parent_lnode=NULL;
    struct cds_lfht *ht;
    int max_count = dn.label_count;

    parent_lnode = lt->root;
    for (int i = max_count-1; i >= 0; i--) {
        char *label = dn.name + dn.label_offset[i];
        ht = parent_lnode->children;

        lnode = rcu_ht_fetch_value(ht, label);
        if (lnode == NULL) {
            err = DICT_ERR;
            break;
        }
        if (i == 0) {
            if (lnode->z == NULL) {
                err = DICT_ERR;
            } else {
                struct cds_lfht_node *ht_node;
                int label_len = *label;
                unsigned int hash = ltreeHash(label, label_len + 1);
                ltreeNode *new_lnode = socket_malloc(lt->socket_id, sizeof(ltreeNode));
                memcpy(new_lnode, lnode, sizeof(ltreeNode));
                new_lnode->z = NULL;
                cds_lfht_node_init(&new_lnode->htnode);

                ht_node = cds_lfht_add_replace(ht, hash, ltreeHtMatch, label, &new_lnode->htnode);
                ltreeNode *old_node = caa_container_of(ht_node, ltreeNode, htnode);
                assert(old_node == lnode);
                old_node->label = NULL;
                old_node->children = NULL;
                call_rcu(&old_node->rcu_head, ltreeFreeCallback);
                lt->nb_zone--;
                err = DICT_OK;
            }
        }
        parent_lnode = lnode;
    }
    return err;
}

int ltreeDelete(ltree *lt, char *origin) {
    ltreeWLock(lt);
    int err = ltreeDeleteNoLock(lt, origin);
    ltreeWUnlock(lt);
    return err;
}

int ltreeExistZone(ltree *lt, char *origin) {
    int ret;
    struct dname dn;
    makeDname(origin, &dn);

    ltreeRLock(lt);
    ret = (ltreeGetZoneExact(lt, &dn) != NULL);
    ltreeRUnlock(lt);
    return ret;
}

size_t ltreeGetNumZones(ltree *lt) {
    int count;
    ltreeRLock(lt);
    count = lt->nb_zone;
    ltreeRUnlock(lt);
    return (size_t)count;
}

// may lock the dict long time, mainly for debug.
static sds ltreeNodeToStr(ltreeNode *lnode, sds s) {
    struct cds_lfht_iter iter;	/* For iteration on hash table */
    sds zone_s;
    struct cds_lfht *ht = lnode->children;
    cds_lfht_for_each_entry(ht, &iter, lnode, htnode) {
        if (lnode->z) {
            zone_s = zoneToStr(lnode->z);
            s = sdscatsds(s, zone_s);
            sdsfree(zone_s);
            LOG_DEBUG(USER1, "label: %s %d", lnode->label, strlen(lnode->label));
        }
        s = ltreeNodeToStr(lnode, s);
    }
    return s;
}

sds ltreeToStr(ltree *lt) {
    sds s = sdsempty();

    ltreeRLock(lt);
    s = ltreeNodeToStr(lt->root, s);
    ltreeRUnlock(lt);
    return s;
}
