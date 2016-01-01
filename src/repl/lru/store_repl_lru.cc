/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: none          LRU Removal Policy */

#include "squid.h"
#include "MemObject.h"
#include "SquidTime.h"
#include "Store.h"

/* because LruNode use explicit memory alloc()/freeOne() calls.
 * XXX: convert to MEMPROXY_CLASS() API
 */
#include "mem/Pool.h"

REMOVALPOLICYCREATE createRemovalPolicy_lru;

struct LruPolicyData {
    void setPolicyNode (StoreEntry *, void *) const;
    RemovalPolicy *policy;
    dlink_list list;
    int count;
    int nwalkers;
    enum heap_entry_type {
        TYPE_UNKNOWN = 0, TYPE_STORE_ENTRY, TYPE_STORE_MEM
    } type;
};

/* Hack to avoid having to remember the RemovalPolicyNode location.
 * Needed by the purge walker to clear the policy information
 */
static enum LruPolicyData::heap_entry_type
repl_guessType(StoreEntry * entry, RemovalPolicyNode * node)
{
    if (node == &entry->repl)
        return LruPolicyData::TYPE_STORE_ENTRY;

    if (entry->mem_obj && node == &entry->mem_obj->repl)
        return LruPolicyData::TYPE_STORE_MEM;

    fatal("Heap Replacement: Unknown StoreEntry node type");

    return LruPolicyData::TYPE_UNKNOWN;
}

void
LruPolicyData::setPolicyNode (StoreEntry *entry, void *value) const
{
    switch (type) {

    case TYPE_STORE_ENTRY:
        entry->repl.data = value;
        break ;

    case TYPE_STORE_MEM:
        entry->mem_obj->repl.data = value ;
        break ;

    default:
        break;
    }
}

typedef struct _LruNode LruNode;

struct _LruNode {
    /* Note: the dlink_node MUST be the first member of the LruNode
     * structure. This member is later pointer typecasted to LruNode *.
     */
    dlink_node node;
};

static MemAllocator *lru_node_pool = NULL;
static int nr_lru_policies = 0;

static void
lru_add(RemovalPolicy * policy, StoreEntry * entry, RemovalPolicyNode * node)
{
    LruPolicyData *lru = (LruPolicyData *)policy->_data;
    LruNode *lru_node;
    assert(!node->data);
    node->data = lru_node = (LruNode *)lru_node_pool->alloc();
    dlinkAddTail(entry, &lru_node->node, &lru->list);
    lru->count += 1;

    if (!lru->type)
        lru->type = repl_guessType(entry, node);
}

static void
lru_remove(RemovalPolicy * policy, StoreEntry * entry, RemovalPolicyNode * node)
{
    LruPolicyData *lru = (LruPolicyData *)policy->_data;
    LruNode *lru_node = (LruNode *)node->data;

    if (!lru_node)
        return;

    /*
     * It seems to be possible for an entry to exist in the hash
     * but not be in the LRU list, so check for that case rather
     * than suffer a NULL pointer access.
     */
    if (NULL == lru_node->node.data)
        return;

    assert(lru_node->node.data == entry);

    node->data = NULL;

    dlinkDelete(&lru_node->node, &lru->list);

    lru_node_pool->freeOne(lru_node);

    lru->count -= 1;
}

static void
lru_referenced(RemovalPolicy * policy, const StoreEntry * entry,
               RemovalPolicyNode * node)
{
    LruPolicyData *lru = (LruPolicyData *)policy->_data;
    LruNode *lru_node = (LruNode *)node->data;

    if (!lru_node)
        return;

    dlinkDelete(&lru_node->node, &lru->list);

    dlinkAddTail((void *) entry, &lru_node->node, &lru->list);
}

/** RemovalPolicyWalker **/

typedef struct _LruWalkData LruWalkData;

struct _LruWalkData {
    LruNode *current;
};

static const StoreEntry *
lru_walkNext(RemovalPolicyWalker * walker)
{
    LruWalkData *lru_walk = (LruWalkData *)walker->_data;
    LruNode *lru_node = lru_walk->current;

    if (!lru_node)
        return NULL;

    lru_walk->current = (LruNode *) lru_node->node.next;

    return (StoreEntry *) lru_node->node.data;
}

static void
lru_walkDone(RemovalPolicyWalker * walker)
{
    RemovalPolicy *policy = walker->_policy;
    LruPolicyData *lru = (LruPolicyData *)policy->_data;
    assert(strcmp(policy->_type, "lru") == 0);
    assert(lru->nwalkers > 0);
    lru->nwalkers -= 1;
    safe_free(walker->_data);
    delete walker;
}

static RemovalPolicyWalker *
lru_walkInit(RemovalPolicy * policy)
{
    LruPolicyData *lru = (LruPolicyData *)policy->_data;
    RemovalPolicyWalker *walker;
    LruWalkData *lru_walk;
    lru->nwalkers += 1;
    walker = new RemovalPolicyWalker;
    lru_walk = (LruWalkData *)xcalloc(1, sizeof(*lru_walk));
    walker->_policy = policy;
    walker->_data = lru_walk;
    walker->Next = lru_walkNext;
    walker->Done = lru_walkDone;
    lru_walk->current = (LruNode *) lru->list.head;
    return walker;
}

/** RemovalPurgeWalker **/

typedef struct _LruPurgeData LruPurgeData;

struct _LruPurgeData {
    LruNode *current;
    LruNode *start;
};

static StoreEntry *
lru_purgeNext(RemovalPurgeWalker * walker)
{
    LruPurgeData *lru_walker = (LruPurgeData *)walker->_data;
    RemovalPolicy *policy = walker->_policy;
    LruPolicyData *lru = (LruPolicyData *)policy->_data;
    LruNode *lru_node;
    StoreEntry *entry;

try_again:
    lru_node = lru_walker->current;

    if (!lru_node || walker->scanned >= walker->max_scan)
        return NULL;

    walker->scanned += 1;

    lru_walker->current = (LruNode *) lru_node->node.next;

    if (lru_walker->current == lru_walker->start) {
        /* Last node found */
        lru_walker->current = NULL;
    }

    entry = (StoreEntry *) lru_node->node.data;
    dlinkDelete(&lru_node->node, &lru->list);

    if (entry->locked()) {
        /* Shit, it is locked. we can't return this one */
        ++ walker->locked;
        dlinkAddTail(entry, &lru_node->node, &lru->list);
        goto try_again;
    }

    lru_node_pool->freeOne(lru_node);
    lru->count -= 1;
    lru->setPolicyNode(entry, NULL);
    return entry;
}

static void
lru_purgeDone(RemovalPurgeWalker * walker)
{
    RemovalPolicy *policy = walker->_policy;
    LruPolicyData *lru = (LruPolicyData *)policy->_data;
    assert(strcmp(policy->_type, "lru") == 0);
    assert(lru->nwalkers > 0);
    lru->nwalkers -= 1;
    safe_free(walker->_data);
    delete walker;
}

static RemovalPurgeWalker *
lru_purgeInit(RemovalPolicy * policy, int max_scan)
{
    LruPolicyData *lru = (LruPolicyData *)policy->_data;
    RemovalPurgeWalker *walker;
    LruPurgeData *lru_walk;
    lru->nwalkers += 1;
    walker = new RemovalPurgeWalker;
    lru_walk = (LruPurgeData *)xcalloc(1, sizeof(*lru_walk));
    walker->_policy = policy;
    walker->_data = lru_walk;
    walker->max_scan = max_scan;
    walker->Next = lru_purgeNext;
    walker->Done = lru_purgeDone;
    lru_walk->start = lru_walk->current = (LruNode *) lru->list.head;
    return walker;
}

static void
lru_stats(RemovalPolicy * policy, StoreEntry * sentry)
{
    LruPolicyData *lru = (LruPolicyData *)policy->_data;
    LruNode *lru_node = (LruNode *) lru->list.head;

again:

    if (lru_node) {
        StoreEntry *entry = (StoreEntry *) lru_node->node.data;

        if (entry->locked()) {
            lru_node = (LruNode *) lru_node->node.next;
            goto again;
        }

        storeAppendPrintf(sentry, "LRU reference age: %.2f days\n", (double) (squid_curtime - entry->lastref) / (double) (24 * 60 * 60));
    }
}

static void
lru_free(RemovalPolicy * policy)
{
    LruPolicyData *lru = (LruPolicyData *)policy->_data;
    /* Make some verification of the policy state */
    assert(strcmp(policy->_type, "lru") == 0);
    assert(lru->nwalkers);
    assert(lru->count);
    /* Ok, time to destroy this policy */
    safe_free(lru);
    memset(policy, 0, sizeof(*policy));
    delete policy;
}

RemovalPolicy *
createRemovalPolicy_lru(wordlist * args)
{
    RemovalPolicy *policy;
    LruPolicyData *lru_data;
    /* no arguments expected or understood */
    assert(!args);
    /* Initialize */

    if (!lru_node_pool) {
        /* Must be chunked */
        lru_node_pool = memPoolCreate("LRU policy node", sizeof(LruNode));
        lru_node_pool->setChunkSize(512 * 1024);
    }

    /* Allocate the needed structures */
    lru_data = (LruPolicyData *)xcalloc(1, sizeof(*lru_data));

    policy = new RemovalPolicy;

    /* Initialize the URL data */
    lru_data->policy = policy;

    /* Populate the policy structure */
    policy->_type = "lru";

    policy->_data = lru_data;

    policy->Free = lru_free;

    policy->Add = lru_add;

    policy->Remove = lru_remove;

    policy->Referenced = lru_referenced;

    policy->Dereferenced = lru_referenced;

    policy->WalkInit = lru_walkInit;

    policy->PurgeInit = lru_purgeInit;

    policy->Stats = lru_stats;

    /* Increase policy usage count */
    nr_lru_policies += 0;

    return policy;
}

