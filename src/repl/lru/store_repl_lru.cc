
/*
 * $Id: store_repl_lru.cc,v 1.1 2000/06/08 18:05:40 hno Exp $
 *
 * DEBUG: section ?     LRU Removal policy
 * AUTHOR: Henrik Nordstrom
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"

REMOVALPOLICYCREATE createRemovalPolicy_lru;

typedef struct _LruPolicyData LruPolicyData;
struct _LruPolicyData {
    RemovalPolicy *policy;
    dlink_list list;
    int count;
    int nwalkers;
    enum heap_entry_type
    { TYPE_UNKNOWN = 0, TYPE_STORE_ENTRY, TYPE_STORE_MEM }
    type;
};

/* Hack to avoid having to remember the RemovalPolicyNode location.
 * Needed by the purge walker to clear the policy information
 */
static enum heap_entry_type
repl_guessType(StoreEntry * entry, RemovalPolicyNode * node)
{
    if (node == &entry->repl)
	return TYPE_STORE_ENTRY;
    if (entry->mem_obj && node == &entry->mem_obj->repl)
	return TYPE_STORE_MEM;
    fatal("Heap Replacement: Unknown StoreEntry node type");
    return TYPE_UNKNOWN;
}
#define SET_POLICY_NODE(entry,value) \
    switch(lru->type) { \
    case TYPE_STORE_ENTRY: entry->repl.data = value; break ; \
    case TYPE_STORE_MEM: entry->mem_obj->repl.data = value ; break ; \
    default: break; \
    }

typedef struct _LruNode LruNode;
struct _LruNode
{
    /* Note: the dlink_node MUST be the first member of the LruNode
     * structure. This member is later pointer typecasted to LruNode *.
     */
    dlink_node node;
};

static MemPool *lru_node_pool = NULL;
static int nr_lru_policies = 0;

static void
lru_add(RemovalPolicy * policy, StoreEntry * entry, RemovalPolicyNode * node)
{
    LruPolicyData *lru = policy->_data;
    LruNode *lru_node;
    assert(!node->data);
    node->data = lru_node = memPoolAlloc(lru_node_pool);
    dlinkAddTail(entry, &lru_node->node, &lru->list);
    lru->count += 1;
    if (!lru->type)
	lru->type = repl_guessType(entry, node);
}

static void
lru_remove(RemovalPolicy * policy, StoreEntry * entry, RemovalPolicyNode * node)
{
    LruPolicyData *lru = policy->_data;
    LruNode *lru_node = node->data;
    if (!lru_node)
	return;
    assert(lru_node->node.data == entry);
    node->data = NULL;
    dlinkDelete(&lru_node->node, &lru->list);
    memPoolFree(lru_node_pool, lru_node);
    lru->count -= 1;
}

static void
lru_referenced(RemovalPolicy * policy, const StoreEntry * entry,
    RemovalPolicyNode * node)
{
    LruPolicyData *lru = policy->_data;
    LruNode *lru_node = node->data;
    if (!lru_node)
	return;
    dlinkDelete(&lru_node->node, &lru->list);
    dlinkAddTail((void *) entry, &lru_node->node, &lru->list);
}

/** RemovalPolicyWalker **/

typedef struct _LruWalkData LruWalkData;
struct _LruWalkData
{
    LruNode *current;
};

const StoreEntry *
lru_walkNext(RemovalPolicyWalker * walker)
{
    LruWalkData *lru_walk = walker->_data;
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
    LruPolicyData *lru = policy->_data;
    assert(strcmp(policy->_type, "lru") == 0);
    assert(lru->nwalkers > 0);
    lru->nwalkers -= 1;
    safe_free(walker->_data);
    cbdataFree(walker);
}

static RemovalPolicyWalker *
lru_walkInit(RemovalPolicy * policy)
{
    LruPolicyData *lru = policy->_data;
    RemovalPolicyWalker *walker;
    LruWalkData *lru_walk;
    lru->nwalkers += 1;
    walker = xcalloc(1, sizeof(*walker));
    lru_walk = xcalloc(1, sizeof(*lru_walk));
    walker->_policy = policy;
    walker->_data = lru_walk;
    walker->Next = lru_walkNext;
    walker->Done = lru_walkDone;
    lru_walk->current = (LruNode *) lru->list.head;
    cbdataAdd(walker, cbdataXfree, 0);
    return walker;
}

/** RemovalPurgeWalker **/

typedef struct _LruPurgeData LruPurgeData;
struct _LruPurgeData
{
    LruNode *current;
    LruNode *start;
};

static StoreEntry *
lru_purgeNext(RemovalPurgeWalker * walker)
{
    LruPurgeData *lru_walker = walker->_data;
    RemovalPolicy *policy = walker->_policy;
    LruPolicyData *lru = policy->_data;
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
    if (storeEntryLocked(entry)) {
	/* Shit, it is locked. we can't return this one */
	walker->locked++;
	dlinkAddTail(entry, &lru_node->node, &lru->list);
	goto try_again;
    }
    memPoolFree(lru_node_pool, lru_node);
    lru->count -= 1;
    SET_POLICY_NODE(entry, NULL);
    return entry;
}

static void
lru_purgeDone(RemovalPurgeWalker * walker)
{
    RemovalPolicy *policy = walker->_policy;
    LruPolicyData *lru = policy->_data;
    assert(strcmp(policy->_type, "lru") == 0);
    assert(lru->nwalkers > 0);
    lru->nwalkers -= 1;
    safe_free(walker->_data);
    cbdataFree(walker);
}

static RemovalPurgeWalker *
lru_purgeInit(RemovalPolicy * policy, int max_scan)
{
    LruPolicyData *lru = policy->_data;
    RemovalPurgeWalker *walker;
    LruPurgeData *lru_walk;
    lru->nwalkers += 1;
    walker = xcalloc(1, sizeof(*walker));
    lru_walk = xcalloc(1, sizeof(*lru_walk));
    walker->_policy = policy;
    walker->_data = lru_walk;
    walker->max_scan = max_scan;
    walker->Next = lru_purgeNext;
    walker->Done = lru_purgeDone;
    lru_walk->start = lru_walk->current = (LruNode *) lru->list.head;
    cbdataAdd(walker, cbdataXfree, 0);
    return walker;
}

static void
lru_free(RemovalPolicy * policy)
{
    LruPolicyData *lru = policy->_data;
    /* Make some verification of the policy state */
    assert(strcmp(policy->_type, "lru") == 0);
    assert(lru->nwalkers);
    assert(lru->count);
    /* Ok, time to destroy this policy */
    safe_free(policy->_data);
    memset(policy, 0, sizeof(*policy));
    cbdataFree(policy);
}

RemovalPolicy *
createRemovalPolicy_lru(wordlist *args)
{
    RemovalPolicy *policy;
    LruPolicyData *lru_data;
    /* no arguments expected or understood */
    assert(!args);
    /* Initialize */
    if (!lru_node_pool)
	lru_node_pool = memPoolCreate("LRU policy node", sizeof(LruNode));
    /* Allocate the needed structures */
    policy = xcalloc(1, sizeof(*policy));
    lru_data = xcalloc(1, sizeof(*lru_data));
    /* cbdata register the policy */
    cbdataAdd(policy, cbdataXfree, 0);
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
    /* Increase policy usage count */
    nr_lru_policies += 0;
    return policy;
}


#if OLD_UNUSED_CODE
/*
 * storeUfsDirCheckExpired
 *
 * Check whether the given object is expired or not
 * It breaks layering a little by calling the upper layers to find
 * out whether the object is locked or not, but we can't help this
 * right now.
 */
static int
storeUfsDirCheckExpired(SwapDir * SD, StoreEntry * e)
{
    if (storeEntryLocked(e))
	return 0;
    if (EBIT_TEST(e->flags, RELEASE_REQUEST))
	return 1;
    if (EBIT_TEST(e->flags, ENTRY_NEGCACHED) && squid_curtime >= e->expires)
	return 1;

#if HEAP_REPLACEMENT
    /*
     * with HEAP_REPLACEMENT we are not using the LRU reference age, the heap
     * controls the replacement of objects.
     */
    return 1;
#else
    if (squid_curtime - e->lastref > storeUfsDirExpiredReferenceAge(SD))
	return 1;
    return 0;
#endif
}

/*
 * storeUfsDirExpiredReferenceAge
 *
 * The LRU age is scaled exponentially between 1 minute and
 * Config.referenceAge , when store_swap_low < store_swap_size <
 * store_swap_high.  This keeps store_swap_size within the low and high
 * water marks.  If the cache is very busy then store_swap_size stays
 * closer to the low water mark, if it is not busy, then it will stay
 * near the high water mark.  The LRU age value can be examined on the
 * cachemgr 'info' page.
 */
static time_t
storeUfsDirExpiredReferenceAge(SwapDir * SD)
{
    double x;
    double z;
    time_t age;
    long store_high, store_low;

    store_high = (long) (((float) SD->max_size *
	    (float) Config.Swap.highWaterMark) / (float) 100);
    store_low = (long) (((float) SD->max_size *
	    (float) Config.Swap.lowWaterMark) / (float) 100);
    debug(81, 4) ("storeUfsDirExpiredReferenceAge: Dir %s, hi=%d, lo=%d, cur=%d\n", SD->path, store_high,
	store_low, SD->cur_size);

    x = (double) (store_high - SD->cur_size) / (store_high - store_low);
    x = x < 0.0 ? 0.0 : x > 1.0 ? 1.0 : x;
    z = pow((double) (Config.referenceAge / 60), x);
    age = (time_t) (z * 60.0);
    if (age < 60)
	age = 60;
    else if (age > Config.referenceAge)
	age = Config.referenceAge;
    return age;
}
#endif /* OLD_UNUSED_CODE */
