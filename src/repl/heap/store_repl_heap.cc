/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DEBUG: section 81    Store HEAP Removal Policies
 *
 * Based on the ideas of the heap policy implemented by John Dilley of
 * Hewlett Packard. Rewritten from scratch when modularizing the removal
 * policy implementation of Squid.
 *
 * For details on the original heap policy work and the thinking behind see
 * http://www.hpl.hp.com/techreports/1999/HPL-1999-69.html
 */

#include "squid.h"
#include "heap.h"
#include "MemObject.h"
#include "SquidList.h"
#include "Store.h"
#include "store_heap_replacement.h"
#include "wordlist.h"

REMOVALPOLICYCREATE createRemovalPolicy_heap;

static int nr_heap_policies = 0;

struct HeapPolicyData {
    void setPolicyNode (StoreEntry *, void *) const;
    RemovalPolicy *policy;
    heap *theHeap;
    heap_key_func *keyfunc;
    int count;
    int nwalkers;
    enum heap_entry_type {
        TYPE_UNKNOWN = 0, TYPE_STORE_ENTRY, TYPE_STORE_MEM
    } type;
};

/* Hack to avoid having to remember the RemovalPolicyNode location.
 * Needed by the purge walker.
 */
static enum HeapPolicyData::heap_entry_type
heap_guessType(StoreEntry * entry, RemovalPolicyNode * node)
{
    if (node == &entry->repl)
        return HeapPolicyData::TYPE_STORE_ENTRY;

    if (entry->mem_obj && node == &entry->mem_obj->repl)
        return HeapPolicyData::TYPE_STORE_MEM;

    fatal("Heap Replacement: Unknown StoreEntry node type");

    return HeapPolicyData::TYPE_UNKNOWN;
}

void
HeapPolicyData::setPolicyNode (StoreEntry *entry, void *value) const
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

static void
heap_add(RemovalPolicy * policy, StoreEntry * entry, RemovalPolicyNode * node)
{
    HeapPolicyData *h = (HeapPolicyData *)policy->_data;
    assert(!node->data);

    if (EBIT_TEST(entry->flags, ENTRY_SPECIAL))
        return;         /* We won't manage these.. they messes things up */

    node->data = heap_insert(h->theHeap, entry);

    h->count += 1;

    if (!h->type)
        h->type = heap_guessType(entry, node);

    /* Add a little more variance to the aging factor */
    h->theHeap->age += h->theHeap->age / 100000000;
}

static void
heap_remove(RemovalPolicy * policy, StoreEntry * entry,
            RemovalPolicyNode * node)
{
    HeapPolicyData *h = (HeapPolicyData *)policy->_data;
    heap_node *hnode = (heap_node *)node->data;

    if (!hnode)
        return;

    heap_delete(h->theHeap, hnode);

    node->data = NULL;

    h->count -= 1;
}

static void
heap_referenced(RemovalPolicy * policy, const StoreEntry * entry,
                RemovalPolicyNode * node)
{
    HeapPolicyData *h = (HeapPolicyData *)policy->_data;
    heap_node *hnode = (heap_node *)node->data;

    if (!hnode)
        return;

    heap_update(h->theHeap, hnode, (StoreEntry *) entry);
}

/** RemovalPolicyWalker **/

typedef struct _HeapWalkData HeapWalkData;

struct _HeapWalkData {
    size_t current;
};

static const StoreEntry *
heap_walkNext(RemovalPolicyWalker * walker)
{
    HeapWalkData *heap_walk = (HeapWalkData *)walker->_data;
    RemovalPolicy *policy = walker->_policy;
    HeapPolicyData *h = (HeapPolicyData *)policy->_data;
    StoreEntry *entry;

    if (heap_walk->current >= heap_nodes(h->theHeap))
        return NULL;        /* done */

    entry = (StoreEntry *) heap_peep(h->theHeap, heap_walk->current++);

    return entry;
}

static void
heap_walkDone(RemovalPolicyWalker * walker)
{
    RemovalPolicy *policy = walker->_policy;
    HeapPolicyData *h = (HeapPolicyData *)policy->_data;
    assert(strcmp(policy->_type, "heap") == 0);
    assert(h->nwalkers > 0);
    h->nwalkers -= 1;
    safe_free(walker->_data);
    delete walker;
}

static RemovalPolicyWalker *
heap_walkInit(RemovalPolicy * policy)
{
    HeapPolicyData *h = (HeapPolicyData *)policy->_data;
    RemovalPolicyWalker *walker;
    HeapWalkData *heap_walk;
    h->nwalkers += 1;
    walker = new RemovalPolicyWalker;
    heap_walk = (HeapWalkData *)xcalloc(1, sizeof(*heap_walk));
    heap_walk->current = 0;
    walker->_policy = policy;
    walker->_data = heap_walk;
    walker->Next = heap_walkNext;
    walker->Done = heap_walkDone;
    return walker;
}

/** RemovalPurgeWalker **/

typedef struct _HeapPurgeData HeapPurgeData;

struct _HeapPurgeData {
    link_list *locked_entries;
    heap_key min_age;
};

static StoreEntry *
heap_purgeNext(RemovalPurgeWalker * walker)
{
    HeapPurgeData *heap_walker = (HeapPurgeData *)walker->_data;
    RemovalPolicy *policy = walker->_policy;
    HeapPolicyData *h = (HeapPolicyData *)policy->_data;
    StoreEntry *entry;
    heap_key age;

try_again:

    if (heap_empty(h->theHeap))
        return NULL;        /* done */

    age = heap_peepminkey(h->theHeap);

    entry = (StoreEntry *)heap_extractmin(h->theHeap);

    if (entry->locked()) {

        entry->lock("heap_purgeNext");
        linklistPush(&heap_walker->locked_entries, entry);

        goto try_again;
    }

    heap_walker->min_age = age;
    h->setPolicyNode(entry, NULL);
    return entry;
}

static void
heap_purgeDone(RemovalPurgeWalker * walker)
{
    HeapPurgeData *heap_walker = (HeapPurgeData *)walker->_data;
    RemovalPolicy *policy = walker->_policy;
    HeapPolicyData *h = (HeapPolicyData *)policy->_data;
    StoreEntry *entry;
    assert(strcmp(policy->_type, "heap") == 0);
    assert(h->nwalkers > 0);
    h->nwalkers -= 1;

    if (heap_walker->min_age > 0) {
        h->theHeap->age = heap_walker->min_age;
        debugs(81, 3, "Heap age set to " << h->theHeap->age);
    }

    /*
     * Reinsert the locked entries
     */
    while ((entry = (StoreEntry *)linklistShift(&heap_walker->locked_entries))) {
        heap_node *node = heap_insert(h->theHeap, entry);
        h->setPolicyNode(entry, node);
        entry->unlock("heap_purgeDone");
    }

    safe_free(walker->_data);
    delete walker;
}

static RemovalPurgeWalker *
heap_purgeInit(RemovalPolicy * policy, int max_scan)
{
    HeapPolicyData *h = (HeapPolicyData *)policy->_data;
    RemovalPurgeWalker *walker;
    HeapPurgeData *heap_walk;
    h->nwalkers += 1;
    walker = new RemovalPurgeWalker;
    heap_walk = (HeapPurgeData *)xcalloc(1, sizeof(*heap_walk));
    heap_walk->min_age = 0.0;
    heap_walk->locked_entries = NULL;
    walker->_policy = policy;
    walker->_data = heap_walk;
    walker->max_scan = max_scan;
    walker->Next = heap_purgeNext;
    walker->Done = heap_purgeDone;
    return walker;
}

static void
heap_free(RemovalPolicy * policy)
{
    HeapPolicyData *h = (HeapPolicyData *)policy->_data;
    /* Make some verification of the policy state */
    assert(strcmp(policy->_type, "heap") == 0);
    assert(h->nwalkers);
    assert(h->count);
    /* Ok, time to destroy this policy */
    safe_free(h);
    memset(policy, 0, sizeof(*policy));
    delete policy;
}

RemovalPolicy *
createRemovalPolicy_heap(wordlist * args)
{
    RemovalPolicy *policy;
    HeapPolicyData *heap_data;
    const char *keytype;
    /* Allocate the needed structures */
    policy = new RemovalPolicy;
    heap_data = (HeapPolicyData *)xcalloc(1, sizeof(*heap_data));
    /* Initialize the policy data */
    heap_data->policy = policy;

    if (args) {
        keytype = args->key;
        args = args->next;
    } else {
        debugs(81, DBG_IMPORTANT, "createRemovalPolicy_heap: No key type specified. Using LRU");
        keytype = "LRU";
    }

    if (!strcmp(keytype, "GDSF"))
        heap_data->keyfunc = HeapKeyGen_StoreEntry_GDSF;
    else if (!strcmp(keytype, "LFUDA"))
        heap_data->keyfunc = HeapKeyGen_StoreEntry_LFUDA;
    else if (!strcmp(keytype, "LRU"))
        heap_data->keyfunc = HeapKeyGen_StoreEntry_LRU;
    else {
        debugs(81, DBG_CRITICAL, "createRemovalPolicy_heap: Unknown key type \"" << keytype << "\". Using LRU");
        heap_data->keyfunc = HeapKeyGen_StoreEntry_LRU;
    }

    /* No additional arguments expected */
    while (args) {
        debugs(81, DBG_IMPORTANT, "WARNING: discarding unknown removal policy '" << args->key << "'");
        args = args->next;
    }

    heap_data->theHeap = new_heap(1000, heap_data->keyfunc);

    heap_data->theHeap->age = 1.0;

    /* Populate the policy structure */
    policy->_type = "heap";

    policy->_data = heap_data;

    policy->Free = heap_free;

    policy->Add = heap_add;

    policy->Remove = heap_remove;

    policy->Referenced = NULL;

    policy->Dereferenced = heap_referenced;

    policy->WalkInit = heap_walkInit;

    policy->PurgeInit = heap_purgeInit;

    /* Increase policy usage count */
    nr_heap_policies += 0;

    return policy;
}

