/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#include "squid.h"

#if USE_DELAY_POOLS
#include "acl/Acl.h"
#include "acl/Gadgets.h"
#include "CommonPool.h"
#include "DelayPool.h"
#include "Store.h"

DelayPool::DelayPool() : pool (NULL), access (NULL)
{
    pool = CommonPool::Factory(0, theComposite_);
}

DelayPool::~DelayPool()
{
    if (pool)
        freeData();

    if (access)
        aclDestroyAccessList(&access);
}

void
DelayPool::parse()
{
    assert(theComposite() != NULL);
    theComposite()->parse();
}

void
DelayPool::dump(StoreEntry *entry, unsigned int i) const
{
    if (theComposite() == NULL)
        return;

    storeAppendPrintf(entry, "delay_class %d %s\n", i + 1, pool->theClassTypeLabel());

    LOCAL_ARRAY(char, nom, 32);

    snprintf(nom, 32, "delay_access %d", i + 1);

    dump_acl_access(entry, nom, access);

    storeAppendPrintf(entry, "delay_parameters %d", i + 1);

    theComposite()->dump (entry);

    storeAppendPrintf(entry, "\n");
}

void
DelayPool::createPool(u_char delay_class)
{
    if (pool)
        freeData();

    pool = CommonPool::Factory(delay_class, theComposite_);
}

void
DelayPool::freeData()
{
    delete pool;
    pool = NULL;
}

// TODO: create DelayIdComposite.cc
void
CompositePoolNode::delayRead(DeferredRead const &aRead)
{
    deferredReads.delayRead(aRead);
}

#include "comm.h"

void
CompositePoolNode::kickReads()
{
    deferredReads.kickReads(-1);
}

#endif /* USE_DELAY_POOLS */

