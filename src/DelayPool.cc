
/*
 * $Id: DelayPool.cc,v 1.7 2007/04/23 06:11:55 wessels Exp $
 *
 * DEBUG: section 77    Delay Pools
 * AUTHOR: Robert Collins <robertc@squid-cache.org>
 * Based upon original delay pools code by
 *   David Luyer <david@luyer.net>
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "config.h"

#if DELAY_POOLS
#include "DelayPool.h"
#include "CommonPool.h"
#include "ACL.h"
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
    assert (theComposite() != NULL);
    theComposite()->parse();
}

void
DelayPool::dump (StoreEntry *entry, unsigned int i) const
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

/* XXX create DelayIdComposite.cc */
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

#endif
