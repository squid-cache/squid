
/*
 * $Id: DelayBucket.cc,v 1.7 2007/05/29 13:31:36 amosjeffries Exp $
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
#include "squid.h"
#include "DelayBucket.h"
#include "DelaySpec.h"
#include "Store.h"
/*
#include "DelayPools.h"
#include "StoreClient.h"
#include "MemObject.h"
#include "client_side_request.h"
#include "ACLChecklist.h"
#include "ACL.h"
#include "ConfigParser.h"
#include "DelayId.h"
#include "Array.h"
#include "String.h"
#include "CommonPool.h"
#include "CompositePoolNode.h"
#include "DelayPool.h"
#include "DelayVector.h"
#include "NullDelayId.h"
*/

void
DelayBucket::stats(StoreEntry *entry)const
{
    storeAppendPrintf(entry, "%d", level());
}

void
DelayBucket::update (DelaySpec const &rate, int incr)
{
    if (rate.restore_bps != -1 &&
            (level() += rate.restore_bps * incr) > rate.max_bytes)
        level() = rate.max_bytes;
}

int
DelayBucket::bytesWanted (int minimum, int maximum) const
{
    int result = max(minimum, min(maximum, level()));
    return result;
}

void
DelayBucket::bytesIn(int qty)
{
    level() -= qty;
}

void
DelayBucket::init (DelaySpec const &rate)
{
    level() = (int) (((double)rate.max_bytes *
                      Config.Delay.initial) / 100);
}

#endif

