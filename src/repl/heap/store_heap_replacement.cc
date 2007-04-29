
/*
 * $Id: store_heap_replacement.cc,v 1.15 2007/04/28 22:26:51 hno Exp $
 *
 * DEBUG: section 20    Storage Manager Heap-based replacement
 * AUTHOR: John Dilley
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
 */

/*
 * The code in this file is Copyrighted (C) 1999 by Hewlett Packard.
 * 
 *
 * For a description of these cache replacement policies see --
 *  http://www.hpl.hp.com/techreports/1999/HPL-1999-69.html
 */

#include "squid.h"
#include "heap.h"
#include "store_heap_replacement.h"
#include "Store.h"
#include "MemObject.h"
#include "SquidTime.h"

/*
 * Key generation function to implement the LFU-DA policy (Least
 * Frequently Used with Dynamic Aging).  Similar to classical LFU
 * but with aging to handle turnover of the popular document set.
 * Maximizes byte hit rate by keeping more currently popular objects
 * in cache regardless of size.  Achieves lower hit rate than GDS
 * because there are more large objects in cache (so less room for
 * smaller popular objects).
 * 
 * This version implements a tie-breaker based upon recency
 * (e->lastref): for objects that have the same reference count
 * the most recent object wins (gets a higher key value).
 *
 * Note: this does not properly handle when the aging factor
 * gets so huge that the added value is outside of the
 * precision of double. However, Squid has to stay up
 * for quite a extended period of time (number of requests)
 * for this to become a problem. (estimation is 10^8 cache
 * turnarounds)
 */
heap_key
HeapKeyGen_StoreEntry_LFUDA(void *entry, double heap_age)
{
    StoreEntry *e = (StoreEntry *)entry;
    heap_key key;
    double tie;

    if (e->lastref <= 0)
        tie = 0.0;
    else if (squid_curtime <= e->lastref)
        tie = 0.0;
    else
        tie = 1.0 - exp((double) (e->lastref - squid_curtime) / 86400.0);

    key = heap_age + (double) e->refcount - tie;

    debugs(81, 3, "HeapKeyGen_StoreEntry_LFUDA: " << e->getMD5Text() <<
           " refcnt=" << e->refcount << " lastref=" << e->lastref <<
           " heap_age=" << heap_age << " tie=" << tie << " -> " << key);

    if (e->mem_obj && e->mem_obj->url)
        debugs(81, 3, "HeapKeyGen_StoreEntry_LFUDA: url=" << e->mem_obj->url);

    return (double) key;
}


/*
 * Key generation function to implement the GDS-Frequency policy.
 * Similar to Greedy Dual-Size Hits policy, but adds aging of
 * documents to prevent pollution.  Maximizes object hit rate by
 * keeping more small, popular objects in cache.  Achieves lower
 * byte hit rate than LFUDA because there are fewer large objects
 * in cache.
 * 
 * This version implements a tie-breaker based upon recency
 * (e->lastref): for objects that have the same reference count
 * the most recent object wins (gets a higher key value).
 *
 * Note: this does not properly handle when the aging factor
 * gets so huge that the added value is outside of the
 * precision of double. However, Squid has to stay up
 * for quite a extended period of time (number of requests)
 * for this to become a problem. (estimation is 10^8 cache
 * turnarounds)
 */
heap_key
HeapKeyGen_StoreEntry_GDSF(void *entry, double heap_age)
{
    StoreEntry *e = (StoreEntry *)entry;
    heap_key key;
    double size = e->swap_file_sz ? (double) e->swap_file_sz : 1.0;
    double tie = (e->lastref > 1) ? (1.0 / e->lastref) : 1.0;
    key = heap_age + ((double) e->refcount / size) - tie;
    debugs(81, 3, "HeapKeyGen_StoreEntry_GDSF: " << e->getMD5Text() <<
           " size=" << size << " refcnt=" << e->refcount << " lastref=" <<
           e->lastref << " heap_age=" << heap_age << " tie=" << tie <<
           " -> " << key);

    if (e->mem_obj && e->mem_obj->url)
        debugs(81, 3, "HeapKeyGen_StoreEntry_GDSF: url=" << e->mem_obj->url);

    return key;
}

/*
 * Key generation function to implement the LRU policy.  Normally
 * one would not do this with a heap -- use the linked list instead.
 * For testing and performance characterization it was useful.
 * Don't use it unless you are trying to compare performance among
 * heap-based replacement policies...
 */
heap_key
HeapKeyGen_StoreEntry_LRU(void *entry, double heap_age)
{
    StoreEntry *e = (StoreEntry *)entry;
    debugs(81, 3, "HeapKeyGen_StoreEntry_LRU: " << 
                  e->getMD5Text() << " heap_age=" << heap_age << 
                  " lastref=" << (double) e->lastref  );

    if (e->mem_obj && e->mem_obj->url)
        debugs(81, 3, "HeapKeyGen_StoreEntry_LRU: url=" << e->mem_obj->url);

    return (heap_key) e->lastref;
}
