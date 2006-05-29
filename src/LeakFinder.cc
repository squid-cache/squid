
/*
 * $Id: LeakFinder.cc,v 1.4 2006/05/29 00:15:00 robertc Exp $
 *
 * DEBUG: section 45    Callback Data Registry
 * AUTHOR: Duane Wessels
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
 * Use these to find memory leaks
 */

#include "squid.h"
#include "LeakFinder.h"
#include "Store.h"
#include "SquidTime.h"

#if USE_LEAKFINDER
/* ========================================================================= */

LeakFinderPtr::LeakFinderPtr(void *p , const char *f, const int l) :
        file(f), line(l), when(squid_curtime)
{
    key = p;
    next = NULL;
}

/* ========================================================================= */

LeakFinder::LeakFinder()
{
    debug(45, 3) ("LeakFinder constructed\n");
    table = hash_create(cmp, 1 << 8, hash);
#if 0
    /* if this is desired to reinstate, add a
     * RegisterWithCacheManager method
     */
    cachemgrRegister("leaks",
                     "Memory Leak Tracking",
                     cachemgr_dump, 0, 1);
#endif
}

void *

LeakFinder::add
    (void *p, const char *file, int line)
{
    assert(hash_lookup(table, p) == NULL);
    LeakFinderPtr *c = new LeakFinderPtr(p, file, line);
    hash_join(table, c);
    count++;
    return p;
}

void *
LeakFinder::touch(void *p, const char *file, int line)
{
    assert(p);
    LeakFinderPtr *c = (LeakFinderPtr *) hash_lookup(table, p);
    assert(c);
    c->file = file;
    c->line = line;
    c->when = squid_curtime;
    return p;
}

void *
LeakFinder::free(void *p, const char *file, int line)
{
    assert(p);
    LeakFinderPtr *c = (LeakFinderPtr *) hash_lookup(table, p);
    assert(c);
    hash_remove_link(table, c);
    count--;
    delete c;
    dump();
    return p;
}

/* ========================================================================= */

int
LeakFinder::cmp(const void *p1, const void *p2)
{
    return (char *) p1 - (char *) p2;
}

unsigned int
LeakFinder::hash(const void *p, unsigned int mod)
{
    return ((unsigned long) p >> 8) % mod;
}


void
LeakFinder::dump()
{
    if (0 == count)
        return;

    if (squid_curtime == last_dump)
        return;

    last_dump = squid_curtime;

    debug(45,1)("Tracking %d pointers\n", count);

    hash_first(table);

    LeakFinderPtr *c;

    while ((c = (LeakFinderPtr *)hash_next(table))) {
        debug(45,1)("%20p last used %9d seconds ago by %s:%d\n",
                    c->key, (int)(squid_curtime - c->when), c->file, c->line);
    }
}

#endif /* USE_LEAKFINDER */
