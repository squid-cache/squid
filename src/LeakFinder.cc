/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 45    Callback Data Registry */

/*
 * Use these to find memory leaks
 */

#include "squid.h"

#if USE_LEAKFINDER

#include "LeakFinder.h"
#include "SquidTime.h"
#include "Store.h"

/* ========================================================================= */

LeakFinderPtr::LeakFinderPtr(void *p, const char *f, const int l) :
    file(f),
    line(l),
    when(squid_curtime)
{
    // XXX: these bits should be done by hash_link()
    key = p;
    next = NULL;
}

/* ========================================================================= */

LeakFinder::LeakFinder() :
    count(0),
    last_dump(0)
{
    debugs(45, 3, "LeakFinder constructed");
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
LeakFinder::addSome(void *p, const char *file, int line)
{
    assert(hash_lookup(table, p) == NULL);
    LeakFinderPtr *c = new LeakFinderPtr(p, file, line);
    hash_join(table, c);
    ++count;
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
LeakFinder::freeSome(void *p, const char *file, int line)
{
    assert(p);
    LeakFinderPtr *c = (LeakFinderPtr *) hash_lookup(table, p);
    assert(c);
    hash_remove_link(table, c);
    --count;
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

    debugs(45, DBG_IMPORTANT, "Tracking " << count << " pointers");

    hash_first(table);

    LeakFinderPtr *c;

    while ((c = (LeakFinderPtr *)hash_next(table))) {
        debugs(45, DBG_IMPORTANT, std::setw(20) << c->key << " last used " << std::setw(9) << (squid_curtime - c->when) <<
               " seconds ago by " << c->file << ":" << c->line);
    }
}

#endif /* USE_LEAKFINDER */

