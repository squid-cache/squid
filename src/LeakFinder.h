/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_LEAKFINDER_H
#define SQUID_LEAKFINDER_H

#if USE_LEAKFINDER

#include "hash.h"

#define leakAdd(p,l) if (l) l->addSome(p,__FILE__,__LINE__)
#define leakTouch(p,l) if (l) l->touch(p,__FILE__,__LINE__)
#define leakFree(p,l) if (l) l->freeSome(p,__FILE__,__LINE__)

class LeakFinderPtr : public hash_link
{

public:
    LeakFinderPtr(void *, const char *, const int);
    const char *file;
    int line;
    time_t when;
};

class LeakFinder
{

public:
    LeakFinder();
    ~LeakFinder();

    void *addSome(void *, const char *, const int);

    void *touch(void *, const char *, const int);

    void *freeSome(void *, const char *, const int);

    void dump();

private:
    static HASHCMP cmp;

    static HASHHASH hash;

    hash_table *table;

    int count;

    time_t last_dump;

};

#else /* USE_LEAKFINDER */

class LeakFinder {};

#define leakAdd(p,l) (void)0
#define leakTouch(p,l) (void)0
#define leakFree(p,l) (void)0
#endif /* USE_LEAKFINDER */

#endif /* SQUID_LEAKFINDER_H */

