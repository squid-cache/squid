/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_MEMPOOLS

#include "MemPool.h"

#include <iostream>

/* TODO: put this in a libTest */
void
xassert(const char *msg, const char *file, int line)
{
    std::cout << "Assertion failed: (" << msg << ") at " << file << ":" << line << std::endl;
    exit (1);
}

class MemPoolTest
{
public:
    void run();
private:
    class SomethingToAlloc
    {
    public:
        int aValue;
    };
    static MemAllocator *Pool;
};
MemAllocator *MemPoolTest::Pool = NULL;

void
MemPoolTest::run()
{
    assert (Pool == NULL);
    Pool = memPoolCreate("Test Pool", sizeof(SomethingToAlloc));
    assert (Pool);
    SomethingToAlloc *something = static_cast<SomethingToAlloc *>(Pool->alloc());
    assert (something);
    assert (something->aValue == 0);
    something->aValue = 5;
    Pool->freeOne(something);
    SomethingToAlloc *otherthing = static_cast<SomethingToAlloc *>(Pool->alloc());
    assert (otherthing == something);
    assert (otherthing->aValue == 0);
    Pool->freeOne(otherthing);
    delete Pool;
}

#endif /* USE_MEMPOOLS */

int
main (int argc, char **argv)
{
#if USE_MEMPOOLS
    MemPoolTest aTest;
    aTest.run();
#endif
    return 0;
}

