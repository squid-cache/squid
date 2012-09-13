/*
 * AUTHOR: Robert Collins
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"

#if USE_MEMPOOLS

#include "MemPool.h"

#if HAVE_IOSTREAM
#include <iostream>
#endif

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

