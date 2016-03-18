/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: none          Memory Allocation */

#define _SQUID_EXTERNNEW_

#include "squid.h"

#ifdef __SUNPRO_CC

#include <new>
void *operator new(size_t size) throw (std::bad_alloc)
{
    return xmalloc(size);
}
void operator delete (void *address) throw()
{
    xfree (address);
}
void *operator new[] (size_t size) throw (std::bad_alloc)
{
    return xmalloc(size);
}
void operator delete[] (void *address) throw()
{
    xfree (address);
}

#endif /* __SUNPRO_CC */

