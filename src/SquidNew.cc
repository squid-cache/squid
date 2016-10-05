/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: none          Memory Allocation */

#include "squid.h"

#if !defined(__clang__) && !defined(__SUNPRO_CC)

#include <new>

void *operator new(size_t size)
{
    return xmalloc(size);
}
void operator delete(void *address)
{
    xfree(address);
}
void *operator new[](size_t size)
{
    return xmalloc(size);
}
void operator delete[](void *address)
{
    xfree(address);
}

void *operator new(size_t size, const std::nothrow_t &tag)
{
    return xmalloc(size);
}
void operator delete(void *address, const std::nothrow_t &tag)
{
    xfree(address);
}
void *operator new[](size_t size, const std::nothrow_t &tag)
{
    return xmalloc(size);
}
void operator delete[](void *address, const std::nothrow_t &tag)
{
    xfree(address);
}

#endif /* !defined(__clang__) */

