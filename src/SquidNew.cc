/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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

// Squid does not use C++14 yet, but this declaration avoids a
// -Wsized-deallocation error when building with C++14 implicitly enabled.
#if __cplusplus >= 201402L
void operator delete(void *address, size_t)
{
    operator delete(address);
}
#endif

#endif /* !defined(__clang__) */

