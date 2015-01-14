/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_NEW_H
#define SQUID_NEW_H

#if !defined(__SUNPRO_CC) && !defined(__clang__)
/* Any code using libstdc++ must have externally resolvable overloads
 * for void * operator new - which means in the .o for the binary,
 * or in a shared library. static libs don't propogate the symbol
 * so, look in the translation unit containing main() in squid
 * for the extern version in squid
 */
#include <new>

_SQUID_EXTERNNEW_ void *operator new(size_t size) throw (std::bad_alloc)
{
    return xmalloc(size);
}
_SQUID_EXTERNNEW_ void operator delete (void *address) throw()
{
    xfree(address);
}
_SQUID_EXTERNNEW_ void *operator new[] (size_t size) throw (std::bad_alloc)
{
    return xmalloc(size);
}
_SQUID_EXTERNNEW_ void operator delete[] (void *address) throw()
{
    xfree(address);
}

#endif /* !__SUNPRO_CC && !__clang__*/

#endif /* SQUID_NEW_H */

