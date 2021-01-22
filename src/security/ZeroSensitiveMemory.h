/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_ZEROSENSITIVEMEMORY_H
#define SQUID_SRC_SECURITY_ZEROSENSITIVEMEMORY_H

#if HAVE_LIMITS_H
#include <limits.h>
#endif

#if HAVE_STRING_H
#include <string.h>
#endif

#include <stdexcept>

namespace Security {

inline static void
ZeroSensitiveMemory(void *dst, const size_t len)
{
    if (!dst)
        throw std::runtime_error("Cannot clear a null buffer");
    if (len > SIZE_MAX)
        throw std::runtime_error("Cannot clear a buffer of length exceeding SIZE_MAX");

    /**
     * to zero a buffer in a more secure manner meant for a handful of purposes.
     * e.g. for password clearing matters.
     * The compiler can optimize away a memset call to gain performance here
     * making sure it does not occur.
     *
     * address in a volatile pointer avoid gcc's likes doing optimizations.
     * thus it is not mean as memset replacement which would cause a performance
     * drop.
     */
    void *(*volatile memset_fn)(void *, int, size_t) = &memset;
    (void)memset_fn(dst, 0, len);
}

} // namespace Security

#endif /* SQUID_SRC_SECURITY_ZEROSENSITIVEMEMORY_H */

