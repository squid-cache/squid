/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_MEM_SENSITIVE_H
#define SQUID_SRC_MEM_SENSITIVE_H

#include <cstring>

namespace Mem {

/// zeros the given memory area while disallowing the compiler to skip (i.e.
/// optimize away) this cleanup, unlike a regular call to std::memset() or alike
inline void
ZeroSensitiveMemory(void *dst, const size_t len)
{
    if (!len)
        return;

    assert(dst);

    volatile const auto setMemory = &std::memset;
    (void)setMemory(dst, 0, len);
}

} // namespace mem

#endif /* SQUID_SRC_MEM_SENSITIVE_H */

