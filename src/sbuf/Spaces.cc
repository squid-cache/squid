/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "sbuf/SBuf.h"

const SBuf
spaces(size_t count)
{
    const size_t maxLength = 32;
    static_assert(count < maxLength, "Count exceeds max length");
    const static SBuf s("                                ", 32);
    return s.substr(0, count);
}

