/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/netdb.h"

struct hostent *
xgethostbyname(const char *name)
{
    auto result = ::gethostbyname(name);
    if (!result)
        SetErrnoFromWsaError();
    return result;
}

