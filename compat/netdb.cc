/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if (_SQUID_WINDOWS_ || _SQUID_MINGW_)

#include "compat/netdb.h"
#include "compat/wserrno.h"

struct hostent *
xgethostbyname(const char *name)
{
    auto result = ::gethostbyname(name);
    if (!result)
        SetErrnoFromWsaError();
    return result;
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */