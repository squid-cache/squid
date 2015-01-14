/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/shm.h"

#if _SQUID_FREEBSD_ && (__FreeBSD__ >= 7)
#include <sys/sysctl.h>
#endif

/*
 * Some systems have filesystem-based resources and interpret segment names
 * as file paths. The so-called 'portable' "/name" format does not work well
 * for them. And, according to Boost::interprocess, recent FreeBSD versions
 * make this decision depending on whether the shm_open() caller is jailed!
 */
bool
shm_portable_segment_name_is_path()
{
#if _SQUID_HPUX_ || _SQUID_OSF_ || defined(__vms) || (_SQUID_FREEBSD_ && (__FreeBSD__ < 7))
    return true;
#elif _SQUID_FREEBSD_
    int jailed = 0;
    size_t len = sizeof(jailed);
    ::sysctlbyname("security.jail.jailed", &jailed, &len, NULL, 0);
    return !jailed;
#else
    return false;
#endif
}

