#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef SQUID_OS_NETBSD_H
#define SQUID_OS_NETBSD_H

#ifdef _SQUID_NETBSD_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

/* Exclude CPPUnit tests from the allocator restrictions. */
/* BSD implementation uses these still */
#if defined(SQUID_UNIT_TEST)
#define SQUID_NO_ALLOC_PROTECT 1
#endif

/* NetBSD does not provide sys_errlist global for strerror */
#define NEED_SYS_ERRLIST 1

#endif /* _SQUID_NETBSD_ */
#endif /* SQUID_OS_NETBSD_H */
