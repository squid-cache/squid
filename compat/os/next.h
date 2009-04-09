#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef SQUID_OS_NEXT_H
#define SQUID_OS_NEXT_H

#ifdef _SQUID_NEXT_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/


/*
 * Don't allow inclusion of malloc.h
 */
#if defined(HAVE_MALLOC_H)
#undef HAVE_MALLOC_H
#endif

/*
 * S_ISDIR() may not be defined on Next
 */
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if !defined(S_ISDIR)
#define S_ISDIR(mode) (((mode) & (_S_IFMT)) == (_S_IFDIR))
#endif

/*
 * WAS: lots of special wrappers labeled only 'protect NEXTSTEP'
 * I'm assuming its an incomplete definition problem on that OS.
 * Or a missing safety wrapper by the looks of the _SQUID_NETDB_H_
 *
 * Anyway, this file is included before all general non-type headers.
 * doing the include here for Next and undefining HAVE_NETDB_H will
 * save us from including it again in general.
 */
// All the hacks included this first without safety wrapping, then netdb.h.
#include <netinet/in_systm.h>
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#undef HAVE_NETDB_H
#define HAVE_NETDB_H 0


#endif /* _SQUID_NEXT_ */
#endif /* SQUID_OS_NEXT_H */
