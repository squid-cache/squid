#ifndef _getnameinfo_h
#define _getnameinfo_h
/*
 * Reconstructed from KAME getnameinfo.c (in lib/)
 *
 * $Id: getnameinfo.h,v 1.1 2007/12/14 05:03:25 amosjeffries Exp $
 */

#include "config.h"

#ifdef HAVE_GETNAMEINFO

/* These functions are provided by the OS */
#define xgetnameinfo	getnameinfo

#else /* !HAVE_GETNAMEINFO */

/* RFC 2553 / Posix resolver */
SQUIDCEXTERN int xgetnameinfo(const struct sockaddr *sa,
                              socklen_t salen,
                              char *host,
                              size_t hostlen,
                              char *serv,
                              size_t servlen,
                              int flags );


#endif /* HAVE_GETNAMEINFO */

#endif
