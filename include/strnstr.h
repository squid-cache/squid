/*
 * Squid VCS $Id$
 */
#include "config.h"

#if HAVE_STRNSTR

/* Is strnstr exists and is usablewe do so. */
#define squid_strnstr(a,b,c)	strnstr(a,b,c)

#else /* not HAVE_STRNSTR */

/* If its not usable we have our own copy imported from FreeBSD */
const char * squid_strnstr(const char *s, const char *find, size_t slen);

#endif /* HAVE_STRNSTR*/
