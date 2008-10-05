/*
 * $Id$
 */
#ifndef _SQUIDINC_STRTOLL_H
#define _SQUIDINC_STRTOLL_H

#include "config.h"

#if HAVE_STRTOLL

/*
 * Get strtoll() declaration.
 */
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

#else

/**
\par
* Convert a string to a int64 integer.
\par
* Ignores `locale' stuff.  Assumes that the upper and lower case
* alphabets and digits are each contiguous.
*/
SQUIDCEXTERN int64_t strtoll(const char *nptr, char **endptr, int base);

#endif /* !HAVE_STRTOLL */

#endif /* _SQUIDINC_STRTOLL_H */
