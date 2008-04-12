#if HAVE_STRTOLL

/*
 * Get strtoll() declaration.
 */
#include <stdlib.h>

#else

/*
 * Convert a string to a int64 integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */

SQUIDCEXTERN int64_t strtoll (const char *nptr, char **endptr, int base);

#endif
