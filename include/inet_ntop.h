#ifndef _INC_INET_NTOP_H
#define _INC_INET_NTOP_H

#include "config.h"

#if HAVE_INET_NTOP

/* Use the system provided version where possible */
#define xinet_ntop inet_ntop

#else

/* char *
* inet_ntop(af, src, dst, size)
*      convert a network format address to presentation format.
* return:
*      pointer to presentation format address (`dst'), or NULL (see errno).
* author:
*      Paul Vixie, 1996.
*/
SQUIDCEXTERN const char * xinet_ntop(int af, const void *src, char *dst, size_t size);

#endif

#endif /* _INC_INET_NTOP_H */
