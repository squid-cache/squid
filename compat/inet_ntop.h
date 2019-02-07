/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _INC_INET_NTOP_H
#define _INC_INET_NTOP_H

/* Use the system provided version where possible */
#if !HAVE_DECL_INET_NTOP

/* char *
* inet_ntop(af, src, dst, size)
*      convert a network format address to presentation format.
* return:
*      pointer to presentation format address (`dst'), or NULL (see errno).
* author:
*      Paul Vixie, 1996.
*/
SQUIDCEXTERN const char * xinet_ntop(int af, const void *src, char *dst, size_t size);
#ifndef inet_ntop
#define inet_ntop xinet_ntop
#endif

#endif /* HAVE_DECL_INET_NTOP */
#endif /* _INC_INET_NTOP_H */

