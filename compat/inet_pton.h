/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _INC_INET_PTON_H
#define _INC_INET_PTON_H

/* Use the system provided version where possible */
#if !HAVE_DECL_INET_PTON

/* int
* inet_pton(af, src, dst)
*      convert from presentation format (which usually means ASCII printable)
*      to network format (which is usually some kind of binary format).
* return:
*      1 if the address was valid for the specified address family
*      0 if the address wasn't valid (`dst' is untouched in this case)
*      -1 if some other error occurred (`dst' is untouched in this case, too)
* author:
*      Paul Vixie, 1996.
*/
SQUIDCEXTERN int xinet_pton(int af, const char *src, void *dst);
#ifndef inet_pton
#define inet_pton xinet_pton
#endif

#endif /* HAVE_DECL_INET_PTON */
#endif /* _INC_INET_NTOP_H */

