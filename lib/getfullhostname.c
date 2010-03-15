/*
 * $Id$
 *
 * DEBUG:
 * AUTHOR: Harvest Derived
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#include "getfullhostname.h"

#if 0 /* we SHOULD NOT need ALL these here. */
#if HAVE_LIBC_H
#include <libc.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#endif /* 0 */


#if HAVE_UNISTD_H
/* for gethostname() function */
#include <unistd.h>
#endif
#if HAVE_NETDB_H && !defined(_SQUID_NETDB_H_)	/* protect on NEXTSTEP */
#define _SQUID_NETDB_H_
/* for gethostbyname() */
#include <netdb.h>
#endif

/* for RFC 2181 constants */
#include "rfc2181.h"

/* for xstrncpy() - may need breakign out of there. */
#include "util.h"

/**
 \retval NULL  An error occured.
 \retval *    The fully qualified name (FQDN) of the current host.
 *            Pointer is only valid until the next call to the gethost*() functions.
 *
 \todo Make this a squid String result so the duration limit is flexible.
 */
const char *
getfullhostname(void)
{
    const struct hostent *hp = NULL;
    static char buf[RFC2181_MAXHOSTNAMELEN + 1];

    if (gethostname(buf, RFC2181_MAXHOSTNAMELEN) < 0)
        return NULL;
    /** \todo convert this to a xgetaddrinfo() call */
    if ((hp = gethostbyname(buf)) != NULL)
        xstrncpy(buf, hp->h_name, RFC2181_MAXHOSTNAMELEN);
    return buf;
}
