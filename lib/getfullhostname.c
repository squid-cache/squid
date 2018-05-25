/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "getfullhostname.h"

#if HAVE_UNISTD_H
/* for gethostname() function */
#include <unistd.h>
#endif
#if HAVE_NETDB_H
/* for gethostbyname() */
#include <netdb.h>
#endif

/* for RFC 2181 constants */
#include "rfc2181.h"

/* for xstrncpy() - may need breaking out of there. */
#include "util.h"

/**
 * \retval nullptr  An error occurred.
 * \retval *        The fully qualified name (FQDN) of the current host.
 *                  Pointer is only valid until the next call to the
 *                  gethost*() functions.
 */
const char *
getfullhostname(void)
{
    const struct hostent *hp = NULL;
    // TODO: make this dynamic so the duration limit is flexible
    static char buf[RFC2181_MAXHOSTNAMELEN + 1];

    if (gethostname(buf, RFC2181_MAXHOSTNAMELEN) < 0)
        return NULL;
    // TODO: convert this to a getaddrinfo() call
    if ((hp = gethostbyname(buf)) != NULL)
        xstrncpy(buf, hp->h_name, RFC2181_MAXHOSTNAMELEN);
    return buf;
}

