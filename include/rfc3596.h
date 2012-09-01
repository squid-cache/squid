/*
 * AUTHOR: Amos Jeffries, Rafael Martinez Torres
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
 *  This code is copyright (C) 2007 by Treehouse Networks Ltd of
 *  New Zealand. It is published and Lisenced as an extension of
 *  squid under the same conditions as the main squid application.
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

#ifndef SQUID_RFC3596_H
#define SQUID_RFC3596_H

/* RFC 3596 extends RFC 1035 */
#include "rfc1035.h"

SQUIDCEXTERN ssize_t rfc3596BuildAQuery(const char *hostname,
                                        char *buf,
                                        size_t sz,
                                        unsigned short qid,
                                        rfc1035_query * query,
                                        ssize_t edns_sz);

SQUIDCEXTERN ssize_t rfc3596BuildAAAAQuery(const char *hostname,
        char *buf,
        size_t sz,
        unsigned short qid,
        rfc1035_query * query,
        ssize_t edns_sz);

SQUIDCEXTERN ssize_t rfc3596BuildPTRQuery4(const struct in_addr,
        char *buf,
        size_t sz,
        unsigned short qid,
        rfc1035_query * query,
        ssize_t edns_sz);

SQUIDCEXTERN ssize_t rfc3596BuildPTRQuery6(const struct in6_addr,
        char *buf,
        size_t sz,
        unsigned short qid,
        rfc1035_query * query,
        ssize_t edns_sz);

/* RFC3596 library implements RFC1035 generic host interface */
SQUIDCEXTERN ssize_t rfc3596BuildHostQuery(const char *hostname,
        char *buf,
        size_t sz,
        unsigned short qid,
        rfc1035_query * query,
        int qtype,
        ssize_t edns_sz);

/* RFC3596 section 2.1 defines new RR type AAAA as 28 */
#define RFC1035_TYPE_AAAA 28

#endif /* SQUID_RFC3596_H */
