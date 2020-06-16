/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_RFC2671_H
#define SQUID_RFC2671_H

/* RFC2671 section 7 defines new RR type OPT as 41 */
#define RFC1035_TYPE_OPT 41

SQUIDCEXTERN int rfc2671RROptPack(char *buf, size_t sz, ssize_t edns_sz);

#endif /* SQUID_RFC3596_H */

