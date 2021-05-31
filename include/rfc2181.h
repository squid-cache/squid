/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_INCLUDE_RFC1123_H
#define _SQUID_INCLUDE_RFC1123_H

/**
 \par RFC 2181 section 11:
 *  A full domain name is limited to 255 octets (including the separators).
 *
 \par RFC 1123 section 2.1:
 *  Host software MUST handle host names of up to 63 characters and
 *  SHOULD handle host names of up to 255 characters.
 *
 *\par
 *  Also Ref: RFC 1035 Section 3.1  (RFC1035_MAXHOSTNAMESZ)
 *
 \par
 *  Squid accepts up to 255 character Hostname and Fully-Qualified Domain Names.
 *  Squid still NULL-terminates its FQDN and hotsname strings.
 */
#define RFC2181_MAXHOSTNAMELEN  256

/** Back-port macro for old squid code still using SQUIDHOSTNAMELEN without RFC reference. */
#define SQUIDHOSTNAMELEN    RFC2181_MAXHOSTNAMELEN

#endif /* _SQUID_INCLUDE_RFC1123_H */

