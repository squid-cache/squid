/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 14    IP Storage and Handling */

#ifndef _SQUID_IP_FORWARD_H
#define _SQUID_IP_FORWARD_H

// Forward-declare Ip classes needed by reference in other parts of the code
// for passing objects around without actually touching them
namespace Ip
{
class Address;
}

/// Length of buffer that needs to be allocated to old a null-terminated IP-string
// Yuck. But there are still structures that need it to be an 'integer constant'.
#define MAX_IPSTRLEN  75

typedef uint32_t nfmark_t;
typedef unsigned char tos_t;

#endif /* _SQUID_IP_FORWARD_H */

