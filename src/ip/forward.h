/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
#endif /* _SQUID_IP_FORWARD_H */

