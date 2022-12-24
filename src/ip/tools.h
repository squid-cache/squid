/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_IP_TOOLS_H
#define _SQUID_SRC_IP_TOOLS_H

namespace Ip
{

/// Probe to discover IPv6 capabilities
void ProbeTransport(void);

/* Squids notion of IPv6 stack types and state */
#define IPV6_OFF  0
#define IPV6_ON   1
#define IPV6_SPECIAL_V4MAPPING  2
#define IPV6_SPECIAL_SPLITSTACK 4

/// Whether IPv6 is supported and type of support.
extern int EnableIpv6;

} // namespace Ip

#endif /* _SQUID_SRC_IP_TOOLS_H */

