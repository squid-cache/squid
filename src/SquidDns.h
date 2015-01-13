/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DNS_H
#define SQUID_DNS_H

namespace Ip
{
class Address;
}

// generic DNS API
void dnsInit(void);
void dnsShutdown(void);

// internal DNS client API
void idnsALookup(const char *, IDNSCB *, void *);
void idnsPTRLookup(const Ip::Address &, IDNSCB *, void *);

#endif /* SQUID_DNS_H */

