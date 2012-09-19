#ifndef SQUID_DNS_H
#define SQUID_DNS_H

#if USE_DNSHELPER
#include "helper.h"
#endif

namespace Ip
{
class Address;
}

// generic DNS API
extern void dnsInit(void);
extern void dnsShutdown(void);

#if USE_DNSHELPER
// external DNS helper API
extern void dnsSubmit(const char *lookup, HLPCB * callback, void *data);
#else
// internal DNS client API
extern void idnsALookup(const char *, IDNSCB *, void *);
extern void idnsPTRLookup(const Ip::Address &, IDNSCB *, void *);
#endif

#endif /* SQUID_DNS_H */
