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
