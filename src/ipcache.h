#ifndef _SQUID_IPCACHE_H
#define _SQUID_IPCACHE_H

namespace Ip
{
class Address;
}

class DnsLookupDetails;

typedef struct _ipcache_addrs {
    Ip::Address *in_addrs;
    unsigned char *bad_mask;
    unsigned char count;
    unsigned char cur;
    unsigned char badcount;
} ipcache_addrs;

typedef void IPH(const ipcache_addrs *, const DnsLookupDetails &details, void *);

extern void ipcache_purgelru(void *);
extern void ipcache_nbgethostbyname(const char *name, IPH * handler, void *handlerData);
extern const ipcache_addrs *ipcache_gethostbyname(const char *, int flags);
extern void ipcacheInvalidate(const char *);
extern void ipcacheInvalidateNegative(const char *);
extern void ipcache_init(void);
extern void ipcacheCycleAddr(const char *name, ipcache_addrs *);
extern void ipcacheMarkBadAddr(const char *name, const Ip::Address &);
extern void ipcacheMarkGoodAddr(const char *name, const Ip::Address &);
extern void ipcacheMarkAllGood(const char *name);
extern void ipcacheFreeMemory(void);
extern ipcache_addrs *ipcacheCheckNumeric(const char *name);
extern void ipcache_restart(void);
extern int ipcacheAddEntryFromHosts(const char *name, const char *ipaddr);

#endif /* _SQUID_IPCACHE_H */
