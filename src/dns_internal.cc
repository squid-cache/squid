
/*
 * $Id$
 *
 * DEBUG: section 78    DNS lookups; interacts with lib/rfc1035.c
 * AUTHOR: Duane Wessels
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

#include "config.h"
#include "squid.h"
#include "event.h"
#include "CacheManager.h"
#include "SquidTime.h"
#include "Store.h"
#include "comm.h"
#include "fde.h"
#include "ip/tools.h"
#include "MemBuf.h"
#include "util.h"
#include "wordlist.h"

#if HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#if HAVE_RESOLV_H
#include <resolv.h>
#endif

/* MS Visual Studio Projects are monolithic, so we need the following
   #ifndef to exclude the internal DNS code from compile process when
   using external DNS process.
 */
#ifndef USE_DNSSERVERS
#ifdef _SQUID_WIN32_
#include "squid_windows.h"
#define REG_TCPIP_PARA_INTERFACES "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"
#define REG_TCPIP_PARA "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define REG_VXD_MSTCP "SYSTEM\\CurrentControlSet\\Services\\VxD\\MSTCP"
#endif
#ifndef _PATH_RESCONF
#define _PATH_RESCONF "/etc/resolv.conf"
#endif
#ifndef NS_DEFAULTPORT
#define NS_DEFAULTPORT 53
#endif

#ifndef NS_MAXDNAME
#define NS_MAXDNAME 1025
#endif

#ifndef MAXDNSRCH
#define MAXDNSRCH 6
#endif

/* The buffer size required to store the maximum allowed search path */
#ifndef RESOLV_BUFSZ
#define RESOLV_BUFSZ NS_MAXDNAME * MAXDNSRCH + sizeof("search ") + 1
#endif

#define IDNS_MAX_TRIES 20
#define MAX_RCODE 6
#define MAX_ATTEMPT 3
static int RcodeMatrix[MAX_RCODE][MAX_ATTEMPT];

typedef struct _idns_query idns_query;

typedef struct _ns ns;

typedef struct _sp sp;

typedef struct _nsvc nsvc;

struct _idns_query {
    hash_link hash;
    rfc1035_query query;
    char buf[RESOLV_BUFSZ];
    char name[NS_MAXDNAME + 1];
    char orig[NS_MAXDNAME + 1];
    ssize_t sz;
    unsigned short id;
    int nsends;
    int need_vc;

    struct timeval start_t;
    struct timeval sent_t;
    struct timeval queue_t;
    dlink_node lru;
    IDNSCB *callback;
    void *callback_data;
    int attempt;
    const char *error;
    int rcode;
    idns_query *queue;
    unsigned short domain;
    unsigned short do_searchpath;
    bool need_A;
    struct {
        int count;
        rfc1035_rr *answers;
    } initial_AAAA;
};

struct _nsvc {
    int ns;
    int fd;
    unsigned short msglen;
    int read_msglen;
    MemBuf *msg;
    MemBuf *queue;
    bool busy;
};

struct _ns {
    IpAddress S;
    int nqueries;
    int nreplies;
    nsvc *vc;
};

struct _sp {
    char domain[NS_MAXDNAME];
    int queries;
};

CBDATA_TYPE(nsvc);
CBDATA_TYPE(idns_query);

static ns *nameservers = NULL;
static sp *searchpath = NULL;
static int nns = 0;
static int nns_alloc = 0;
static int npc = 0;
static int npc_alloc = 0;
static int ndots = 1;
static dlink_list lru_list;
static int event_queued = 0;
static hash_table *idns_lookup_hash = NULL;

static OBJH idnsStats;
static void idnsAddNameserver(const char *buf);
static void idnsAddPathComponent(const char *buf);
static void idnsFreeNameservers(void);
static void idnsFreeSearchpath(void);
static void idnsParseNameservers(void);
#ifndef _SQUID_MSWIN_
static void idnsParseResolvConf(void);
#endif
#ifdef _SQUID_WIN32_
static void idnsParseWIN32Registry(void);
static void idnsParseWIN32SearchList(const char *);
#endif
static void idnsCacheQuery(idns_query * q);
static void idnsSendQuery(idns_query * q);
static IOCB idnsReadVCHeader;
static void idnsDoSendQueryVC(nsvc *vc);

static int idnsFromKnownNameserver(IpAddress const &from);
static idns_query *idnsFindQuery(unsigned short id);
static void idnsGrokReply(const char *buf, size_t sz);
static PF idnsRead;
static EVH idnsCheckQueue;
static void idnsTickleQueue(void);
static void idnsRcodeCount(int, int);

static void
idnsAddNameserver(const char *buf)
{
    IpAddress A;

    if (!(A = buf)) {
        debugs(78, 0, "WARNING: rejecting '" << buf << "' as a name server, because it is not a numeric IP address");
        return;
    }

    if (A.IsAnyAddr()) {
        debugs(78, 0, "WARNING: Squid does not accept " << A << " in DNS server specifications.");
        A.SetLocalhost();
        debugs(78, 0, "Will be using " << A << " instead, assuming you meant that DNS is running on the same machine");
    }

    if (!Ip::EnableIpv6 && !A.SetIPv4()) {
        debugs(78, DBG_IMPORTANT, "WARNING: IPv6 is disabled. Discarding " << A << " in DNS server specifications.");
        return;
    }

    if (nns == nns_alloc) {
        int oldalloc = nns_alloc;
        ns *oldptr = nameservers;

        if (nns_alloc == 0)
            nns_alloc = 2;
        else
            nns_alloc <<= 1;

        nameservers = (ns *)xcalloc(nns_alloc, sizeof(*nameservers));

        if (oldptr && oldalloc)
            xmemcpy(nameservers, oldptr, oldalloc * sizeof(*nameservers));

        if (oldptr)
            safe_free(oldptr);
    }

    assert(nns < nns_alloc);
    A.SetPort(NS_DEFAULTPORT);
    nameservers[nns].S = A;
    debugs(78, 3, "idnsAddNameserver: Added nameserver #" << nns << " (" << A << ")");
    nns++;
}

static void
idnsAddPathComponent(const char *buf)
{
    if (npc == npc_alloc) {
        int oldalloc = npc_alloc;
        sp *oldptr = searchpath;

        if (0 == npc_alloc)
            npc_alloc = 2;
        else
            npc_alloc <<= 1;

        searchpath = (sp *)xcalloc(npc_alloc, sizeof(*searchpath));

        if (oldptr && oldalloc)
            xmemcpy(searchpath, oldptr, oldalloc * sizeof(*searchpath));

        if (oldptr)
            safe_free(oldptr);
    }

    assert(npc < npc_alloc);
    strcpy(searchpath[npc].domain, buf);
    Tolower(searchpath[npc].domain);
    debugs(78, 3, "idnsAddPathComponent: Added domain #" << npc << ": " << searchpath[npc].domain);
    npc++;
}


static void
idnsFreeNameservers(void)
{
    safe_free(nameservers);
    nns = nns_alloc = 0;
}

static void
idnsFreeSearchpath(void)
{
    safe_free(searchpath);
    npc = npc_alloc = 0;
}



static void
idnsParseNameservers(void)
{
    wordlist *w;

    for (w = Config.dns_nameservers; w; w = w->next) {
        debugs(78, 1, "Adding nameserver " << w->key << " from squid.conf");
        idnsAddNameserver(w->key);
    }
}

#ifndef _SQUID_MSWIN_
static void
idnsParseResolvConf(void)
{
    FILE *fp;
    char buf[RESOLV_BUFSZ];
    const char *t;
    fp = fopen(_PATH_RESCONF, "r");

    if (fp == NULL) {
        debugs(78, 1, "" << _PATH_RESCONF << ": " << xstrerror());
        return;
    }

#if defined(_SQUID_CYGWIN_)
    setmode(fileno(fp), O_TEXT);

#endif

    while (fgets(buf, RESOLV_BUFSZ, fp)) {
        t = strtok(buf, w_space);

        if (NULL == t) {
            continue;
        } else if (strcasecmp(t, "nameserver") == 0) {
            t = strtok(NULL, w_space);

            if (NULL == t)
                continue;

            debugs(78, 1, "Adding nameserver " << t << " from " << _PATH_RESCONF);

            idnsAddNameserver(t);
        } else if (strcasecmp(t, "domain") == 0) {
            idnsFreeSearchpath();
            t = strtok(NULL, w_space);

            if (NULL == t)
                continue;

            debugs(78, 1, "Adding domain " << t << " from " << _PATH_RESCONF);

            idnsAddPathComponent(t);
        } else if (strcasecmp(t, "search") == 0) {
            idnsFreeSearchpath();
            while (NULL != t) {
                t = strtok(NULL, w_space);

                if (NULL == t)
                    continue;

                debugs(78, 1, "Adding domain " << t << " from " << _PATH_RESCONF);

                idnsAddPathComponent(t);
            }
        } else if (strcasecmp(t, "options") == 0) {
            while (NULL != t) {
                t = strtok(NULL, w_space);

                if (NULL == t)
                    continue;

                if (strncmp(t, "ndots:", 6) == 0) {
                    ndots = atoi(t + 6);

                    if (ndots < 1)
                        ndots = 1;

                    debugs(78, 1, "Adding ndots " << ndots << " from " << _PATH_RESCONF);
                }
            }
        }
    }
    if (npc == 0 && (t = getMyHostname())) {
        t = strchr(t, '.');
        if (t)
            idnsAddPathComponent(t+1);
    }

    fclose(fp);
}

#endif

#ifdef _SQUID_WIN32_
static void
idnsParseWIN32SearchList(const char * Separator)
{
    char *t;
    char *token;
    HKEY hndKey;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_TCPIP_PARA, 0, KEY_QUERY_VALUE, &hndKey) == ERROR_SUCCESS) {
        DWORD Type = 0;
        DWORD Size = 0;
        LONG Result;
        Result = RegQueryValueEx(hndKey, "Domain", NULL, &Type, NULL, &Size);

        if (Result == ERROR_SUCCESS && Size) {
            t = (char *) xmalloc(Size);
            RegQueryValueEx(hndKey, "Domain", NULL, &Type, (LPBYTE) t, &Size);
            debugs(78, 1, "Adding domain " << t << " from Registry");
            idnsAddPathComponent(t);
            xfree(t);
        }
        Result = RegQueryValueEx(hndKey, "SearchList", NULL, &Type, NULL, &Size);

        if (Result == ERROR_SUCCESS && Size) {
            t = (char *) xmalloc(Size);
            RegQueryValueEx(hndKey, "SearchList", NULL, &Type, (LPBYTE) t, &Size);
            token = strtok(t, Separator);

            while (token) {
                idnsAddPathComponent(token);
                debugs(78, 1, "Adding domain " << token << " from Registry");
                token = strtok(NULL, Separator);
            }
            xfree(t);
        }

        RegCloseKey(hndKey);
    }
    if (npc == 0 && (t = (char *) getMyHostname())) {
        t = strchr(t, '.');
        if (t)
            idnsAddPathComponent(t + 1);
    }
}

static void
idnsParseWIN32Registry(void)
{
    char *t;
    char *token;
    HKEY hndKey, hndKey2;

    switch (WIN32_OS_version) {

    case _WIN_OS_WINNT:
        /* get nameservers from the Windows NT registry */

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_TCPIP_PARA, 0, KEY_QUERY_VALUE, &hndKey) == ERROR_SUCCESS) {
            DWORD Type = 0;
            DWORD Size = 0;
            LONG Result;
            Result = RegQueryValueEx(hndKey, "DhcpNameServer", NULL, &Type, NULL, &Size);

            if (Result == ERROR_SUCCESS && Size) {
                t = (char *) xmalloc(Size);
                RegQueryValueEx(hndKey, "DhcpNameServer", NULL, &Type, (LPBYTE) t, &Size);
                token = strtok(t, ", ");

                while (token) {
                    idnsAddNameserver(token);
                    debugs(78, 1, "Adding DHCP nameserver " << token << " from Registry");
                    token = strtok(NULL, ",");
                }
                xfree(t);
            }

            Result = RegQueryValueEx(hndKey, "NameServer", NULL, &Type, NULL, &Size);

            if (Result == ERROR_SUCCESS && Size) {
                t = (char *) xmalloc(Size);
                RegQueryValueEx(hndKey, "NameServer", NULL, &Type, (LPBYTE) t, &Size);
                token = strtok(t, ", ");

                while (token) {
                    debugs(78, 1, "Adding nameserver " << token << " from Registry");
                    idnsAddNameserver(token);
                    token = strtok(NULL, ", ");
                }
                xfree(t);
            }

            RegCloseKey(hndKey);
        }

        idnsParseWIN32SearchList(" ");

        break;

    case _WIN_OS_WIN2K:

    case _WIN_OS_WINXP:

    case _WIN_OS_WINNET:

    case _WIN_OS_WINLON:

    case _WIN_OS_WIN7:
        /* get nameservers from the Windows 2000 registry */
        /* search all interfaces for DNS server addresses */

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_TCPIP_PARA_INTERFACES, 0, KEY_READ, &hndKey) == ERROR_SUCCESS) {
            int i;
            DWORD MaxSubkeyLen, InterfacesCount;
            char *keyname;
            FILETIME ftLastWriteTime;

            if (RegQueryInfoKey(hndKey, NULL, NULL, NULL, &InterfacesCount, &MaxSubkeyLen, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                keyname = (char *) xmalloc(++MaxSubkeyLen);
                for (i = 0; i < (int) InterfacesCount; i++) {
                    DWORD j;
                    j = MaxSubkeyLen;
                    if (RegEnumKeyEx(hndKey, i, keyname, &j, NULL, NULL, NULL, &ftLastWriteTime) == ERROR_SUCCESS) {
                        char *newkeyname;
                        newkeyname = (char *) xmalloc(sizeof(REG_TCPIP_PARA_INTERFACES) + j + 2);
                        strcpy(newkeyname, REG_TCPIP_PARA_INTERFACES);
                        strcat(newkeyname, "\\");
                        strcat(newkeyname, keyname);
                        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, newkeyname, 0, KEY_QUERY_VALUE, &hndKey2) == ERROR_SUCCESS) {
                            DWORD Type = 0;
                            DWORD Size = 0;
                            LONG Result;
                            Result = RegQueryValueEx(hndKey2, "DhcpNameServer", NULL, &Type, NULL, &Size);
                            if (Result == ERROR_SUCCESS && Size) {
                                t = (char *) xmalloc(Size);
                                RegQueryValueEx(hndKey2, "DhcpNameServer", NULL, &Type, (LPBYTE)t, &Size);
                                token = strtok(t, ", ");
                                while (token) {
                                    debugs(78, 1, "Adding DHCP nameserver " << token << " from Registry");
                                    idnsAddNameserver(token);
                                    token = strtok(NULL, ", ");
                                }
                                xfree(t);
                            }

                            Result = RegQueryValueEx(hndKey2, "NameServer", NULL, &Type, NULL, &Size);
                            if (Result == ERROR_SUCCESS && Size) {
                                t = (char *) xmalloc(Size);
                                RegQueryValueEx(hndKey2, "NameServer", NULL, &Type, (LPBYTE)t, &Size);
                                token = strtok(t, ", ");
                                while (token) {
                                    debugs(78, 1, "Adding nameserver " << token << " from Registry");
                                    idnsAddNameserver(token);
                                    token = strtok(NULL, ", ");
                                }

                                xfree(t);
                            }

                            RegCloseKey(hndKey2);
                        }

                        xfree(newkeyname);
                    }
                }

                xfree(keyname);
            }

            RegCloseKey(hndKey);
        }

        idnsParseWIN32SearchList(", ");

        break;

    case _WIN_OS_WIN95:

    case _WIN_OS_WIN98:

    case _WIN_OS_WINME:
        /* get nameservers from the Windows 9X registry */

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_VXD_MSTCP, 0, KEY_QUERY_VALUE, &hndKey) == ERROR_SUCCESS) {
            DWORD Type = 0;
            DWORD Size = 0;
            LONG Result;
            Result = RegQueryValueEx(hndKey, "NameServer", NULL, &Type, NULL, &Size);

            if (Result == ERROR_SUCCESS && Size) {
                t = (char *) xmalloc(Size);
                RegQueryValueEx(hndKey, "NameServer", NULL, &Type, (LPBYTE) t, &Size);
                token = strtok(t, ", ");

                while (token) {
                    debugs(78, 1, "Adding nameserver " << token << " from Registry");
                    idnsAddNameserver(token);
                    token = strtok(NULL, ", ");
                }
                xfree(t);
            }

            RegCloseKey(hndKey);
        }

        break;

    default:
        debugs(78, 1, "Failed to read nameserver from Registry: Unknown System Type.");
        return;
    }
}

#endif

static void
idnsStats(StoreEntry * sentry)
{
    dlink_node *n;
    idns_query *q;
    int i;
    int j;
    char buf[MAX_IPSTRLEN];
    storeAppendPrintf(sentry, "Internal DNS Statistics:\n");
    storeAppendPrintf(sentry, "\nThe Queue:\n");
    storeAppendPrintf(sentry, "                       DELAY SINCE\n");
    storeAppendPrintf(sentry, "  ID   SIZE SENDS FIRST SEND LAST SEND\n");
    storeAppendPrintf(sentry, "------ ---- ----- ---------- ---------\n");

    for (n = lru_list.head; n; n = n->next) {
        q = (idns_query *)n->data;
        storeAppendPrintf(sentry, "%#06x %4d %5d %10.3f %9.3f\n",
                          (int) q->id, (int) q->sz, q->nsends,
                          tvSubDsec(q->start_t, current_time),
                          tvSubDsec(q->sent_t, current_time));
    }

    storeAppendPrintf(sentry, "\nNameservers:\n");
    storeAppendPrintf(sentry, "IP ADDRESS                                     # QUERIES # REPLIES\n");
    storeAppendPrintf(sentry, "---------------------------------------------- --------- ---------\n");

    for (i = 0; i < nns; i++) {
        storeAppendPrintf(sentry, "%-45s %9d %9d\n",  /* Let's take the maximum: (15 IPv4/45 IPv6) */
                          nameservers[i].S.NtoA(buf,MAX_IPSTRLEN),
                          nameservers[i].nqueries,
                          nameservers[i].nreplies);
    }

    storeAppendPrintf(sentry, "\nRcode Matrix:\n");
    storeAppendPrintf(sentry, "RCODE");

    for (i = 0; i < MAX_ATTEMPT; i++)
        storeAppendPrintf(sentry, " ATTEMPT%d", i + 1);

    storeAppendPrintf(sentry, "\n");

    for (j = 0; j < MAX_RCODE; j++) {
        storeAppendPrintf(sentry, "%5d", j);

        for (i = 0; i < MAX_ATTEMPT; i++)
            storeAppendPrintf(sentry, " %8d", RcodeMatrix[j][i]);

        storeAppendPrintf(sentry, "\n");
    }

    if (npc) {
        storeAppendPrintf(sentry, "\nSearch list:\n");

        for (i=0; i < npc; i++)
            storeAppendPrintf(sentry, "%s\n", searchpath[i].domain);

        storeAppendPrintf(sentry, "\n");
    }
}

static void
idnsTickleQueue(void)
{
    if (event_queued)
        return;

    if (NULL == lru_list.tail)
        return;

    eventAdd("idnsCheckQueue", idnsCheckQueue, NULL, 1.0, 1);

    event_queued = 1;
}

static void
idnsSentQueryVC(int fd, char *buf, size_t size, comm_err_t flag, int xerrno, void *data)
{
    nsvc * vc = (nsvc *)data;

    if (flag == COMM_ERR_CLOSING)
        return;

    if (fd_table[fd].closing())
        return;

    if (flag != COMM_OK || size <= 0) {
        comm_close(fd);
        return;
    }

    vc->busy = 0;
    idnsDoSendQueryVC(vc);
}

static void
idnsDoSendQueryVC(nsvc *vc)
{
    if (vc->busy)
        return;

    if (vc->queue->contentSize() == 0)
        return;

    MemBuf *mb = vc->queue;

    vc->queue = new MemBuf;

    vc->busy = 1;

    commSetTimeout(vc->fd, Config.Timeout.idns_query, NULL, NULL);

    comm_write_mbuf(vc->fd, mb, idnsSentQueryVC, vc);

    delete mb;
}

static void
idnsInitVCConnected(int fd, const DnsLookupDetails &details, comm_err_t status, int xerrno, void *data)
{
    nsvc * vc = (nsvc *)data;

    if (status != COMM_OK) {
        char buf[MAX_IPSTRLEN] = "";
        if (vc->ns < nns)
            nameservers[vc->ns].S.NtoA(buf,MAX_IPSTRLEN);
        debugs(78, 1, HERE << "Failed to connect to nameserver " << buf << " using TCP: " << details);
        comm_close(fd);
        return;
    }

    comm_read(fd, (char *)&vc->msglen, 2 , idnsReadVCHeader, vc);
    vc->busy = 0;
    idnsDoSendQueryVC(vc);
}

static void
idnsVCClosed(int fd, void *data)
{
    nsvc * vc = (nsvc *)data;
    delete vc->queue;
    delete vc->msg;
    if (vc->ns < nns) // XXX: idnsShutdown may have freed nameservers[]
        nameservers[vc->ns].vc = NULL;
    cbdataFree(vc);
}

static void
idnsInitVC(int ns)
{
    char buf[MAX_IPSTRLEN];

    nsvc *vc = cbdataAlloc(nsvc);
    assert(ns < nns);
    nameservers[ns].vc = vc;
    vc->ns = ns;

    IpAddress addr;

    if (!Config.Addrs.udp_outgoing.IsNoAddr())
        addr = Config.Addrs.udp_outgoing;
    else
        addr = Config.Addrs.udp_incoming;

    if (nameservers[ns].S.IsIPv4() && !addr.SetIPv4()) {
        debugs(31, DBG_CRITICAL, "ERROR: Cannot contact DNS nameserver " << nameservers[ns].S << " from " << addr);
        addr.SetAnyAddr();
        addr.SetIPv4();
    }

    vc->queue = new MemBuf;

    vc->msg = new MemBuf;

    vc->fd = comm_open(SOCK_STREAM,
                       IPPROTO_TCP,
                       addr,
                       COMM_NONBLOCKING,
                       "DNS TCP Socket");

    if (vc->fd < 0)
        fatal("Could not create a DNS socket");

    comm_add_close_handler(vc->fd, idnsVCClosed, vc);

    vc->busy = 1;

    commConnectStart(vc->fd, nameservers[ns].S.NtoA(buf,MAX_IPSTRLEN), nameservers[ns].S.GetPort(), idnsInitVCConnected, vc);
}

static void
idnsSendQueryVC(idns_query * q, int ns)
{
    assert(ns < nns);
    if (nameservers[ns].vc == NULL)
        idnsInitVC(ns);

    nsvc *vc = nameservers[ns].vc;

    if (!vc) {
        char buf[MAX_IPSTRLEN];
        debugs(78, 1, "idnsSendQuery: Failed to initiate TCP connection to nameserver " << nameservers[ns].S.NtoA(buf,MAX_IPSTRLEN) << "!");

        return;
    }

    vc->queue->reset();

    short head = htons(q->sz);

    vc->queue->append((char *)&head, 2);

    vc->queue->append(q->buf, q->sz);

    idnsDoSendQueryVC(vc);
}

static void
idnsSendQuery(idns_query * q)
{
    if (DnsSocketA < 0 && DnsSocketB < 0) {
        debugs(78, 1, "WARNING: idnsSendQuery: Can't send query, no DNS socket!");
        return;
    }

    if (nns <= 0) {
        debugs(78, 1, "WARNING: idnsSendQuery: Can't send query, no DNS nameservers known!");
        return;
    }

    assert(q->lru.next == NULL);

    assert(q->lru.prev == NULL);

    int x = -1, y = -1;
    int ns;

    do {
        ns = q->nsends % nns;

        if (q->need_vc) {
            idnsSendQueryVC(q, ns);
            x = y = 0;
        } else {
            if (DnsSocketB >= 0 && nameservers[ns].S.IsIPv6())
                y = comm_udp_sendto(DnsSocketB, nameservers[ns].S, q->buf, q->sz);
            else if (DnsSocketA)
                x = comm_udp_sendto(DnsSocketA, nameservers[ns].S, q->buf, q->sz);
        }

        q->nsends++;

        q->queue_t = q->sent_t = current_time;

        if (y < 0 && nameservers[ns].S.IsIPv6())
            debugs(50, 1, "idnsSendQuery: FD " << DnsSocketB << ": sendto: " << xstrerror());
        if (x < 0 && nameservers[ns].S.IsIPv4())
            debugs(50, 1, "idnsSendQuery: FD " << DnsSocketA << ": sendto: " << xstrerror());

    } while ( (x<0 && y<0) && q->nsends % nns != 0);

    if (y > 0) {
        fd_bytes(DnsSocketB, y, FD_WRITE);
    }
    if (x > 0) {
        fd_bytes(DnsSocketA, x, FD_WRITE);
    }

    nameservers[ns].nqueries++;
    q->queue_t = current_time;
    dlinkAdd(q, &q->lru, &lru_list);
    idnsTickleQueue();
}

static int
idnsFromKnownNameserver(IpAddress const &from)
{
    int i;

    for (i = 0; i < nns; i++) {
        if (nameservers[i].S != from)
            continue;

        if (nameservers[i].S.GetPort() != from.GetPort())
            continue;

        return i;
    }

    return -1;
}

static idns_query *
idnsFindQuery(unsigned short id)
{
    dlink_node *n;
    idns_query *q;

    for (n = lru_list.tail; n; n = n->prev) {
        q = (idns_query*)n->data;

        if (q->id == id)
            return q;
    }

    return NULL;
}

static unsigned short
idnsQueryID(void)
{
    unsigned short id = squid_random() & 0xFFFF;
    unsigned short first_id = id;

    while (idnsFindQuery(id)) {
        id++;

        if (id == first_id) {
            debugs(78, 1, "idnsQueryID: Warning, too many pending DNS requests");
            break;
        }
    }

    return id;
}

static void
idnsCallback(idns_query *q, rfc1035_rr *answers, int n, const char *error)
{
    IDNSCB *callback;
    void *cbdata;

    callback = q->callback;
    q->callback = NULL;

    if (cbdataReferenceValidDone(q->callback_data, &cbdata))
        callback(cbdata, answers, n, error);

    while (q->queue) {
        idns_query *q2 = q->queue;
        q->queue = q2->queue;
        callback = q2->callback;
        q2->callback = NULL;

        if (cbdataReferenceValidDone(q2->callback_data, &cbdata))
            callback(cbdata, answers, n, error);

        cbdataFree(q2);
    }

    if (q->hash.key) {
        hash_remove_link(idns_lookup_hash, &q->hash);
        q->hash.key = NULL;
    }
}

void
idnsDropMessage(rfc1035_message *message, idns_query *q)
{
    rfc1035MessageDestroy(&message);
    if (q->hash.key) {
        hash_remove_link(idns_lookup_hash, &q->hash);
        q->hash.key = NULL;
    }
}

static void
idnsGrokReply(const char *buf, size_t sz)
{
    int n;
    rfc1035_message *message = NULL;
    idns_query *q;

    n = rfc1035MessageUnpack(buf, sz, &message);

    if (message == NULL) {
        debugs(78, 1, "idnsGrokReply: Malformed DNS response");
        return;
    }

    debugs(78, 3, "idnsGrokReply: ID 0x" << std::hex << message->id << ", " << std::dec << n << " answers");

    q = idnsFindQuery(message->id);

    if (q == NULL) {
        debugs(78, 3, "idnsGrokReply: Late response");
        rfc1035MessageDestroy(&message);
        return;
    }

    if (rfc1035QueryCompare(&q->query, message->query) != 0) {
        debugs(78, 3, "idnsGrokReply: Query mismatch (" << q->query.name << " != " << message->query->name << ")");
        rfc1035MessageDestroy(&message);
        return;
    }

    if (message->tc) {
        debugs(78, 3, HERE << "Resolver requested TC (" << q->query.name << ")");
        dlinkDelete(&q->lru, &lru_list);
        rfc1035MessageDestroy(&message);

        if (!q->need_vc) {
            q->need_vc = 1;
            q->nsends--;
            idnsSendQuery(q);
        }

        return;
    }

    dlinkDelete(&q->lru, &lru_list);
    idnsRcodeCount(n, q->attempt);
    q->error = NULL;

    if (n < 0) {
        debugs(78, 3, "idnsGrokReply: error " << rfc1035_error_message << " (" << rfc1035_errno << ")");

        q->error = rfc1035_error_message;
        q->rcode = -n;

        if (q->rcode == 2 && ++q->attempt < MAX_ATTEMPT) {
            /*
             * RCODE 2 is "Server failure - The name server was
             * unable to process this query due to a problem with
             * the name server."
             */
            debugs(78, 3, "idnsGrokReply: Query result: SERV_FAIL");
            rfc1035MessageDestroy(&message);
            q->start_t = current_time;
            q->id = idnsQueryID();
            rfc1035SetQueryID(q->buf, q->id);
            idnsSendQuery(q);
            return;
        }

        if (q->rcode == 3 && q->do_searchpath && q->attempt < MAX_ATTEMPT) {
            assert(NULL == message->answer);
            strcpy(q->name, q->orig);

            debugs(78, 3, "idnsGrokReply: Query result: NXDOMAIN - " << q->name );

            if (q->domain < npc) {
                strcat(q->name, ".");
                strcat(q->name, searchpath[q->domain].domain);
                debugs(78, 3, "idnsGrokReply: searchpath used for " << q->name);
                q->domain++;
            } else {
                q->attempt++;
            }

            idnsDropMessage(message, q);

            q->start_t = current_time;
            q->id = idnsQueryID();
            rfc1035SetQueryID(q->buf, q->id);
            if (Ip::EnableIpv6 && q->query.qtype == RFC1035_TYPE_AAAA) {
                debugs(78, 3, "idnsGrokReply: Trying AAAA Query for " << q->name);
                q->sz = rfc3596BuildAAAAQuery(q->name, q->buf, sizeof(q->buf), q->id, &q->query);
            } else {
                debugs(78, 3, "idnsGrokReply: Trying A Query for " << q->name);
                q->sz = rfc3596BuildAQuery(q->name, q->buf, sizeof(q->buf), q->id, &q->query);
            }

            if (q->sz < 0) {
                /* problem with query data -- query not sent */
                idnsCallback(static_cast<idns_query *>(q->callback_data), NULL, 0, "Internal error");
                cbdataFree(q);
                return;
            }

            idnsCacheQuery(q);
            idnsSendQuery(q);
            return;
        }
    }

    if (q->need_A && (Config.onoff.dns_require_A == 1 || n <= 0 ) ) {
        /* ERROR or NO AAAA exist. Failover to A records. */
        /*      Apparently its also a good idea to lookup and store the A records
         *      just in case the AAAA are not available when we need them.
         *      This could occur due to number of network failings beyond our control
         *      thus the || above allowing the user to request always both.
         */

        if (n == 0)
            debugs(78, 3, "idnsGrokReply: " << q->name << " has no AAAA records. Looking up A record instead.");
        else if (q->need_A && n <= 0)
            debugs(78, 3, "idnsGrokReply: " << q->name << " AAAA query failed. Trying A now instead.");
        else // admin requested this.
            debugs(78, 3, "idnsGrokReply: " << q->name << " AAAA query done. Configured to retrieve A now also.");

        // move the initial message results into the failover query for merging later.
        if (n > 0) {
            q->initial_AAAA.count = message->ancount;
            q->initial_AAAA.answers = message->answer;
            message->answer = NULL;
        }

        // remove the hashed query info
        idnsDropMessage(message, q);

        // reset the query as an A query
        q->nsends = 0;
        q->start_t = current_time;
        q->id = idnsQueryID();
        rfc1035SetQueryID(q->buf, q->id);
        q->sz = rfc3596BuildAQuery(q->name, q->buf, sizeof(q->buf), q->id, &q->query);
        q->need_A = false;

        if (q->sz < 0) {
            /* problem with query data -- query not sent */
            idnsCallback(static_cast<idns_query *>(q->callback_data), NULL, 0, "Internal error");
            cbdataFree(q);
            return;
        }

        idnsCacheQuery(q);
        idnsSendQuery(q);
        return;
    }

    /** If there are two result sets from preceeding AAAA and A lookups merge them with a preference for AAAA */
    if (q->initial_AAAA.count > 0 && n > 0) {
        /* two sets of RR need merging */
        rfc1035_rr *result = (rfc1035_rr*) xmalloc( sizeof(rfc1035_rr)*(n + q->initial_AAAA.count) );
        rfc1035_rr *tmp = result;

        debugs(78, 6, HERE << "Merging DNS results " << q->name << " AAAA has " << q->initial_AAAA.count << " RR, A has " << n << " RR");

        memcpy(tmp, q->initial_AAAA.answers, (sizeof(rfc1035_rr)*(q->initial_AAAA.count)) );
        tmp += q->initial_AAAA.count;
        /* free the RR object without freeing its child strings (they are now taken by the copy above) */
        safe_free(q->initial_AAAA.answers);

        memcpy( tmp, message->answer, (sizeof(rfc1035_rr)*n) );
        /* free the RR object without freeing its child strings (they are now taken by the copy above) */
        safe_free(message->answer);

        message->answer = result;
        message->ancount += q->initial_AAAA.count;
        n += q->initial_AAAA.count;
        q->initial_AAAA.count=0;
    } else if (q->initial_AAAA.count > 0 && n <= 0) {
        /* initial of dual queries was the only result set. */
        debugs(78, 6, HERE << "Merging DNS results " << q->name << " AAAA has " << q->initial_AAAA.count << " RR, A has " << n << " RR");
        rfc1035RRDestroy(&(message->answer), n);
        message->answer = q->initial_AAAA.answers;
        n = q->initial_AAAA.count;
    }
    /* else initial results were empty. just use the final set as authoritative */

    debugs(78, 6, HERE << "Sending " << n << " DNS results to caller.");
    idnsCallback(q, message->answer, n, q->error);
    rfc1035MessageDestroy(&message);
    cbdataFree(q);
}

static void
idnsRead(int fd, void *data)
{
    int *N = &incoming_sockets_accepted;
    int len;
    int max = INCOMING_DNS_MAX;
    static char rbuf[SQUID_UDP_SO_RCVBUF];
    int ns;
    IpAddress from;

    debugs(78, 3, "idnsRead: starting with FD " << fd);

    // Always keep reading. This stops (or at least makes harder) several
    // attacks on the DNS client.
    commSetSelect(fd, COMM_SELECT_READ, idnsRead, NULL, 0);

    /* BUG (UNRESOLVED)
     *  two code lines after returning from comm_udprecvfrom()
     *  something overwrites the memory behind the from parameter.
     *  NO matter where in the stack declaration list above it is placed
     *  The cause of this is still unknown, however copying the data appears
     *  to allow it to be passed further without this erasure.
     */
    IpAddress bugbypass;

    while (max--) {
        len = comm_udp_recvfrom(fd, rbuf, SQUID_UDP_SO_RCVBUF, 0, bugbypass);

        from = bugbypass; // BUG BYPASS. see notes above.

        if (len == 0)
            break;

        if (len < 0) {
            if (ignoreErrno(errno))
                break;

#ifdef _SQUID_LINUX_
            /* Some Linux systems seem to set the FD for reading and then
             * return ECONNREFUSED when sendto() fails and generates an ICMP
             * port unreachable message. */
            /* or maybe an EHOSTUNREACH "No route to host" message */
            if (errno != ECONNREFUSED && errno != EHOSTUNREACH)
#endif

                debugs(50, 1, "idnsRead: FD " << fd << " recvfrom: " << xstrerror());

            break;
        }

        fd_bytes(fd, len, FD_READ);

        assert(N);
        (*N)++;

        debugs(78, 3, "idnsRead: FD " << fd << ": received " << len << " bytes from " << from);

        /* BUG: see above. Its here that it becomes apparent that the content of bugbypass is gone. */
        ns = idnsFromKnownNameserver(from);

        if (ns >= 0) {
            nameservers[ns].nreplies++;
        }

        // Before unknown_nameservers check to avoid flooding cache.log on attacks,
        // but after the ++ above to keep statistics right.
        if (!lru_list.head)
            continue; // Don't process replies if there is no pending query.

        if (ns < 0 && Config.onoff.ignore_unknown_nameservers) {
            static time_t last_warning = 0;

            if (squid_curtime - last_warning > 60) {
                debugs(78, 1, "WARNING: Reply from unknown nameserver " << from);
                last_warning = squid_curtime;
            } else {
                debugs(78, 1, "WARNING: Reply from unknown nameserver " << from << " (retrying..." <<  (squid_curtime-last_warning) << "<=60)" );
            }
            continue;
        }

        idnsGrokReply(rbuf, len);
    }
}

static void
idnsCheckQueue(void *unused)
{
    dlink_node *n;
    dlink_node *p = NULL;
    idns_query *q;
    event_queued = 0;

    if (0 == nns)
        /* name servers went away; reconfiguring or shutting down */
        return;

    for (n = lru_list.tail; n; n = p) {

        p = n->prev;
        q = static_cast<idns_query*>(n->data);

        /* Anything to process in the queue? */
        if (tvSubDsec(q->queue_t, current_time) < Config.Timeout.idns_retransmit )
            break;

        /* Query timer expired? */
        if (tvSubDsec(q->sent_t, current_time) < Config.Timeout.idns_retransmit * 1 << ((q->nsends - 1) / nns)) {
            dlinkDelete(&q->lru, &lru_list);
            q->queue_t = current_time;
            dlinkAdd(q, &q->lru, &lru_list);
            continue;
        }

        debugs(78, 3, "idnsCheckQueue: ID 0x" << std::hex << std::setfill('0') << std::setw(4) << q->id << "timeout" );

        dlinkDelete(&q->lru, &lru_list);

        if (tvSubDsec(q->start_t, current_time) < Config.Timeout.idns_query) {
            idnsSendQuery(q);
        } else {
            debugs(78, 2, "idnsCheckQueue: ID " << std::hex << q->id <<
                   ": giving up after " << std::dec << q->nsends << " tries and " <<
                   std::setw(5)<< std::setprecision(2) << tvSubDsec(q->start_t, current_time) << " seconds");

            if (q->rcode != 0)
                idnsCallback(q, NULL, -q->rcode, q->error);
            else
                idnsCallback(q, NULL, -16, "Timeout");

            cbdataFree(q);
        }
    }

    idnsTickleQueue();
}

static void
idnsReadVC(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    nsvc * vc = (nsvc *)data;

    if (flag == COMM_ERR_CLOSING)
        return;

    if (flag != COMM_OK || len <= 0) {
        comm_close(fd);
        return;
    }

    vc->msg->size += len;       // XXX should not access -> size directly

    if (vc->msg->contentSize() < vc->msglen) {
        comm_read(fd, buf + len, vc->msglen - vc->msg->contentSize(), idnsReadVC, vc);
        return;
    }

    assert(vc->ns < nns);
    debugs(78, 3, "idnsReadVC: FD " << fd << ": received " <<
           (int) vc->msg->contentSize() << " bytes via tcp from " <<
           nameservers[vc->ns].S << ".");

    idnsGrokReply(vc->msg->buf, vc->msg->contentSize());
    vc->msg->clean();
    comm_read(fd, (char *)&vc->msglen, 2 , idnsReadVCHeader, vc);
}

static void
idnsReadVCHeader(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    nsvc * vc = (nsvc *)data;

    if (flag == COMM_ERR_CLOSING)
        return;

    if (flag != COMM_OK || len <= 0) {
        comm_close(fd);
        return;
    }

    vc->read_msglen += len;

    assert(vc->read_msglen <= 2);

    if (vc->read_msglen < 2) {
        comm_read(fd, buf + len, 2 - vc->read_msglen, idnsReadVCHeader, vc);
        return;
    }

    vc->read_msglen = 0;

    vc->msglen = ntohs(vc->msglen);

    vc->msg->init(vc->msglen, vc->msglen);
    comm_read(fd, vc->msg->buf, vc->msglen, idnsReadVC, vc);
}

/*
 * rcode < 0 indicates an error, rocde >= 0 indicates success
 */
static void
idnsRcodeCount(int rcode, int attempt)
{
    if (rcode > 0)
        rcode = 0;
    else if (rcode < 0)
        rcode = -rcode;

    if (rcode < MAX_RCODE)
        if (attempt < MAX_ATTEMPT)
            RcodeMatrix[rcode][attempt]++;
}

/* ====================================================================== */

static void
idnsRegisterWithCacheManager(void)
{
    CacheManager::GetInstance()->
    registerAction("idns", "Internal DNS Statistics", idnsStats, 0, 1);
}

void
idnsInit(void)
{
    static int init = 0;

    CBDATA_INIT_TYPE(nsvc);
    CBDATA_INIT_TYPE(idns_query);

    if (DnsSocketA < 0 && DnsSocketB < 0) {
        IpAddress addrA; // since we don't want to alter Config.Addrs.udp_* and dont have one of our own.

        if (!Config.Addrs.udp_outgoing.IsNoAddr())
            addrA = Config.Addrs.udp_outgoing;
        else
            addrA = Config.Addrs.udp_incoming;

        IpAddress addrB = addrA;
        addrA.SetIPv4();

        if (Ip::EnableIpv6 && (addrB.IsAnyAddr() || addrB.IsIPv6())) {
            debugs(78, 2, "idnsInit: attempt open DNS socket to: " << addrB);
            DnsSocketB = comm_open_listener(SOCK_DGRAM,
                                            IPPROTO_UDP,
                                            addrB,
                                            COMM_NONBLOCKING,
                                            "DNS Socket IPv6");
        }

        if (addrA.IsAnyAddr() || addrA.IsIPv4()) {
            debugs(78, 2, "idnsInit: attempt open DNS socket to: " << addrA);
            DnsSocketA = comm_open_listener(SOCK_DGRAM,
                                            IPPROTO_UDP,
                                            addrA,
                                            COMM_NONBLOCKING,
                                            "DNS Socket IPv4");
        }

        if (DnsSocketA < 0 && DnsSocketB < 0)
            fatal("Could not create a DNS socket");

        /* Ouch... we can't call functions using debug from a debug
         * statement. Doing so messes up the internal Debug::level
         */
        if (DnsSocketB >= 0) {
            comm_local_port(DnsSocketB);
            debugs(78, 1, "DNS Socket created at " << addrB << ", FD " << DnsSocketB);
            commSetSelect(DnsSocketB, COMM_SELECT_READ, idnsRead, NULL, 0);
        }
        if (DnsSocketA >= 0) {
            comm_local_port(DnsSocketA);
            debugs(78, 1, "DNS Socket created at " << addrA << ", FD " << DnsSocketA);
            commSetSelect(DnsSocketA, COMM_SELECT_READ, idnsRead, NULL, 0);
        }
    }

    assert(0 == nns);
    idnsParseNameservers();
#ifndef _SQUID_MSWIN_

    if (0 == nns)
        idnsParseResolvConf();

#endif
#ifdef _SQUID_WIN32_

    if (0 == nns)
        idnsParseWIN32Registry();

#endif

    if (0 == nns) {
        debugs(78, 1, "Warning: Could not find any nameservers. Trying to use localhost");
#ifdef _SQUID_WIN32_

        debugs(78, 1, "Please check your TCP-IP settings or /etc/resolv.conf file");
#else

        debugs(78, 1, "Please check your /etc/resolv.conf file");
#endif

        debugs(78, 1, "or use the 'dns_nameservers' option in squid.conf.");
        idnsAddNameserver("127.0.0.1");
    }

    if (!init) {
        memDataInit(MEM_IDNS_QUERY, "idns_query", sizeof(idns_query), 0);
        memset(RcodeMatrix, '\0', sizeof(RcodeMatrix));
        idns_lookup_hash = hash_create((HASHCMP *) strcmp, 103, hash_string);
        init++;
    }

    idnsRegisterWithCacheManager();
}

void
idnsShutdown(void)
{
    if (DnsSocketA < 0 && DnsSocketB < 0)
        return;

    if (DnsSocketA >= 0 ) {
        comm_close(DnsSocketA);
        DnsSocketA = -1;
    }

    if (DnsSocketB >= 0 ) {
        comm_close(DnsSocketB);
        DnsSocketB = -1;
    }

    for (int i = 0; i < nns; i++) {
        if (nsvc *vc = nameservers[i].vc) {
            if (vc->fd >= 0)
                comm_close(vc->fd);
        }
    }

    // XXX: vcs are not closed/freed yet and may try to access nameservers[]
    idnsFreeNameservers();
    idnsFreeSearchpath();
}

static int
idnsCachedLookup(const char *key, IDNSCB * callback, void *data)
{
    idns_query *q;

    idns_query *old = (idns_query *) hash_lookup(idns_lookup_hash, key);

    if (!old)
        return 0;

    q = cbdataAlloc(idns_query);

    q->callback = callback;

    q->callback_data = cbdataReference(data);

    q->queue = old->queue;

    old->queue = q;

    return 1;
}

static void
idnsCacheQuery(idns_query *q)
{
    q->hash.key = q->query.name;
    hash_join(idns_lookup_hash, &q->hash);
}

void
idnsALookup(const char *name, IDNSCB * callback, void *data)
{
    unsigned int i;
    int nd = 0;
    idns_query *q;

    if (idnsCachedLookup(name, callback, data))
        return;

    q = cbdataAlloc(idns_query);

    q->id = idnsQueryID();

    for (i = 0; i < strlen(name); i++)
        if (name[i] == '.')
            nd++;

    if (Config.onoff.res_defnames && npc > 0 && name[strlen(name)-1] != '.') {
        q->do_searchpath = 1;
    } else {
        q->do_searchpath = 0;
    }

    strcpy(q->orig, name);
    strcpy(q->name, q->orig);

    if (q->do_searchpath && nd < ndots) {
        q->domain = 0;
        strcat(q->name, ".");
        strcat(q->name, searchpath[q->domain].domain);
        debugs(78, 3, "idnsALookup: searchpath used for " << q->name);
    }

    if (Ip::EnableIpv6) {
        q->sz = rfc3596BuildAAAAQuery(q->name, q->buf, sizeof(q->buf), q->id, &q->query);
        q->need_A = true;
    } else {
        q->sz = rfc3596BuildAQuery(q->name, q->buf, sizeof(q->buf), q->id, &q->query);
        q->need_A = false;
    }

    if (q->sz < 0) {
        /* problem with query data -- query not sent */
        callback(data, NULL, 0, "Internal error");
        cbdataFree(q);
        return;
    }

    debugs(78, 3, "idnsALookup: buf is " << q->sz << " bytes for " << q->name <<
           ", id = 0x" << std::hex << q->id);

    q->callback = callback;
    q->callback_data = cbdataReference(data);

    q->start_t = current_time;

    idnsCacheQuery(q);
    idnsSendQuery(q);
}

void
idnsPTRLookup(const IpAddress &addr, IDNSCB * callback, void *data)
{
    idns_query *q;

    char ip[MAX_IPSTRLEN];

    addr.NtoA(ip,MAX_IPSTRLEN);

    q = cbdataAlloc(idns_query);

    q->id = idnsQueryID();

    if (addr.IsIPv6()) {
        struct in6_addr addr6;
        addr.GetInAddr(addr6);
        q->sz = rfc3596BuildPTRQuery6(addr6, q->buf, sizeof(q->buf), q->id, &q->query);
    } else {
        struct in_addr addr4;
        addr.GetInAddr(addr4);
        q->sz = rfc3596BuildPTRQuery4(addr4, q->buf, sizeof(q->buf), q->id, &q->query);
    }

    /* PTR does not do inbound A/AAAA */
    q->need_A = false;

    if (q->sz < 0) {
        /* problem with query data -- query not sent */
        callback(data, NULL, 0, "Internal error");
        cbdataFree(q);
        return;
    }

    if (idnsCachedLookup(q->query.name, callback, data)) {
        cbdataFree(q);
        return;
    }

    debugs(78, 3, "idnsPTRLookup: buf is " << q->sz << " bytes for " << ip <<
           ", id = 0x" << std::hex << q->id);

    q->callback = callback;
    q->callback_data = cbdataReference(data);

    q->start_t = current_time;

    idnsCacheQuery(q);
    idnsSendQuery(q);
}

#ifdef SQUID_SNMP
/*
 * The function to return the DNS via SNMP
 */
variable_list *
snmp_netIdnsFn(variable_list * Var, snint * ErrP)
{
    int i, n = 0;
    variable_list *Answer = NULL;
    MemBuf tmp;
    debugs(49, 5, "snmp_netDnsFn: Processing request: " << snmpDebugOid(Var->name, Var->name_length, tmp));
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[LEN_SQ_NET + 1]) {

    case DNS_REQ:

        for (i = 0; i < nns; i++)
            n += nameservers[i].nqueries;

        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      n,
                                      SMI_COUNTER32);

        break;

    case DNS_REP:
        for (i = 0; i < nns; i++)
            n += nameservers[i].nreplies;

        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      n,
                                      SMI_COUNTER32);

        break;

    case DNS_SERVERS:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      nns,
                                      SMI_COUNTER32);

        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;

        break;
    }

    return Answer;
}

#endif /*SQUID_SNMP */
#endif /* USE_DNSSERVERS */
