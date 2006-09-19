
/*
 * $Id: dns_internal.cc,v 1.94 2006/09/19 07:56:57 adrian Exp $
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
#include "MemBuf.h"

#include "wordlist.h"

#if HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#if HAVE_RESOLV_H
#include <resolv.h>
#endif

/* MS VisualStudio Projects are monolithic, so we need the following
   #ifndef to exclude the internal DNS code from compile process when
   using external DNS process.
 */
#ifndef USE_DNSSERVERS
#ifdef _SQUID_WIN32_
#include "squid_windows.h"
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

struct _idns_query
{
    hash_link hash;
    rfc1035_query query;
    char buf[RESOLV_BUFSZ];
    char name[NS_MAXDNAME + 1];
    char orig[NS_MAXDNAME + 1];
    size_t sz;
    unsigned short id;
    int nsends;
    int need_vc;

    struct timeval start_t;

    struct timeval sent_t;
    dlink_node lru;
    IDNSCB *callback;
    void *callback_data;
    int attempt;
    const char *error;
    int rcode;
    idns_query *queue;
    unsigned short domain;
    unsigned short do_searchpath;
};

struct _nsvc
{
    int ns;
    int fd;
    unsigned short msglen;
    int read_msglen;
    MemBuf *msg;
    MemBuf *queue;
    bool busy;
};

struct _ns
{

    struct sockaddr_in S;
    int nqueries;
    int nreplies;
    nsvc *vc;
};

struct _sp
{
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

static int idnsFromKnownNameserver(struct sockaddr_in *from);
static idns_query *idnsFindQuery(unsigned short id);
static void idnsGrokReply(const char *buf, size_t sz);
static PF idnsRead;
static EVH idnsCheckQueue;
static void idnsTickleQueue(void);
static void idnsRcodeCount(int, int);

static void
idnsAddNameserver(const char *buf)
{

    struct IN_ADDR A;

    if (!safe_inet_addr(buf, &A)) {
        debug(78, 0) ("WARNING: rejecting '%s' as a name server, because it is not a numeric IP address\n", buf);
        return;
    }

    if (A.s_addr == 0) {
        debug(78, 0) ("WARNING: Squid does not accept 0.0.0.0 in DNS server specifications.\n");
        debug(78, 0) ("Will be using 127.0.0.1 instead, assuming you meant that DNS is running on the same machine\n");
        safe_inet_addr("127.0.0.1", &A);
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
    nameservers[nns].S.sin_family = AF_INET;
    nameservers[nns].S.sin_port = htons(NS_DEFAULTPORT);
    nameservers[nns].S.sin_addr.s_addr = A.s_addr;
    debug(78, 3) ("idnsAddNameserver: Added nameserver #%d: %s\n",
                  nns, inet_ntoa(nameservers[nns].S.sin_addr));
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
    debug(78, 3) ("idnsAddPathComponent: Added domain #%d: %s\n",
                  npc, searchpath[npc].domain);
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
        debug(78, 1) ("Adding nameserver %s from squid.conf\n", w->key);
        idnsAddNameserver(w->key);
    }
}

#ifndef _SQUID_MSWIN_
static void
idnsParseResolvConf(void)
{
    FILE *fp;
    char buf[RESOLV_BUFSZ];
    char *t;
    fp = fopen(_PATH_RESCONF, "r");

    if (fp == NULL) {
        debug(78, 1) ("%s: %s\n", _PATH_RESCONF, xstrerror());
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

            debug(78, 1) ("Adding nameserver %s from %s\n", t, _PATH_RESCONF);

            idnsAddNameserver(t);
        } else if (strcasecmp(t, "search") == 0) {
            while (NULL != t) {
                t = strtok(NULL, w_space);

                if (NULL == t)
                    continue;

                debug(78, 1) ("Adding domain %s from %s\n", t, _PATH_RESCONF);

                idnsAddPathComponent(t);
            }
        } else if (strcasecmp(t, "options") == 0) {
            while (NULL != t) {
                t = strtok(NULL, w_space);

                if (NULL == t)
                    continue;

                if (strncmp(t, "ndots:", 6) != 0) {
                    ndots = atoi(t + 6);

                    if (ndots < 1)
                        ndots = 1;

                    debug(78, 1) ("Adding ndots %d from %s\n", ndots, _PATH_RESCONF);
                }
            }
        }
    }

    fclose(fp);
}

#endif

#ifdef _SQUID_WIN32_
static void
idnsParseWIN32SearchList(const char * Separator)
{
    BYTE *t;
    char *token;
    HKEY hndKey;

    if (RegOpenKey(HKEY_LOCAL_MACHINE,
                   "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                   &hndKey) == ERROR_SUCCESS) {
        DWORD Type = 0;
        DWORD Size = 0;
        LONG Result;
        Result =
            RegQueryValueEx(hndKey, "SearchList", NULL, &Type, NULL,
                            &Size);

        if (Result == ERROR_SUCCESS && Size) {
            t = (unsigned char *) xmalloc(Size);
            RegQueryValueEx(hndKey, "SearchList", NULL, &Type, t,
                            &Size);
            token = strtok((char *) t, Separator);

            while (token) {
                idnsAddPathComponent(token);
                debugs(78, 1, "Adding domain " << token << " from Registry");
                token = strtok(NULL, Separator);
            }
        }

        RegCloseKey(hndKey);
    }
}

static void
idnsParseWIN32Registry(void)
{
    BYTE *t;
    char *token;
    HKEY hndKey, hndKey2;

    idnsFreeNameservers();

    switch (WIN32_OS_version) {

    case _WIN_OS_WINNT:
        /* get nameservers from the Windows NT registry */

        if (RegOpenKey(HKEY_LOCAL_MACHINE,
                       "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                       &hndKey) == ERROR_SUCCESS) {
            DWORD Type = 0;
            DWORD Size = 0;
            LONG Result;
            Result =
                RegQueryValueEx(hndKey, "DhcpNameServer", NULL, &Type, NULL,
                                &Size);

            if (Result == ERROR_SUCCESS && Size) {
                t = (unsigned char *) xmalloc(Size);
                RegQueryValueEx(hndKey, "DhcpNameServer", NULL, &Type, t,
                                &Size);
                token = strtok((char *) t, ", ");

                while (token) {
                    idnsAddNameserver(token);
                    debugs(78, 1, "Adding DHCP nameserver " << token << " from Registry");
                    token = strtok(NULL, ",");
                }
            }

            Result =
                RegQueryValueEx(hndKey, "NameServer", NULL, &Type, NULL, &Size);

            if (Result == ERROR_SUCCESS && Size) {
                t = (unsigned char *) xmalloc(Size);
                RegQueryValueEx(hndKey, "NameServer", NULL, &Type, t, &Size);
                token = strtok((char *) t, ", ");

                while (token) {
                    debugs(78, 1, "Adding nameserver " << token << " from Registry");
                    idnsAddNameserver(token);
                    token = strtok(NULL, ", ");
                }
            }

            RegCloseKey(hndKey);
        }

        idnsParseWIN32SearchList(" ");

        break;

    case _WIN_OS_WIN2K:

    case _WIN_OS_WINXP:

    case _WIN_OS_WINNET:

    case _WIN_OS_WINLON:
        /* get nameservers from the Windows 2000 registry */
        /* search all interfaces for DNS server addresses */

        if (RegOpenKey(HKEY_LOCAL_MACHINE,
                       "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                       &hndKey) == ERROR_SUCCESS) {
            int i;
            char keyname[255];

            for (i = 0; i < 10; i++) {
                if (RegEnumKey(hndKey, i, (char *) &keyname,
                               255) == ERROR_SUCCESS) {
                    char newkeyname[255];
                    strcpy(newkeyname,
                           "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\");
                    strcat(newkeyname, keyname);

                    if (RegOpenKey(HKEY_LOCAL_MACHINE, newkeyname,
                                   &hndKey2) == ERROR_SUCCESS) {
                        DWORD Type = 0;
                        DWORD Size = 0;
                        LONG Result;
                        Result =
                            RegQueryValueEx(hndKey2, "DhcpNameServer", NULL,
                                            &Type, NULL, &Size);

                        if (Result == ERROR_SUCCESS && Size) {
                            t = (unsigned char *) xmalloc(Size);
                            RegQueryValueEx(hndKey2, "DhcpNameServer", NULL,
                                            &Type, t, &Size);
                            token = strtok((char *) t, ", ");

                            while (token) {
                                debugs(78, 1, "Adding DHCP nameserver " << token << " from Registry");
                                idnsAddNameserver(token);
                                token = strtok(NULL, ", ");
                            }
                        }

                        Result =
                            RegQueryValueEx(hndKey2, "NameServer", NULL, &Type,
                                            NULL, &Size);

                        if (Result == ERROR_SUCCESS && Size) {
                            t = (unsigned char *) xmalloc(Size);
                            RegQueryValueEx(hndKey2, "NameServer", NULL, &Type,
                                            t, &Size);
                            token = strtok((char *) t, ", ");

                            while (token) {
                                debugs(78, 1, "Adding nameserver " << token << " from Registry");
                                idnsAddNameserver(token);
                                token = strtok(NULL, ", ");
                            }
                        }

                        RegCloseKey(hndKey2);
                    }
                }
            }

            RegCloseKey(hndKey);
        }

        idnsParseWIN32SearchList(", ");

        break;

    case _WIN_OS_WIN95:

    case _WIN_OS_WIN98:

    case _WIN_OS_WINME:
        /* get nameservers from the Windows 9X registry */

        if (RegOpenKey(HKEY_LOCAL_MACHINE,
                       "SYSTEM\\CurrentControlSet\\Services\\VxD\\MSTCP",
                       &hndKey) == ERROR_SUCCESS) {
            DWORD Type = 0;
            DWORD Size = 0;
            LONG Result;
            Result =
                RegQueryValueEx(hndKey, "NameServer", NULL, &Type, NULL, &Size);

            if (Result == ERROR_SUCCESS && Size) {
                t = (unsigned char *) xmalloc(Size);
                RegQueryValueEx(hndKey, "NameServer", NULL, &Type, t, &Size);
                token = strtok((char *) t, ", ");

                while (token) {
                    debugs(78, 1, "Adding nameserver " << token << " from Registry");
                    idnsAddNameserver(token);
                    token = strtok(NULL, ", ");
                }
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
    storeAppendPrintf(sentry, "IP ADDRESS      # QUERIES # REPLIES\n");
    storeAppendPrintf(sentry, "--------------- --------- ---------\n");

    for (i = 0; i < nns; i++) {
        storeAppendPrintf(sentry, "%-15s %9d %9d\n",
                          inet_ntoa(nameservers[i].S.sin_addr),
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
idnsInitVCConnected(int fd, comm_err_t status, int xerrno, void *data)
{
    nsvc * vc = (nsvc *)data;

    if (status != COMM_OK) {
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
    nameservers[vc->ns].vc = NULL;
    cbdataFree(vc);
}

static void
idnsInitVC(int ns)
{
    nsvc *vc = cbdataAlloc(nsvc);
    nameservers[ns].vc = vc;

    struct IN_ADDR addr;

    if (Config.Addrs.udp_outgoing.s_addr != no_addr.s_addr)
        addr = Config.Addrs.udp_outgoing;
    else
        addr = Config.Addrs.udp_incoming;

    vc->queue = new MemBuf;

    vc->msg = new MemBuf;

    vc->fd = comm_open(SOCK_STREAM,
                       IPPROTO_TCP,
                       addr,
                       0,
                       COMM_NONBLOCKING,
                       "DNS TCP Socket");

    if (vc->fd < 0)
        fatal("Could not create a DNS socket");

    comm_add_close_handler(vc->fd, idnsVCClosed, vc);

    vc->busy = 1;

    commConnectStart(vc->fd, inet_ntoa(nameservers[ns].S.sin_addr), ntohs(nameservers[ns].S.sin_port), idnsInitVCConnected, vc);
}

static void
idnsSendQueryVC(idns_query * q, int ns)
{
    if (nameservers[ns].vc == NULL)
        idnsInitVC(ns);

    nsvc *vc = nameservers[ns].vc;

    vc->queue->reset();

    short head = htons(q->sz);

    vc->queue->append((char *)&head, 2);

    vc->queue->append(q->buf, q->sz);

    idnsDoSendQueryVC(vc);
}

static void
idnsSendQuery(idns_query * q)
{
    int x;
    int ns;

    if (DnsSocket < 0) {
        debug(78, 1) ("idnsSendQuery: Can't send query, no DNS socket!\n");
        return;
    }

    /* XXX Select nameserver */
    assert(nns > 0);

    assert(q->lru.next == NULL);

    assert(q->lru.prev == NULL);

try_again:
    ns = q->nsends % nns;

    if (q->need_vc) {
        idnsSendQueryVC(q, ns);
        x = 0;
    } else
        x = comm_udp_sendto(DnsSocket,
                            &nameservers[ns].S,
                            sizeof(nameservers[ns].S),
                            q->buf,
                            q->sz);

    q->nsends++;

    q->sent_t = current_time;

    if (x < 0) {
        debug(50, 1) ("idnsSendQuery: FD %d: sendto: %s\n",
                      DnsSocket, xstrerror());

        if (q->nsends % nns != 0)
            goto try_again;
    } else {
        fd_bytes(DnsSocket, x, FD_WRITE);
        commSetSelect(DnsSocket, COMM_SELECT_READ, idnsRead, NULL, 0);
    }

    nameservers[ns].nqueries++;
    dlinkAdd(q, &q->lru, &lru_list);
    idnsTickleQueue();
}

static int

idnsFromKnownNameserver(struct sockaddr_in *from)
{
    int i;

    for (i = 0; i < nns; i++)
    {
        if (nameservers[i].S.sin_addr.s_addr != from->sin_addr.s_addr)
            continue;

        if (nameservers[i].S.sin_port != from->sin_port)
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

    while(idnsFindQuery(id)) {
        id++;

        if (id == first_id) {
            debug(78, 1) ("idnsQueryID: Warning, too many pending DNS requests\n");
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

    while(q->queue) {
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

static void
idnsGrokReply(const char *buf, size_t sz)
{
    int n;
    rfc1035_message *message = NULL;
    idns_query *q;

    n = rfc1035MessageUnpack(buf,
                             sz,
                             &message);

    if (message == NULL) {
        debug(78, 1) ("idnsGrokReply: Malformed DNS response\n");
        return;
    }

    debug(78, 3) ("idnsGrokReply: ID %#hx, %d answers\n", message->id, n);

    q = idnsFindQuery(message->id);

    if (q == NULL) {
        debug(78, 3) ("idnsGrokReply: Late response\n");
        rfc1035MessageDestroy(message);
        return;
    }

    if (rfc1035QueryCompare(&q->query, message->query) != 0) {
        debug(78, 3) ("idnsGrokReply: Query mismatch (%s != %s)\n", q->query.name, message->query->name);
        rfc1035MessageDestroy(message);
        return;
    }

    if (message->tc) {
        dlinkDelete(&q->lru, &lru_list);
        rfc1035MessageDestroy(message);

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
        debug(78, 3) ("idnsGrokReply: error %s (%d)\n", rfc1035_error_message, rfc1035_errno);

        q->error = rfc1035_error_message;
        q->rcode = -n;

        if (q->rcode == 2 && ++q->attempt < MAX_ATTEMPT) {
            /*
             * RCODE 2 is "Server failure - The name server was
             * unable to process this query due to a problem with
             * the name server."
             */
            rfc1035MessageDestroy(message);
            q->start_t = current_time;
            q->id = idnsQueryID();
            rfc1035SetQueryID(q->buf, q->id);
            idnsSendQuery(q);
            return;
        }

        if (q->rcode == 3 && q->do_searchpath && q->attempt < MAX_ATTEMPT) {
            assert(NULL == message->answer);
            strcpy(q->name, q->orig);

            if (q->domain < npc) {
                strcat(q->name, ".");
                strcat(q->name, searchpath[q->domain].domain);
                debug(78, 3) ("idnsGrokReply: searchpath used for %s\n",
                              q->name);
                q->domain++;
            } else {
                q->attempt++;
            }

            rfc1035MessageDestroy(message);
            q->start_t = current_time;
            q->id = idnsQueryID();
            rfc1035SetQueryID(q->buf, q->id);
            q->sz = rfc1035BuildAQuery(q->name, q->buf, sizeof(q->buf), q->id,
                                       &q->query);

            idnsCacheQuery(q);
            idnsSendQuery(q);
            return;
        }
    }

    idnsCallback(q, message->answer, n, q->error);
    rfc1035MessageDestroy(message);

    cbdataFree(q);
}

static void
idnsRead(int fd, void *data)
{
    int *N = &incoming_sockets_accepted;
    ssize_t len;

    struct sockaddr_in from;
    socklen_t from_len;
    int max = INCOMING_DNS_MAX;
    static char rbuf[SQUID_UDP_SO_RCVBUF];
    int ns;

    while (max--) {
        from_len = sizeof(from);
        memset(&from, '\0', from_len);

        len = comm_udp_recvfrom(fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *) &from, &from_len);

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

                debug(50, 1) ("idnsRead: FD %d recvfrom: %s\n",
                              fd, xstrerror());

            break;
        }

        fd_bytes(DnsSocket, len, FD_READ);
        assert(N);
        (*N)++;
        debug(78, 3) ("idnsRead: FD %d: received %d bytes from %s.\n",
                      fd,
                      (int) len,
                      inet_ntoa(from.sin_addr));
        ns = idnsFromKnownNameserver(&from);

        if (ns >= 0) {
            nameservers[ns].nreplies++;
        } else if (Config.onoff.ignore_unknown_nameservers) {
            static time_t last_warning = 0;

            if (squid_curtime - last_warning > 60) {
                debug(78, 1) ("WARNING: Reply from unknown nameserver [%s]\n",
                              inet_ntoa(from.sin_addr));
                last_warning = squid_curtime;
            }

            continue;
        }

        idnsGrokReply(rbuf, len);
    }

    if (lru_list.head)
        commSetSelect(DnsSocket, COMM_SELECT_READ, idnsRead, NULL, 0);
}

static void
idnsCheckQueue(void *unused)
{
    dlink_node *n;
    dlink_node *p = NULL;
    idns_query *q;
    event_queued = 0;

    for (n = lru_list.tail; n; n = p) {
        if (0 == nns)
            /* name servers went away; reconfiguring or shutting down */
            break;

        q = (idns_query *)n->data;

        if (tvSubDsec(q->sent_t, current_time) < Config.Timeout.idns_retransmit * (1 << (q->nsends - 1) % nns))
            break;

        debug(78, 3) ("idnsCheckQueue: ID %#04x timeout\n",
                      q->id);

        p = n->prev;

        dlinkDelete(&q->lru, &lru_list);

        if (tvSubDsec(q->start_t, current_time) < Config.Timeout.idns_query) {
            idnsSendQuery(q);
        } else {
            debug(78, 2) ("idnsCheckQueue: ID %x: giving up after %d tries and %5.1f seconds\n",
                          (int) q->id, q->nsends,
                          tvSubDsec(q->start_t, current_time));

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

    vc->msg->size += len;	// XXX should not access -> size directly

    if (vc->msg->contentSize() < vc->msglen) {
        comm_read(fd, buf + len, vc->msglen - vc->msg->contentSize(), idnsReadVC, vc);
        return;
    }

    debug(78, 3) ("idnsReadVC: FD %d: received %d bytes via tcp from %s.\n",
                  fd,
                  (int) vc->msg->contentSize(),
                  inet_ntoa(nameservers[vc->ns].S.sin_addr));

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

void
idnsInit(void)
{
    static int init = 0;

    CBDATA_INIT_TYPE(nsvc);
    CBDATA_INIT_TYPE(idns_query);

    if (DnsSocket < 0) {
        int port;

        struct IN_ADDR addr;

        if (Config.Addrs.udp_outgoing.s_addr != no_addr.s_addr)
            addr = Config.Addrs.udp_outgoing;
        else
            addr = Config.Addrs.udp_incoming;

        DnsSocket = comm_open(SOCK_DGRAM,
                              IPPROTO_UDP,
                              addr,
                              0,
                              COMM_NONBLOCKING,
                              "DNS Socket");

        if (DnsSocket < 0)
            fatal("Could not create a DNS socket");

        /* Ouch... we can't call functions using debug from a debug
         * statement. Doing so messes up the internal Debug::level
         */
        port = comm_local_port(DnsSocket);

        debug(78, 1) ("DNS Socket created at %s, port %d, FD %d\n",
                      inet_ntoa(addr),
                      port, DnsSocket);
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
}

void
idnsRegisterWithCacheManager(CacheManager & manager)
{
    manager.registerAction("idns", "Internal DNS Statistics", idnsStats, 0, 1);
}

void
idnsShutdown(void)
{
    if (DnsSocket < 0)
        return;

    comm_close(DnsSocket);

    DnsSocket = -1;

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
        debug(78, 3) ("idnsALookup: searchpath used for %s\n",
                      q->name);
    }

    q->sz = rfc1035BuildAQuery(q->name, q->buf, sizeof(q->buf), q->id,
                               &q->query);

    if (q->sz < 0) {
        /* problem with query data -- query not sent */
        callback(data, NULL, 0, "Internal error");
        cbdataFree(q);
        return;
    }

    debug(78, 3) ("idnsALookup: buf is %d bytes for %s, id = %#hx\n",
                  (int) q->sz, q->name, q->id);

    q->callback = callback;

    q->callback_data = cbdataReference(data);

    q->start_t = current_time;

    idnsCacheQuery(q);

    idnsSendQuery(q);
}

void

idnsPTRLookup(const struct IN_ADDR addr, IDNSCB * callback, void *data)
{
    idns_query *q;

    const char *ip = inet_ntoa(addr);

    q = cbdataAlloc(idns_query);

    q->id = idnsQueryID();

    q->sz = rfc1035BuildPTRQuery(addr, q->buf, sizeof(q->buf), q->id, &q->query);

    if (q->sz < 0)
    {
        /* problem with query data -- query not sent */
        callback(data, NULL, 0, "Internal error");
        cbdataFree(q);
        return;
    }

    if (idnsCachedLookup(q->query.name, callback, data)) {
	cbdataFree(q);
	return;
    }

    debug(78, 3) ("idnsPTRLookup: buf is %d bytes for %s, id = %#hx\n",
                  (int) q->sz, ip, q->id);

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
    debug(49, 5) ("snmp_netDnsFn: Processing request: \n");
    snmpDebugOid(5, Var->name, Var->name_length);
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
