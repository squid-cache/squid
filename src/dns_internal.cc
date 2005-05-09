
/*
 * $Id: dns_internal.cc,v 1.70 2005/05/09 02:32:09 hno Exp $
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

#include "squid.h"
#include "Store.h"
#include "comm.h"

/* MS VisualStudio Projects are monolitich, so we need the following
   #ifndef to exclude the internal DNS code from compile process when
   using external DNS process.
 */
#ifndef USE_DNSSERVERS
#ifdef _SQUID_WIN32_
#include "squid_windows.h"
#endif
#ifndef _PATH_RESOLV_CONF
#define _PATH_RESOLV_CONF "/etc/resolv.conf"
#endif
#ifndef DOMAIN_PORT
#define DOMAIN_PORT 53
#endif

#define IDNS_MAX_TRIES 20
#define MAX_RCODE 6
#define MAX_ATTEMPT 3
static int RcodeMatrix[MAX_RCODE][MAX_ATTEMPT];

typedef struct _idns_query idns_query;

typedef struct _ns ns;

struct _idns_query
{
    hash_link hash;
    char query[RFC1035_MAXHOSTNAMESZ+1];
    char buf[512];
    size_t sz;
    unsigned short id;
    int nsends;

    struct timeval start_t;

    struct timeval sent_t;
    dlink_node lru;
    IDNSCB *callback;
    void *callback_data;
    int attempt;
    const char *error;
    int rcode;
    idns_query *queue;
};

struct _ns
{

    struct sockaddr_in S;
    int nqueries;
    int nreplies;
    int large_pkts;
};

static ns *nameservers = NULL;
static int nns = 0;
static int nns_alloc = 0;
static dlink_list lru_list;
static int event_queued = 0;
static hash_table *idns_lookup_hash = NULL;

static OBJH idnsStats;
static void idnsAddNameserver(const char *buf);
static void idnsFreeNameservers(void);
static void idnsParseNameservers(void);
#ifndef _SQUID_MSWIN_
static void idnsParseResolvConf(void);
#endif
#ifdef _SQUID_WIN32_
static void idnsParseWIN32Registry(void);
#endif
static void idnsSendQuery(idns_query * q);

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
    nameservers[nns].S.sin_port = htons(DOMAIN_PORT);
    nameservers[nns].S.sin_addr.s_addr = A.s_addr;
    debug(78, 3) ("idnsAddNameserver: Added nameserver #%d: %s\n",
                  nns, inet_ntoa(nameservers[nns].S.sin_addr));
    nns++;
}

static void
idnsFreeNameservers(void)
{
    safe_free(nameservers);
    nns = nns_alloc = 0;
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
    char buf[512];
    char *t;
    fp = fopen(_PATH_RESOLV_CONF, "r");

    if (fp == NULL) {
        debug(78, 1) ("%s: %s\n", _PATH_RESOLV_CONF, xstrerror());
        return;
    }

#if defined(_SQUID_CYGWIN_)
    setmode(fileno(fp), O_TEXT);

#endif

    while (fgets(buf, 512, fp)) {
        t = strtok(buf, w_space);

        if (NULL == t)
            continue;

        if (strcasecmp(t, "nameserver"))
            continue;

        t = strtok(NULL, w_space);

        if (t == NULL)
            continue;

        debug(78, 1) ("Adding nameserver %s from %s\n", t, _PATH_RESOLV_CONF);

        idnsAddNameserver(t);
    }

    fclose(fp);
}

#endif

#ifdef _SQUID_WIN32_
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
                    debug(78, 1) ("Adding DHCP nameserver %s from Registry\n",
                                  token);
                    token = strtok(NULL, ", ");
                }
            }

            Result =
                RegQueryValueEx(hndKey, "NameServer", NULL, &Type, NULL, &Size);

            if (Result == ERROR_SUCCESS && Size) {
                t = (unsigned char *) xmalloc(Size);
                RegQueryValueEx(hndKey, "NameServer", NULL, &Type, t, &Size);
                token = strtok((char *) t, ", ");

                while (token) {
                    debug(78, 1) ("Adding nameserver %s from Registry\n",
                                  token);
                    idnsAddNameserver(token);
                    token = strtok(NULL, ", ");
                }
            }

            RegCloseKey(hndKey);
        }

        break;

    case _WIN_OS_WIN2K:

    case _WIN_OS_WINXP:

    case _WIN_OS_WINNET:
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
                                debug(78, 1)
                                ("Adding DHCP nameserver %s from Registry\n",
                                 token);
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
                                debug(78,
                                      1) ("Adding nameserver %s from Registry\n",
                                          token);
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
                    debug(78, 1) ("Adding nameserver %s from Registry\n",
                                  token);
                    idnsAddNameserver(token);
                    token = strtok(NULL, ", ");
                }
            }

            RegCloseKey(hndKey);
        }

        break;

    default:
        debug(78, 1)
        ("Failed to read nameserver from Registry: Unknown System Type.\n");
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

        if (id > 0xFFFF)
            id = 0;

        if (id == first_id)
            break;
    }

    return squid_random() & 0xFFFF;
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

        memFree(q2, MEM_IDNS_QUERY);
    }

    if (q->hash.key) {
        hash_remove_link(idns_lookup_hash, &q->hash);
        q->hash.key = NULL;
    }
}

/* FIXME: We should also verify that the response is to the correct query to eleminate overlaps */
static void
idnsGrokReply(const char *buf, size_t sz)
{
    int n;
    rfc1035_rr *answers = NULL;
    unsigned short rid;
    idns_query *q;

    n = rfc1035AnswersUnpack(buf,
                             sz,
                             &answers,
                             &rid);
    debug(78, 3) ("idnsGrokReply: ID %#hx, %d answers\n", rid, n);

    if (n == -15 /* rfc1035_unpack_error */ ) {
        debug(78, 1) ("idnsGrokReply: Malformed DNS response\n");
        return;
    }

    q = idnsFindQuery(rid);

    if (q == NULL) {
        debug(78, 3) ("idnsGrokReply: Late response\n");
        rfc1035RRDestroy(answers, n);
        return;
    }

    dlinkDelete(&q->lru, &lru_list);
    idnsRcodeCount(n, q->attempt);
    q->error = NULL;

    if (n < 0) {
        debug(78, 3) ("idnsGrokReply: error %d\n", rfc1035_errno);

        q->error = rfc1035_error_message;
        q->rcode = -n;

        if (q->rcode == 2 && ++q->attempt < MAX_ATTEMPT) {
            /*
             * RCODE 2 is "Server failure - The name server was
             * unable to process this query due to a problem with
             * the name server."
             */
            assert(NULL == answers);
            q->start_t = current_time;
            q->id = idnsQueryID();
            rfc1035SetQueryID(q->buf, q->id);
            idnsSendQuery(q);
            return;
        }
    }

    idnsCallback(q, answers, n, q->error);
    rfc1035RRDestroy(answers, n);

    memFree(q, MEM_IDNS_QUERY);
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

        len = comm_udp_recvfrom(fd, rbuf, 512, 0, (struct sockaddr *) &from, &from_len);

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

        if (len > 512) {
            /*
             * Check for non-conforming replies.  RFC 1035 says
             * DNS/UDP messages must be 512 octets or less.  If we
             * get one that is too large, we generate a warning
             * and then pretend that we only got 512 octets.  This
             * should prevent the rfc1035.c code from reading past
             * the end of our buffer.
             */
            static int other_large_pkts = 0;
            int x;
            x = (ns < 0) ? ++other_large_pkts : ++nameservers[ns].large_pkts;

            if (isPowTen(x))
                debug(78, 1) ("WARNING: Got %d large DNS replies from %s\n",
                              x, inet_ntoa(from.sin_addr));

            len = 512;
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

            memFree(q, MEM_IDNS_QUERY);
        }
    }

    idnsTickleQueue();
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

    if (0 == nns)
        fatal("Could not find any nameservers.\n"
#ifdef _SQUID_WIN32_
              "       Please check your TCP-IP settings or /etc/resolv.conf file\n"
#else
              "       Please check your /etc/resolv.conf file\n"
#endif
              "       or use the 'dns_nameservers' option in squid.conf.");

    if (!init) {
        memDataInit(MEM_IDNS_QUERY, "idns_query", sizeof(idns_query), 0);
        cachemgrRegister("idns",
                         "Internal DNS Statistics",
                         idnsStats, 0, 1);
        memset(RcodeMatrix, '\0', sizeof(RcodeMatrix));
        idns_lookup_hash = hash_create((HASHCMP *) strcmp, 103, hash_string);
        init++;
    }
}

void
idnsShutdown(void)
{
    if (DnsSocket < 0)
        return;

    comm_close(DnsSocket);

    DnsSocket = -1;

    idnsFreeNameservers();
}

static int
idnsCachedLookup(const char *key, IDNSCB * callback, void *data)
{
    idns_query *q;

    idns_query *old = (idns_query *) hash_lookup(idns_lookup_hash, key);

    if (!old)
        return 0;

    q = (idns_query *)memAllocate(MEM_IDNS_QUERY);

    q->callback = callback;

    q->callback_data = cbdataReference(data);

    q->queue = old->queue;

    old->queue = q;

    return 1;
}

static void
idnsCacheQuery(idns_query *q, const char *key)
{
    xstrncpy(q->query, key, sizeof(q->query));
    q->hash.key = q->query;
    hash_join(idns_lookup_hash, &q->hash);
}

void
idnsALookup(const char *name, IDNSCB * callback, void *data)
{
    idns_query *q;

    if (idnsCachedLookup(name, callback, data))
        return;

    q = (idns_query *)memAllocate(MEM_IDNS_QUERY);

    q->sz = rfc1035BuildAQuery(name, q->buf, sizeof(q->buf), idnsQueryID());

    debug(78, 3) ("idnsALookup: buf is %d bytes for %s, id = %#hx\n",
                  (int) q->sz, name, q->id);

    q->callback = callback;

    q->callback_data = cbdataReference(data);

    q->start_t = current_time;

    idnsCacheQuery(q, name);

    idnsSendQuery(q);
}

void

idnsPTRLookup(const struct IN_ADDR addr, IDNSCB * callback, void *data)
{
    idns_query *q;

    const char *ip = inet_ntoa(addr);

    if (idnsCachedLookup(ip, callback, data))
        return;

    q = (idns_query *)memAllocate(MEM_IDNS_QUERY);

    q->sz = rfc1035BuildPTRQuery(addr, q->buf, sizeof(q->buf), idnsQueryID());

    debug(78, 3) ("idnsPTRLookup: buf is %d bytes for %s, id = %#hx\n",
                  (int) q->sz, ip, q->id);

    q->callback = callback;

    q->callback_data = cbdataReference(data);

    q->start_t = current_time;

    idnsCacheQuery(q, ip);

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
