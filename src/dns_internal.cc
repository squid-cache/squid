/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 78    DNS lookups; interacts with dns/rfc1035.cc */

#include "squid.h"
#include "base/InstanceId.h"
#include "base/RunnersRegistry.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "comm/Loops.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "dlink.h"
#include "dns/forward.h"
#include "dns/rfc3596.h"
#include "event.h"
#include "fd.h"
#include "fde.h"
#include "ip/tools.h"
#include "MemBuf.h"
#include "mgr/Registration.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"
#include "tools.h"
#include "util.h"
#include "wordlist.h"

#if SQUID_SNMP
#include "snmp_core.h"
#endif

#if HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#include <cerrno>
#include <random>
#if HAVE_RESOLV_H
#include <resolv.h>
#endif

#if _SQUID_WINDOWS_
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
#define MAX_RCODE 17
#define MAX_ATTEMPT 3
static int RcodeMatrix[MAX_RCODE][MAX_ATTEMPT];
// NP: see http://www.iana.org/assignments/dns-parameters
static const char *Rcodes[] = {
    /* RFC 1035 */
    "Success",
    "Packet Format Error",
    "DNS Server Failure",
    "Non-Existent Domain",
    "Not Implemented",
    "Query Refused",
    /* RFC 2136 */
    "Name Exists when it should not",
    "RR Set Exists when it should not",
    "RR Set that should exist does not",
    "Server Not Authoritative for zone",
    "Name not contained in zone",
    /* unassigned */
    "","","","","",
    /* RFC 2671 */
    "Bad OPT Version or TSIG Signature Failure"
};

typedef struct _ns ns;

typedef struct _sp sp;

class idns_query
{
    CBDATA_CLASS(idns_query);

public:
    idns_query() :
        sz(0),
        query_id(0),
        nsends(0),
        need_vc(0),
        permit_mdns(false),
        pending(0),
        callback(NULL),
        callback_data(NULL),
        attempt(0),
        rcode(0),
        queue(NULL),
        slave(NULL),
        master(NULL),
        domain(0),
        do_searchpath(0),
        message(NULL),
        ancount(0),
        error(NULL)
    {
        memset(&hash, 0, sizeof(hash));
        memset(&query, 0, sizeof(query));
        *buf = 0;
        *name = 0;
        *orig = 0;
        memset(&start_t, 0, sizeof(start_t));
        memset(&sent_t, 0, sizeof(sent_t));
        memset(&queue_t, 0, sizeof(queue_t));
    }

    ~idns_query() {
        if (message)
            rfc1035MessageDestroy(&message);
        delete queue;
        delete slave;
        // master is just a back-reference
        cbdataReferenceDone(callback_data);
    }

    hash_link hash;
    rfc1035_query query;
    char buf[RESOLV_BUFSZ];
    char name[NS_MAXDNAME + 1];
    char orig[NS_MAXDNAME + 1];
    ssize_t sz;
    unsigned short query_id; /// random query ID sent to server; changes with every query sent
    InstanceId<idns_query> xact_id; /// identifies our "transaction", stays constant when query is retried

    int nsends;
    int need_vc;
    bool permit_mdns;
    int pending;

    struct timeval start_t;
    struct timeval sent_t;
    struct timeval queue_t;
    dlink_node lru;
    IDNSCB *callback;
    void *callback_data;
    int attempt;
    int rcode;
    idns_query *queue;
    idns_query *slave;  // single linked list
    idns_query *master; // single pointer to a shared master
    unsigned short domain;
    unsigned short do_searchpath;
    rfc1035_message *message;
    int ancount;
    const char *error;
};

InstanceIdDefinitions(idns_query,  "dns");

CBDATA_CLASS_INIT(idns_query);

class nsvc
{
    CBDATA_CLASS(nsvc);

public:
    explicit nsvc(int nsv) : ns(nsv), msglen(0), read_msglen(0), msg(new MemBuf()), queue(new MemBuf()), busy(true) {}
    ~nsvc();

    int ns;
    Comm::ConnectionPointer conn;
    unsigned short msglen;
    int read_msglen;
    MemBuf *msg;
    MemBuf *queue;
    bool busy;
};

CBDATA_CLASS_INIT(nsvc);

struct _ns {
    Ip::Address S;
    int nqueries;
    int nreplies;
#if WHEN_EDNS_RESPONSES_ARE_PARSED
    int last_seen_edns;
#endif
    bool mDNSResolver;
    nsvc *vc;
};

namespace Dns
{

/// manage DNS internal component
class ConfigRr : public RegisteredRunner
{
public:
    /* RegisteredRunner API */
    virtual void startReconfigure() override;
    virtual void endingShutdown() override;
};

RunnerRegistrationEntry(ConfigRr);

} // namespace Dns

struct _sp {
    char domain[NS_MAXDNAME];
    int queries;
};

static ns *nameservers = NULL;
static sp *searchpath = NULL;
static int nns = 0;
static int nns_alloc = 0;
static int nns_mdns_count = 0;
static int npc = 0;
static int npc_alloc = 0;
static int ndots = 1;
static dlink_list lru_list;
static int event_queued = 0;
static hash_table *idns_lookup_hash = NULL;

/*
 * Notes on EDNS:
 *
 * IPv4:
 *   EDNS as specified may be sent as an additional record for any request.
 *   early testing has revealed that it works on common devices, but cannot
 *   be reliably used on any A or PTR requet done for IPv4 addresses.
 *
 * As such the IPv4 packets are still hard-coded not to contain EDNS (0)
 *
 * Squid design:
 *   Squid is optimized to generate one packet and re-send it to all NS
 *   due to this we cannot customize the EDNS size per NS.
 *
 * As such we take the configuration option value as fixed.
 *
 * FUTURE TODO:
 *   This may not be worth doing, but if/when additional-records are parsed
 *   we will be able to recover the OPT value specific to any one NS and
 *   cache it. Effectively automating the tuning of EDNS advertised to the
 *   size our active NS are capable.
 * Default would need to start with 512 bytes RFC1035 says every NS must accept.
 * Responses from the configured NS may cause this to be raised or turned off.
 */
#if WHEN_EDNS_RESPONSES_ARE_PARSED
static int max_shared_edns = RFC1035_DEFAULT_PACKET_SZ;
#endif

static OBJH idnsStats;
static void idnsAddNameserver(const char *buf);
static void idnsAddMDNSNameservers();
static void idnsAddPathComponent(const char *buf);
static void idnsFreeNameservers(void);
static void idnsFreeSearchpath(void);
static bool idnsParseNameservers(void);
static bool idnsParseResolvConf(void);
#if _SQUID_WINDOWS_
static bool idnsParseWIN32Registry(void);
static void idnsParseWIN32SearchList(const char *);
#endif
static void idnsStartQuery(idns_query * q, IDNSCB * callback, void *data);
static void idnsSendQuery(idns_query * q);
static IOCB idnsReadVCHeader;
static void idnsDoSendQueryVC(nsvc *vc);
static CNCB idnsInitVCConnected;
static IOCB idnsReadVC;
static IOCB idnsSentQueryVC;

static int idnsFromKnownNameserver(Ip::Address const &from);
static idns_query *idnsFindQuery(unsigned short id);
static void idnsGrokReply(const char *buf, size_t sz, int from_ns);
static PF idnsRead;
static EVH idnsCheckQueue;
static void idnsTickleQueue(void);
static void idnsRcodeCount(int, int);
static CLCB idnsVCClosed;
static unsigned short idnsQueryID(void);
static void idnsSendSlaveAAAAQuery(idns_query *q);

static void
idnsCheckMDNS(idns_query *q)
{
    if (!Config.onoff.dns_mdns || q->permit_mdns)
        return;

    size_t slen = strlen(q->name);
    if (slen > 6 && memcmp(q->name +(slen-6),".local", 6) == 0) {
        q->permit_mdns = true;
    }
}

static void
idnsAddMDNSNameservers()
{
    nns_mdns_count=0;

    // mDNS is disabled
    if (!Config.onoff.dns_mdns)
        return;

    // mDNS resolver addresses are explicit multicast group IPs
    if (Ip::EnableIpv6) {
        idnsAddNameserver("FF02::FB");
        nameservers[nns-1].S.port(5353);
        nameservers[nns-1].mDNSResolver = true;
        ++nns_mdns_count;
    }

    idnsAddNameserver("224.0.0.251");
    nameservers[nns-1].S.port(5353);
    nameservers[nns-1].mDNSResolver = true;

    ++nns_mdns_count;
}

static void
idnsAddNameserver(const char *buf)
{
    Ip::Address A;

    if (!(A = buf)) {
        debugs(78, DBG_CRITICAL, "WARNING: rejecting '" << buf << "' as a name server, because it is not a numeric IP address");
        return;
    }

    if (A.isAnyAddr()) {
        debugs(78, DBG_CRITICAL, "WARNING: Squid does not accept " << A << " in DNS server specifications.");
        A.setLocalhost();
        debugs(78, DBG_CRITICAL, "Will be using " << A << " instead, assuming you meant that DNS is running on the same machine");
    }

    if (!Ip::EnableIpv6 && !A.setIPv4()) {
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
            memcpy(nameservers, oldptr, oldalloc * sizeof(*nameservers));

        if (oldptr)
            safe_free(oldptr);
    }

    assert(nns < nns_alloc);
    A.port(NS_DEFAULTPORT);
    nameservers[nns].S = A;
#if WHEN_EDNS_RESPONSES_ARE_PARSED
    nameservers[nns].last_seen_edns = RFC1035_DEFAULT_PACKET_SZ;
    // TODO generate a test packet to probe this NS from EDNS size and ability.
#endif
    debugs(78, 3, "idnsAddNameserver: Added nameserver #" << nns << " (" << A << ")");
    ++nns;
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
            memcpy(searchpath, oldptr, oldalloc * sizeof(*searchpath));

        if (oldptr)
            safe_free(oldptr);
    }

    assert(npc < npc_alloc);
    strncpy(searchpath[npc].domain, buf, sizeof(searchpath[npc].domain)-1);
    searchpath[npc].domain[sizeof(searchpath[npc].domain)-1] = '\0';
    Tolower(searchpath[npc].domain);
    debugs(78, 3, "idnsAddPathComponent: Added domain #" << npc << ": " << searchpath[npc].domain);
    ++npc;
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

static bool
idnsParseNameservers(void)
{
    bool result = false;
    for (wordlist *w = Config.dns_nameservers; w; w = w->next) {
        debugs(78, DBG_IMPORTANT, "Adding nameserver " << w->key << " from squid.conf");
        idnsAddNameserver(w->key);
        result = true;
    }
    return result;
}

static bool
idnsParseResolvConf(void)
{
    bool result = false;
#if !_SQUID_WINDOWS_
    FILE *fp = fopen(_PATH_RESCONF, "r");

    if (!fp) {
        int xerrno = errno;
        debugs(78, DBG_IMPORTANT, "" << _PATH_RESCONF << ": " << xstrerr(xerrno));
        return false;
    }

    char buf[RESOLV_BUFSZ];
    const char *t = NULL;
    while (fgets(buf, RESOLV_BUFSZ, fp)) {
        t = strtok(buf, w_space);

        if (NULL == t) {
            continue;
        } else if (strcmp(t, "nameserver") == 0) {
            t = strtok(NULL, w_space);

            if (NULL == t)
                continue;

            debugs(78, DBG_IMPORTANT, "Adding nameserver " << t << " from " << _PATH_RESCONF);

            idnsAddNameserver(t);
            result = true;
        } else if (strcmp(t, "domain") == 0) {
            idnsFreeSearchpath();
            t = strtok(NULL, w_space);

            if (NULL == t)
                continue;

            debugs(78, DBG_IMPORTANT, "Adding domain " << t << " from " << _PATH_RESCONF);

            idnsAddPathComponent(t);
        } else if (strcmp(t, "search") == 0) {
            idnsFreeSearchpath();
            while (NULL != t) {
                t = strtok(NULL, w_space);

                if (NULL == t)
                    continue;

                debugs(78, DBG_IMPORTANT, "Adding domain " << t << " from " << _PATH_RESCONF);

                idnsAddPathComponent(t);
            }
        } else if (strcmp(t, "options") == 0) {
            while (NULL != t) {
                t = strtok(NULL, w_space);

                if (NULL == t)
                    continue;

                if (strncmp(t, "ndots:", 6) == 0) {
                    ndots = atoi(t + 6);

                    if (ndots < 1)
                        ndots = 1;

                    debugs(78, DBG_IMPORTANT, "Adding ndots " << ndots << " from " << _PATH_RESCONF);
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
#endif
    return result;
}

#if _SQUID_WINDOWS_
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
            debugs(78, DBG_IMPORTANT, "Adding domain " << t << " from Registry");
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
                debugs(78, DBG_IMPORTANT, "Adding domain " << token << " from Registry");
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

static bool
idnsParseWIN32Registry(void)
{
    char *t;
    char *token;
    HKEY hndKey, hndKey2;
    bool result = false;

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
                    result = true;
                    debugs(78, DBG_IMPORTANT, "Adding DHCP nameserver " << token << " from Registry");
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
                    debugs(78, DBG_IMPORTANT, "Adding nameserver " << token << " from Registry");
                    idnsAddNameserver(token);
                    result = true;
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
                for (i = 0; i < (int) InterfacesCount; ++i) {
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
                                    debugs(78, DBG_IMPORTANT, "Adding DHCP nameserver " << token << " from Registry");
                                    idnsAddNameserver(token);
                                    result = true;
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
                                    debugs(78, DBG_IMPORTANT, "Adding nameserver " << token << " from Registry");
                                    idnsAddNameserver(token);
                                    result = true;
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
                    debugs(78, DBG_IMPORTANT, "Adding nameserver " << token << " from Registry");
                    idnsAddNameserver(token);
                    result = true;
                    token = strtok(NULL, ", ");
                }
                xfree(t);
            }

            RegCloseKey(hndKey);
        }

        break;

    default:
        debugs(78, DBG_IMPORTANT, "Failed to read nameserver from Registry: Unknown System Type.");
    }

    return result;
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
    storeAppendPrintf(sentry, "  ID   SIZE SENDS FIRST SEND LAST SEND M FQDN\n");
    storeAppendPrintf(sentry, "------ ---- ----- ---------- --------- - ----\n");

    for (n = lru_list.head; n; n = n->next) {
        q = (idns_query *)n->data;
        storeAppendPrintf(sentry, "%#06x %4d %5d %10.3f %9.3f %c %s\n",
                          (int) q->query_id, (int) q->sz, q->nsends,
                          tvSubDsec(q->start_t, current_time),
                          tvSubDsec(q->sent_t, current_time),
                          (q->permit_mdns? 'M':' '),
                          q->name);
    }

    if (Config.dns.packet_max > 0)
        storeAppendPrintf(sentry, "\nDNS jumbo-grams: %zd Bytes\n", Config.dns.packet_max);
    else
        storeAppendPrintf(sentry, "\nDNS jumbo-grams: not working\n");

    storeAppendPrintf(sentry, "\nNameservers:\n");
    storeAppendPrintf(sentry, "IP ADDRESS                                     # QUERIES # REPLIES Type\n");
    storeAppendPrintf(sentry, "---------------------------------------------- --------- --------- --------\n");

    for (i = 0; i < nns; ++i) {
        storeAppendPrintf(sentry, "%-45s %9d %9d %s\n",  /* Let's take the maximum: (15 IPv4/45 IPv6) */
                          nameservers[i].S.toStr(buf,MAX_IPSTRLEN),
                          nameservers[i].nqueries,
                          nameservers[i].nreplies,
                          nameservers[i].mDNSResolver?"multicast":"recurse");
    }

    storeAppendPrintf(sentry, "\nRcode Matrix:\n");
    storeAppendPrintf(sentry, "RCODE");

    for (i = 0; i < MAX_ATTEMPT; ++i)
        storeAppendPrintf(sentry, " ATTEMPT%d", i + 1);

    storeAppendPrintf(sentry, " PROBLEM\n");

    for (j = 0; j < MAX_RCODE; ++j) {
        if (j > 10 && j < 16)
            continue; // unassigned by IANA.

        storeAppendPrintf(sentry, "%5d", j);

        for (i = 0; i < MAX_ATTEMPT; ++i)
            storeAppendPrintf(sentry, " %8d", RcodeMatrix[j][i]);

        storeAppendPrintf(sentry, " : %s\n",Rcodes[j]);
    }

    if (npc) {
        storeAppendPrintf(sentry, "\nSearch list:\n");

        for (i=0; i < npc; ++i)
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

    const double when = min(Config.Timeout.idns_query, Config.Timeout.idns_retransmit)/1000.0;

    eventAdd("idnsCheckQueue", idnsCheckQueue, NULL, when, 1);

    event_queued = 1;
}

static void
idnsSentQueryVC(const Comm::ConnectionPointer &conn, char *, size_t size, Comm::Flag flag, int, void *data)
{
    nsvc * vc = (nsvc *)data;

    if (flag == Comm::ERR_CLOSING)
        return;

    // XXX: irrelevant now that we have conn pointer?
    if (!Comm::IsConnOpen(conn) || fd_table[conn->fd].closing())
        return;

    if (flag != Comm::OK || size <= 0) {
        conn->close();
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

    // if retrying after a TC UDP response, our close handler cb may be pending
    if (fd_table[vc->conn->fd].closing())
        return;

    MemBuf *mb = vc->queue;

    vc->queue = new MemBuf;

    vc->busy = 1;

    // Comm needs seconds but idnsCheckQueue() will check the exact timeout
    const int timeout = (Config.Timeout.idns_query % 1000 ?
                         Config.Timeout.idns_query + 1000 : Config.Timeout.idns_query) / 1000;
    AsyncCall::Pointer nil;

    commSetConnTimeout(vc->conn, timeout, nil);

    AsyncCall::Pointer call = commCbCall(78, 5, "idnsSentQueryVC",
                                         CommIoCbPtrFun(&idnsSentQueryVC, vc));
    Comm::Write(vc->conn, mb, call);

    delete mb;
}

static void
idnsInitVCConnected(const Comm::ConnectionPointer &conn, Comm::Flag status, int, void *data)
{
    nsvc * vc = (nsvc *)data;

    if (status != Comm::OK || !conn) {
        char buf[MAX_IPSTRLEN] = "";
        if (vc->ns < nns)
            nameservers[vc->ns].S.toStr(buf,MAX_IPSTRLEN);
        debugs(78, DBG_IMPORTANT, HERE << "Failed to connect to nameserver " << buf << " using TCP.");
        return;
    }

    vc->conn = conn;

    comm_add_close_handler(conn->fd, idnsVCClosed, vc);
    AsyncCall::Pointer call = commCbCall(5,4, "idnsReadVCHeader",
                                         CommIoCbPtrFun(idnsReadVCHeader, vc));
    comm_read(conn, (char *)&vc->msglen, 2, call);
    vc->busy = 0;
    idnsDoSendQueryVC(vc);
}

static void
idnsVCClosed(const CommCloseCbParams &params)
{
    nsvc * vc = (nsvc *)params.data;
    delete vc;
}

nsvc::~nsvc()
{
    delete queue;
    delete msg;
    if (ns < nns) // XXX: idnsShutdownAndFreeState may have freed nameservers[]
        nameservers[ns].vc = NULL;
}

static void
idnsInitVC(int nsv)
{
    nsvc *vc = new nsvc(nsv);
    assert(nsv < nns);
    assert(vc->conn == NULL); // MUST be NULL from the construction process!
    nameservers[nsv].vc = vc;

    Comm::ConnectionPointer conn = new Comm::Connection();

    if (!Config.Addrs.udp_outgoing.isNoAddr())
        conn->setAddrs(Config.Addrs.udp_outgoing, nameservers[nsv].S);
    else
        conn->setAddrs(Config.Addrs.udp_incoming, nameservers[nsv].S);

    if (conn->remote.isIPv4())
        conn->local.setIPv4();

    AsyncCall::Pointer call = commCbCall(78,3, "idnsInitVCConnected", CommConnectCbPtrFun(idnsInitVCConnected, vc));

    Comm::ConnOpener *cs = new Comm::ConnOpener(conn, call, Config.Timeout.connect);
    cs->setHost("DNS TCP Socket");
    AsyncJob::Start(cs);
}

static void
idnsSendQueryVC(idns_query * q, int nsn)
{
    assert(nsn < nns);
    if (nameservers[nsn].vc == NULL)
        idnsInitVC(nsn);

    nsvc *vc = nameservers[nsn].vc;

    if (!vc) {
        char buf[MAX_IPSTRLEN];
        debugs(78, DBG_IMPORTANT, "idnsSendQuery: Failed to initiate TCP connection to nameserver " << nameservers[nsn].S.toStr(buf,MAX_IPSTRLEN) << "!");

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
    // XXX: DNS sockets get closed during reconfigure produces a race between
    // any already active connections (or ones received between closing DNS
    // sockets and server listening sockets) and the reconfigure completing
    // (Runner syncConfig() being run). Transactions which loose this race will
    // produce DNS timeouts (or whatever the caller set) as their queries never
    // get queued to be re-tried after the DNS socekts are re-opened.

    if (DnsSocketA < 0 && DnsSocketB < 0) {
        debugs(78, DBG_IMPORTANT, "WARNING: idnsSendQuery: Can't send query, no DNS socket!");
        return;
    }

    if (nns <= 0) {
        debugs(78, DBG_IMPORTANT, "WARNING: idnsSendQuery: Can't send query, no DNS nameservers known!");
        return;
    }

    assert(q->lru.next == NULL);

    assert(q->lru.prev == NULL);

    int x = -1, y = -1;
    int nsn;

    do {
        // only use mDNS resolvers for mDNS compatible queries
        if (!q->permit_mdns)
            nsn = nns_mdns_count + q->nsends % (nns-nns_mdns_count);
        else
            nsn = q->nsends % nns;

        if (q->need_vc) {
            idnsSendQueryVC(q, nsn);
            x = y = 0;
        } else {
            if (DnsSocketB >= 0 && nameservers[nsn].S.isIPv6())
                y = comm_udp_sendto(DnsSocketB, nameservers[nsn].S, q->buf, q->sz);
            else if (DnsSocketA >= 0)
                x = comm_udp_sendto(DnsSocketA, nameservers[nsn].S, q->buf, q->sz);
        }
        int xerrno = errno;

        ++ q->nsends;

        q->sent_t = current_time;

        if (y < 0 && nameservers[nsn].S.isIPv6())
            debugs(50, DBG_IMPORTANT, MYNAME << "FD " << DnsSocketB << ": sendto: " << xstrerr(xerrno));
        if (x < 0 && nameservers[nsn].S.isIPv4())
            debugs(50, DBG_IMPORTANT, MYNAME << "FD " << DnsSocketA << ": sendto: " << xstrerr(xerrno));

    } while ( (x<0 && y<0) && q->nsends % nns != 0);

    if (y > 0) {
        fd_bytes(DnsSocketB, y, FD_WRITE);
    }
    if (x > 0) {
        fd_bytes(DnsSocketA, x, FD_WRITE);
    }

    ++ nameservers[nsn].nqueries;
    q->queue_t = current_time;
    dlinkAdd(q, &q->lru, &lru_list);
    q->pending = 1;
    idnsTickleQueue();
}

static int
idnsFromKnownNameserver(Ip::Address const &from)
{
    int i;

    for (i = 0; i < nns; ++i) {
        if (nameservers[i].S != from)
            continue;

        if (nameservers[i].S.port() != from.port())
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

        if (q->query_id == id)
            return q;
    }

    return NULL;
}

static unsigned short
idnsQueryID()
{
    // NP: apparently ranlux are faster, but not quite as "proven"
    static std::mt19937 mt(static_cast<uint32_t>(getCurrentTime() & 0xFFFFFFFF));
    unsigned short id = mt() & 0xFFFF;
    unsigned short first_id = id;

    // ensure temporal uniqueness by looking for an existing use
    while (idnsFindQuery(id)) {
        ++id;

        if (id == first_id) {
            debugs(78, DBG_IMPORTANT, "idnsQueryID: Warning, too many pending DNS requests");
            break;
        }
    }

    return id;
}

static void
idnsCallback(idns_query *q, const char *error)
{
    IDNSCB *callback;
    void *cbdata;

    if (error)
        q->error = error;

    if (q->master)
        q = q->master;

    // If any of our subqueries are still pending then wait for them to complete before continuing
    for (idns_query *q2 = q; q2; q2 = q2->slave) {
        if (q2->pending) {
            return;
        }
    }

    /* Merge results */
    rfc1035_message *message = q->message;
    q->message = NULL;
    int n = q->ancount;
    error = q->error;

    while ( idns_query *q2 = q->slave ) {
        debugs(78, 6, HERE << "Merging DNS results " << q->name << " A has " << n << " RR, AAAA has " << q2->ancount << " RR");
        q->slave = q2->slave;
        q2->slave = NULL;
        if ( !q2->error ) {
            if (n > 0) {
                // two sets of RR need merging
                rfc1035_rr *result = (rfc1035_rr*) xmalloc( sizeof(rfc1035_rr)*(n + q2->ancount) );
                if (Config.dns.v4_first) {
                    memcpy(result, message->answer, (sizeof(rfc1035_rr)*n) );
                    memcpy(result+n, q2->message->answer, (sizeof(rfc1035_rr)*q2->ancount) );
                } else {
                    memcpy(result, q2->message->answer, (sizeof(rfc1035_rr)*q2->ancount) );
                    memcpy(result+q2->ancount, message->answer, (sizeof(rfc1035_rr)*n) );
                }
                n += q2->ancount;
                // HACK WARNING, the answer rr:s have been copied in-place to
                // result, do not free them here
                safe_free(message->answer);
                safe_free(q2->message->answer);
                message->answer = result;
                message->ancount += q2->message->ancount;
            } else {
                // first response empty or failed, just use the second
                rfc1035MessageDestroy(&message);
                message = q2->message;
                q2->message = NULL;
                n = q2->ancount;
                error = NULL;
            }
        }
        delete q2;
    }

    debugs(78, 6, HERE << "Sending " << n << " (" << (error ? error : "OK") << ") DNS results to caller.");

    callback = q->callback;
    q->callback = NULL;
    const rfc1035_rr *answers = message ? message->answer : NULL;

    if (cbdataReferenceValidDone(q->callback_data, &cbdata))
        callback(cbdata, answers, n, error);

    while (q->queue) {
        idns_query *q2 = q->queue;
        q->queue = q2->queue;
        q2->queue = NULL;

        callback = q2->callback;
        q2->callback = NULL;

        if (cbdataReferenceValidDone(q2->callback_data, &cbdata))
            callback(cbdata, answers, n, error);

        delete q2;
    }

    if (q->hash.key) {
        hash_remove_link(idns_lookup_hash, &q->hash);
        q->hash.key = NULL;
    }

    rfc1035MessageDestroy(&message);
    delete q;
}

static void
idnsGrokReply(const char *buf, size_t sz, int /*from_ns*/)
{
    rfc1035_message *message = NULL;

    int n = rfc1035MessageUnpack(buf, sz, &message);

    if (message == NULL) {
        debugs(78, DBG_IMPORTANT, "idnsGrokReply: Malformed DNS response");
        return;
    }

    debugs(78, 3, "idnsGrokReply: QID 0x" << std::hex <<   message->id << ", " << std::dec << n << " answers");

    idns_query *q = idnsFindQuery(message->id);

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

#if WHEN_EDNS_RESPONSES_ARE_PARSED
// TODO: actually gr the message right here.
//  pull out the DNS meta data we need (A records, AAAA records and EDNS OPT) and store in q
//  this is overall better than force-feeding A response with AAAA an section later anyway.
//  AND allows us to merge AN+AR sections from both responses (one day)

    if (q->edns_seen >= 0) {
        if (max_shared_edns == nameservers[from_ns].last_seen_edns && max_shared_edns < q->edns_seen) {
            nameservers[from_ns].last_seen_edns = q->edns_seen;
            // the altered NS was limiting the whole group.
            max_shared_edns = q->edns_seen;
            // may be limited by one of the others still
            for (int i = 0; i < nns; ++i)
                max_shared_edns = min(max_shared_edns, nameservers[i].last_seen_edns);
        } else {
            nameservers[from_ns].last_seen_edns = q->edns_seen;
            // maybe reduce the global limit downwards to accomodate this NS
            max_shared_edns = min(max_shared_edns, q->edns_seen);
        }
        if (max_shared_edns < RFC1035_DEFAULT_PACKET_SZ)
            max_shared_edns = -1;
    }
#endif

    dlinkDelete(&q->lru, &lru_list);
    q->pending = 0;

    if (message->tc) {
        debugs(78, 3, HERE << "Resolver requested TC (" << q->query.name << ")");
        rfc1035MessageDestroy(&message);

        if (!q->need_vc) {
            q->need_vc = 1;
            -- q->nsends;
            idnsSendQuery(q);
        } else {
            // Strange: A TCP DNS response with the truncation bit (TC) set.
            // Return an error and cleanup; no point in trying TCP again.
            debugs(78, 3, HERE << "TCP DNS response");
            idnsCallback(q, "Truncated TCP DNS response");
        }

        return;
    }

    idnsRcodeCount(n, q->attempt);

    if (n < 0) {
        q->rcode = -n;
        debugs(78, 3, "idnsGrokReply: error " << rfc1035ErrorMessage(n) << " (" << q->rcode << ")");

        if (q->rcode == 2 && (++ q->attempt) < MAX_ATTEMPT) {
            /*
             * RCODE 2 is "Server failure - The name server was
             * unable to process this query due to a problem with
             * the name server."
             */
            debugs(78, 3, "idnsGrokReply: Query result: SERV_FAIL");
            rfc1035MessageDestroy(&message);
            idnsSendQuery(q);
            return;
        }

        // Do searchpath processing on the master A query only to keep
        // things simple. NXDOMAIN is authorative for the label, not
        // the record type.
        if (q->rcode == 3 && !q->master && q->do_searchpath && q->attempt < MAX_ATTEMPT) {
            assert(NULL == message->answer);
            strcpy(q->name, q->orig);

            debugs(78, 3, "idnsGrokReply: Query result: NXDOMAIN - " << q->name );

            if (q->domain < npc) {
                strcat(q->name, ".");
                strcat(q->name, searchpath[q->domain].domain);
                debugs(78, 3, "idnsGrokReply: searchpath used for " << q->name);
                ++ q->domain;
            } else {
                ++ q->attempt;
            }

            rfc1035MessageDestroy(&message);

            // cleanup slave AAAA query
            while (idns_query *slave = q->slave) {
                dlinkDelete(&slave->lru, &lru_list);
                q->slave = slave->slave;
                slave->slave = NULL;
                delete slave;
            }

            // Build new query
            q->query_id = idnsQueryID();
            debugs(78, 3, "idnsGrokReply: Trying A Query for " << q->name);
            // see EDNS notes at top of file why this sends 0
            q->sz = rfc3596BuildAQuery(q->name, q->buf, sizeof(q->buf), q->query_id, &q->query, 0);
            if (q->sz < 0) {
                /* problem with query data -- query not sent */
                idnsCallback(q, "Internal error");
                return;
            }

            q->nsends = 0;

            idnsCheckMDNS(q);
            idnsSendQuery(q);
            if (Ip::EnableIpv6)
                idnsSendSlaveAAAAQuery(q);
            return;
        }
    }

    q->message = message;
    q->ancount = n;

    if (n >= 0)
        idnsCallback(q, NULL);
    else
        idnsCallback(q, rfc1035ErrorMessage(q->rcode));

}

static void
idnsRead(int fd, void *)
{
    int *N = &incoming_sockets_accepted;
    int len;
    int max = INCOMING_DNS_MAX;
    static char rbuf[SQUID_UDP_SO_RCVBUF];
    Ip::Address from;

    debugs(78, 3, "idnsRead: starting with FD " << fd);

    // Always keep reading. This stops (or at least makes harder) several
    // attacks on the DNS client.
    Comm::SetSelect(fd, COMM_SELECT_READ, idnsRead, NULL, 0);

    /* BUG (UNRESOLVED)
     *  two code lines after returning from comm_udprecvfrom()
     *  something overwrites the memory behind the from parameter.
     *  NO matter where in the stack declaration list above it is placed
     *  The cause of this is still unknown, however copying the data appears
     *  to allow it to be passed further without this erasure.
     */
    Ip::Address bugbypass;

    while (max) {
        --max;
        len = comm_udp_recvfrom(fd, rbuf, SQUID_UDP_SO_RCVBUF, 0, bugbypass);

        from = bugbypass; // BUG BYPASS. see notes above.

        if (len == 0)
            break;

        if (len < 0) {
            int xerrno = errno;
            if (ignoreErrno(xerrno))
                break;

#if _SQUID_LINUX_
            /* Some Linux systems seem to set the FD for reading and then
             * return ECONNREFUSED when sendto() fails and generates an ICMP
             * port unreachable message. */
            /* or maybe an EHOSTUNREACH "No route to host" message */
            if (xerrno != ECONNREFUSED && xerrno != EHOSTUNREACH)
#endif
                debugs(50, DBG_IMPORTANT, MYNAME << "FD " << fd << " recvfrom: " << xstrerr(xerrno));

            break;
        }

        fd_bytes(fd, len, FD_READ);

        assert(N);
        ++(*N);

        debugs(78, 3, "idnsRead: FD " << fd << ": received " << len << " bytes from " << from);

        /* BUG: see above. Its here that it becomes apparent that the content of bugbypass is gone. */
        int nsn = idnsFromKnownNameserver(from);

        if (nsn >= 0) {
            ++ nameservers[nsn].nreplies;
        }

        // Before unknown_nameservers check to avoid flooding cache.log on attacks,
        // but after the ++ above to keep statistics right.
        if (!lru_list.head)
            continue; // Don't process replies if there is no pending query.

        if (nsn < 0 && Config.onoff.ignore_unknown_nameservers) {
            static time_t last_warning = 0;

            if (squid_curtime - last_warning > 60) {
                debugs(78, DBG_IMPORTANT, "WARNING: Reply from unknown nameserver " << from);
                last_warning = squid_curtime;
            } else {
                debugs(78, DBG_IMPORTANT, "WARNING: Reply from unknown nameserver " << from << " (retrying..." <<  (squid_curtime-last_warning) << "<=60)" );
            }
            continue;
        }

        idnsGrokReply(rbuf, len, nsn);
    }
}

static void
idnsCheckQueue(void *)
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
        if ((time_msec_t)tvSubMsec(q->queue_t, current_time) < Config.Timeout.idns_retransmit )
            break;

        /* Query timer still running? */
        if ((time_msec_t)tvSubMsec(q->sent_t, current_time) < (Config.Timeout.idns_retransmit * 1 << ((q->nsends - 1) / nns))) {
            dlinkDelete(&q->lru, &lru_list);
            q->queue_t = current_time;
            dlinkAdd(q, &q->lru, &lru_list);
            continue;
        }

        debugs(78, 3, "idnsCheckQueue: ID " << q->xact_id <<
               " QID 0x"  << std::hex << std::setfill('0')  <<
               std::setw(4) << q->query_id << ": timeout" );

        dlinkDelete(&q->lru, &lru_list);
        q->pending = 0;

        if ((time_msec_t)tvSubMsec(q->start_t, current_time) < Config.Timeout.idns_query) {
            idnsSendQuery(q);
        } else {
            debugs(78, 2, "idnsCheckQueue: ID " << q->xact_id <<
                   " QID 0x" << std::hex << q->query_id <<
                   " : giving up after " << std::dec << q->nsends << " tries and " <<
                   std::setw(5)<< std::setprecision(2) << tvSubDsec(q->start_t, current_time) << " seconds");

            if (q->rcode != 0)
                idnsCallback(q, rfc1035ErrorMessage(q->rcode));
            else
                idnsCallback(q, "Timeout");
        }
    }

    idnsTickleQueue();
}

static void
idnsReadVC(const Comm::ConnectionPointer &conn, char *buf, size_t len, Comm::Flag flag, int, void *data)
{
    nsvc * vc = (nsvc *)data;

    if (flag == Comm::ERR_CLOSING)
        return;

    if (flag != Comm::OK || len <= 0) {
        if (Comm::IsConnOpen(conn))
            conn->close();
        return;
    }

    vc->msg->size += len;       // XXX should not access -> size directly

    if (vc->msg->contentSize() < vc->msglen) {
        AsyncCall::Pointer call = commCbCall(5,4, "idnsReadVC",
                                             CommIoCbPtrFun(idnsReadVC, vc));
        comm_read(conn, buf+len, vc->msglen - vc->msg->contentSize(), call);
        return;
    }

    assert(vc->ns < nns);
    debugs(78, 3, HERE << conn << ": received " << vc->msg->contentSize() << " bytes via TCP from " << nameservers[vc->ns].S << ".");

    idnsGrokReply(vc->msg->buf, vc->msg->contentSize(), vc->ns);
    vc->msg->clean();
    AsyncCall::Pointer call = commCbCall(5,4, "idnsReadVCHeader",
                                         CommIoCbPtrFun(idnsReadVCHeader, vc));
    comm_read(conn, (char *)&vc->msglen, 2, call);
}

static void
idnsReadVCHeader(const Comm::ConnectionPointer &conn, char *buf, size_t len, Comm::Flag flag, int, void *data)
{
    nsvc * vc = (nsvc *)data;

    if (flag == Comm::ERR_CLOSING)
        return;

    if (flag != Comm::OK || len <= 0) {
        if (Comm::IsConnOpen(conn))
            conn->close();
        return;
    }

    vc->read_msglen += len;

    assert(vc->read_msglen <= 2);

    if (vc->read_msglen < 2) {
        AsyncCall::Pointer call = commCbCall(5,4, "idnsReadVCHeader",
                                             CommIoCbPtrFun(idnsReadVCHeader, vc));
        comm_read(conn, buf+len, 2 - vc->read_msglen, call);
        return;
    }

    vc->read_msglen = 0;

    vc->msglen = ntohs(vc->msglen);

    if (!vc->msglen) {
        if (Comm::IsConnOpen(conn))
            conn->close();
        return;
    }

    vc->msg->init(vc->msglen, vc->msglen);
    AsyncCall::Pointer call = commCbCall(5,4, "idnsReadVC",
                                         CommIoCbPtrFun(idnsReadVC, vc));
    comm_read(conn, vc->msg->buf, vc->msglen, call);
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
            ++ RcodeMatrix[rcode][attempt];
}

void
Dns::Init(void)
{
    static int init = 0;

    if (DnsSocketA < 0 && DnsSocketB < 0) {
        Ip::Address addrV6; // since we don't want to alter Config.Addrs.udp_* and dont have one of our own.

        if (!Config.Addrs.udp_outgoing.isNoAddr())
            addrV6 = Config.Addrs.udp_outgoing;
        else
            addrV6 = Config.Addrs.udp_incoming;

        Ip::Address addrV4 = addrV6;
        addrV4.setIPv4();

        if (Ip::EnableIpv6 && addrV6.isIPv6()) {
            debugs(78, 2, "idnsInit: attempt open DNS socket to: " << addrV6);
            DnsSocketB = comm_open_listener(SOCK_DGRAM,
                                            IPPROTO_UDP,
                                            addrV6,
                                            COMM_NONBLOCKING,
                                            "DNS Socket IPv6");
        }

        if (addrV4.isIPv4()) {
            debugs(78, 2, "idnsInit: attempt open DNS socket to: " << addrV4);
            DnsSocketA = comm_open_listener(SOCK_DGRAM,
                                            IPPROTO_UDP,
                                            addrV4,
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
            debugs(78, DBG_IMPORTANT, "DNS Socket created at " << addrV6 << ", FD " << DnsSocketB);
            Comm::SetSelect(DnsSocketB, COMM_SELECT_READ, idnsRead, NULL, 0);
        }
        if (DnsSocketA >= 0) {
            comm_local_port(DnsSocketA);
            debugs(78, DBG_IMPORTANT, "DNS Socket created at " << addrV4 << ", FD " << DnsSocketA);
            Comm::SetSelect(DnsSocketA, COMM_SELECT_READ, idnsRead, NULL, 0);
        }
    }

    assert(0 == nns);
    idnsAddMDNSNameservers();
    bool nsFound = idnsParseNameservers();

    if (!nsFound)
        nsFound = idnsParseResolvConf();

#if _SQUID_WINDOWS_
    if (!nsFound)
        nsFound = idnsParseWIN32Registry();
#endif

    if (!nsFound) {
        debugs(78, DBG_IMPORTANT, "Warning: Could not find any nameservers. Trying to use localhost");
#if _SQUID_WINDOWS_
        debugs(78, DBG_IMPORTANT, "Please check your TCP-IP settings or /etc/resolv.conf file");
#else
        debugs(78, DBG_IMPORTANT, "Please check your /etc/resolv.conf file");
#endif

        debugs(78, DBG_IMPORTANT, "or use the 'dns_nameservers' option in squid.conf.");
        if (Ip::EnableIpv6)
            idnsAddNameserver("::1");
        idnsAddNameserver("127.0.0.1");
    }

    if (!init) {
        memset(RcodeMatrix, '\0', sizeof(RcodeMatrix));
        idns_lookup_hash = hash_create((HASHCMP *) strcmp, 103, hash_string);
        ++init;
    }

#if WHEN_EDNS_RESPONSES_ARE_PARSED
    if (Config.onoff.ignore_unknown_nameservers && max_shared_edns > 0) {
        debugs(0, DBG_IMPORTANT, "ERROR: cannot negotiate EDNS with unknown nameservers. Disabling");
        max_shared_edns = -1; // disable if we might receive random replies.
    }
#endif

    Mgr::RegisterAction("idns", "Internal DNS Statistics", idnsStats, 0, 1);
}

static void
idnsShutdownAndFreeState(const char *reason)
{
    if (DnsSocketA < 0 && DnsSocketB < 0)
        return;

    debugs(78, 2, reason << ": Closing DNS sockets");

    if (DnsSocketA >= 0 ) {
        comm_close(DnsSocketA);
        DnsSocketA = -1;
    }

    if (DnsSocketB >= 0 ) {
        comm_close(DnsSocketB);
        DnsSocketB = -1;
    }

    for (int i = 0; i < nns; ++i) {
        if (nsvc *vc = nameservers[i].vc) {
            if (Comm::IsConnOpen(vc->conn))
                vc->conn->close();
        }
    }

    // XXX: vcs are not closed/freed yet and may try to access nameservers[]
    idnsFreeNameservers();
    idnsFreeSearchpath();
}

void
Dns::ConfigRr::endingShutdown()
{
    idnsShutdownAndFreeState("Shutdown");
}

void
Dns::ConfigRr::startReconfigure()
{
    idnsShutdownAndFreeState("Reconfigure");
}

static int
idnsCachedLookup(const char *key, IDNSCB * callback, void *data)
{
    idns_query *old = (idns_query *) hash_lookup(idns_lookup_hash, key);

    if (!old)
        return 0;

    idns_query *q = new idns_query;
    // no query_id on this instance.

    q->callback = callback;
    q->callback_data = cbdataReference(data);

    q->queue = old->queue;
    old->queue = q;

    return 1;
}

static void
idnsStartQuery(idns_query *q, IDNSCB * callback, void *data)
{
    q->start_t = current_time;
    q->callback = callback;
    q->callback_data = cbdataReference(data);

    q->hash.key = q->orig;
    hash_join(idns_lookup_hash, &q->hash);

    idnsSendQuery(q);
}

static void
idnsSendSlaveAAAAQuery(idns_query *master)
{
    idns_query *q = new idns_query;
    memcpy(q->name, master->name, sizeof(q->name));
    memcpy(q->orig, master->orig, sizeof(q->orig));
    q->master = master;
    q->query_id = idnsQueryID();
    q->sz = rfc3596BuildAAAAQuery(q->name, q->buf, sizeof(q->buf), q->query_id, &q->query, Config.dns.packet_max);

    debugs(78, 3, HERE << "buf is " << q->sz << " bytes for " << q->name <<
           ", id = 0x" << std::hex << q->query_id);
    if (!q->sz) {
        delete q;
        return;
    }

    q->start_t = master->start_t;
    q->slave = master->slave;

    idnsCheckMDNS(q);
    master->slave = q;
    idnsSendQuery(q);
}

void
idnsALookup(const char *name, IDNSCB * callback, void *data)
{
    size_t nameLength = strlen(name);

    // Prevent buffer overflow on q->name
    if (nameLength > NS_MAXDNAME) {
        debugs(23, DBG_IMPORTANT, "SECURITY ALERT: DNS name too long to perform lookup: '" << name << "'. see access.log for details.");
        callback(data, NULL, 0, "Internal error");
        return;
    }

    if (idnsCachedLookup(name, callback, data))
        return;

    idns_query *q = new idns_query;
    q->query_id = idnsQueryID();

    int nd = 0;
    for (unsigned int i = 0; i < nameLength; ++i)
        if (name[i] == '.')
            ++nd;

    if (Config.onoff.res_defnames && npc > 0 && name[nameLength-1] != '.') {
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

    // see EDNS notes at top of file why this sends 0
    q->sz = rfc3596BuildAQuery(q->name, q->buf, sizeof(q->buf), q->query_id, &q->query, 0);

    if (q->sz < 0) {
        /* problem with query data -- query not sent */
        callback(data, NULL, 0, "Internal error");
        delete q;
        return;
    }

    debugs(78, 3, "idnsALookup: buf is " << q->sz << " bytes for " << q->name <<
           ", id = 0x" << std::hex << q->query_id);

    idnsCheckMDNS(q);
    idnsStartQuery(q, callback, data);

    if (Ip::EnableIpv6)
        idnsSendSlaveAAAAQuery(q);
}

void
idnsPTRLookup(const Ip::Address &addr, IDNSCB * callback, void *data)
{
    char ip[MAX_IPSTRLEN];

    addr.toStr(ip,MAX_IPSTRLEN);

    idns_query *q = new idns_query;
    q->query_id = idnsQueryID();

    if (addr.isIPv6()) {
        struct in6_addr addr6;
        addr.getInAddr(addr6);
        q->sz = rfc3596BuildPTRQuery6(addr6, q->buf, sizeof(q->buf), q->query_id, &q->query, Config.dns.packet_max);
    } else {
        struct in_addr addr4;
        addr.getInAddr(addr4);
        // see EDNS notes at top of file why this sends 0
        q->sz = rfc3596BuildPTRQuery4(addr4, q->buf, sizeof(q->buf), q->query_id, &q->query, 0);
    }

    if (q->sz < 0) {
        /* problem with query data -- query not sent */
        callback(data, NULL, 0, "Internal error");
        delete q;
        return;
    }

    if (idnsCachedLookup(q->query.name, callback, data)) {
        delete q;
        return;
    }

    debugs(78, 3, "idnsPTRLookup: buf is " << q->sz << " bytes for " << ip <<
           ", id = 0x" << std::hex << q->query_id);

    q->permit_mdns = Config.onoff.dns_mdns;
    idnsStartQuery(q, callback, data);
}

#if SQUID_SNMP
/*
 * The function to return the DNS via SNMP
 */
variable_list *
snmp_netDnsFn(variable_list * Var, snint * ErrP)
{
    int i, n = 0;
    variable_list *Answer = NULL;
    MemBuf tmp;
    debugs(49, 5, "snmp_netDnsFn: Processing request: " << snmpDebugOid(Var->name, Var->name_length, tmp));
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[LEN_SQ_NET + 1]) {

    case DNS_REQ:

        for (i = 0; i < nns; ++i)
            n += nameservers[i].nqueries;

        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      n,
                                      SMI_COUNTER32);

        break;

    case DNS_REP:
        for (i = 0; i < nns; ++i)
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

