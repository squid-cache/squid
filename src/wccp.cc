
/*
 * $Id$
 *
 * DEBUG: section 80    WCCP Support
 * AUTHOR: Glenn Chisholm
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
#include "comm.h"
#include "event.h"

#if USE_WCCP

#define WCCP_PORT 2048
#define WCCP_REVISION 0
#define WCCP_ACTIVE_CACHES 32
#define WCCP_HASH_SIZE 32
#define WCCP_BUCKETS 256
#define WCCP_CACHE_LEN 4

#define WCCP_HERE_I_AM 7
#define WCCP_I_SEE_YOU 8
#define WCCP_ASSIGN_BUCKET 9

struct wccp_here_i_am_t {
    int type;
    int version;
    int revision;
    char hash[WCCP_HASH_SIZE];
    int reserved;
    int id;
};

struct wccp_cache_entry_t {
    IpAddress ip_addr;
    int revision;
    char hash[WCCP_HASH_SIZE];
    int reserved;
};

struct wccp_i_see_you_t {
    int type;
    int version;
    int change;
    int id;
    int number;

    struct wccp_cache_entry_t wccp_cache_entry[WCCP_ACTIVE_CACHES];
};

struct wccp_assign_bucket_t {
    int type;
    int id;
    int number;
};

static int theWccpConnection = -1;

static struct wccp_here_i_am_t wccp_here_i_am;

static struct wccp_i_see_you_t wccp_i_see_you;
static int last_change;
static int last_id;
static int last_assign_buckets_change;
static unsigned int number_caches;

static IpAddress local_ip;

static PF wccpHandleUdp;
static int wccpLowestIP(void);
static EVH wccpHereIam;
static void wccpAssignBuckets(void);

/*
 * The functions used during startup:
 * wccpInit
 * wccpConnectionOpen
 * wccpConnectionShutdown
 * wccpConnectionClose
 */

void
wccpInit(void)
{
    debugs(80, 5, "wccpInit: Called");
    memset(&wccp_here_i_am, '\0', sizeof(wccp_here_i_am));
    wccp_here_i_am.type = htonl(WCCP_HERE_I_AM);
    wccp_here_i_am.version = htonl(Config.Wccp.version);
    wccp_here_i_am.revision = htonl(WCCP_REVISION);
    last_change = 0;
    last_id = 0;
    last_assign_buckets_change = 0;
    number_caches = 0;

    if (!Config.Wccp.router.IsAnyAddr())
        if (!eventFind(wccpHereIam, NULL))
            eventAdd("wccpHereIam", wccpHereIam, NULL, 5.0, 1);
}

void
wccpConnectionOpen(void)
{
    struct addrinfo *router = NULL, *local = NULL;
    debugs(80, 5, "wccpConnectionOpen: Called");

    if (Config.Wccp.router.IsAnyAddr()) {
        debugs(80, 2, "WCCPv1 disabled.");
        return;
    }

    if ( !Config.Wccp.router.SetIPv4() ) {
        debugs(1, 1, "WCCPv1 Disabled. Router " << Config.Wccp.router << " is not IPv4.");
        return;
    }

    if ( !Config.Wccp.address.SetIPv4() ) {
        debugs(1, 1, "WCCPv1 Disabled. Local address " << Config.Wccp.address << " is not IPv4.");
        return;
    }

    Config.Wccp.address.SetPort(WCCP_PORT);
    Config.Wccp.router.SetPort(WCCP_PORT);

    theWccpConnection = comm_open_listener(SOCK_DGRAM,
                                           IPPROTO_UDP,
                                           Config.Wccp.address,
                                           COMM_NONBLOCKING,
                                           "WCCP Socket");

    if (theWccpConnection < 0)
        fatal("Cannot open WCCP Port");

    commSetSelect(theWccpConnection,
                  COMM_SELECT_READ,
                  wccpHandleUdp,
                  NULL,
                  0);

    debugs(80, 1, "Accepting WCCPv1 messages on " << Config.Wccp.address << ", FD " << theWccpConnection << ".");

    Config.Wccp.router.GetAddrInfo(router,AF_INET);

    if (connect(theWccpConnection, router->ai_addr, router->ai_addrlen))
        fatal("Unable to connect WCCP out socket");

    Config.Wccp.router.FreeAddrInfo(router);

    Config.Wccp.address.InitAddrInfo(local);

    if (getsockname(theWccpConnection, local->ai_addr, &local->ai_addrlen))
        fatal("Unable to getsockname on WCCP out socket");

    local_ip = *local;

    Config.Wccp.address.FreeAddrInfo(local);
}


void
wccpConnectionClose(void)
{
    if (theWccpConnection > -1) {
        debugs(80, 1, "FD " << theWccpConnection << " Closing WCCPv1 socket");
        comm_close(theWccpConnection);
        theWccpConnection = -1;
    }
}

/*
 * Functions for handling the requests.
 */

/*
 * Accept the UDP packet
 */
static void
wccpHandleUdp(int sock, void *not_used)
{

    IpAddress from;
    int len;

    debugs(80, 6, "wccpHandleUdp: Called.");

    commSetSelect(sock, COMM_SELECT_READ, wccpHandleUdp, NULL, 0);

    memset(&wccp_i_see_you, '\0', sizeof(wccp_i_see_you));

    len = comm_udp_recvfrom(sock,
                            (void *) &wccp_i_see_you,
                            sizeof(wccp_i_see_you),
                            0,
                            from);
    debugs(80, 3, "wccpHandleUdp: " << len << " bytes WCCP pkt from " << from <<
           ": type=" <<
           (unsigned) ntohl(wccp_i_see_you.type) << ", version=" <<
           (unsigned) ntohl(wccp_i_see_you.version) << ", change=" <<
           (unsigned) ntohl(wccp_i_see_you.change) << ", id=" <<
           (unsigned) ntohl(wccp_i_see_you.id) << ", number=" <<
           (unsigned) ntohl(wccp_i_see_you.number));

    if (len < 0)
        return;

    if (from != Config.Wccp.router)
        return;

    if ((unsigned) ntohl(wccp_i_see_you.version) != (unsigned) Config.Wccp.version)
        return;

    if (ntohl(wccp_i_see_you.type) != WCCP_I_SEE_YOU)
        return;

    if (ntohl(wccp_i_see_you.number) > WCCP_ACTIVE_CACHES) {
        debugs(80, 1, "Ignoring WCCP_I_SEE_YOU from " <<
               from << " with number of caches set to " <<
               (int) ntohl(wccp_i_see_you.number));

        return;
    }

    last_id = wccp_i_see_you.id;

    if ((0 == last_change) && (number_caches == (unsigned) ntohl(wccp_i_see_you.number))) {
        if (last_assign_buckets_change == wccp_i_see_you.change) {
            /*
             * After a WCCP_ASSIGN_BUCKET message, the router should
             * update the change value.  If not, maybe the route didn't
             * receive our WCCP_ASSIGN_BUCKET message, so send it again.
             *
             * Don't update change here.  Instead, fall through to
             * the next block to call wccpAssignBuckets() again.
             */
            (void) 0;
        } else {
            last_change = wccp_i_see_you.change;
            return;
        }
    }

    if (last_change != wccp_i_see_you.change) {
        last_change = wccp_i_see_you.change;

        if (wccpLowestIP() && wccp_i_see_you.number) {
            last_assign_buckets_change = last_change;
            wccpAssignBuckets();
        }
    }
}

static int
wccpLowestIP(void)
{
    unsigned int loop;
    int found = 0;

    /*
     * We sanity checked wccp_i_see_you.number back in wccpHandleUdp()
     */

    for (loop = 0; loop < (unsigned) ntohl(wccp_i_see_you.number); loop++) {
        assert(loop < WCCP_ACTIVE_CACHES);

        if (wccp_i_see_you.wccp_cache_entry[loop].ip_addr < local_ip)
            return 0;

        if (wccp_i_see_you.wccp_cache_entry[loop].ip_addr == local_ip)
            found = 1;
    }

    return found;
}

static void
wccpHereIam(void *voidnotused)
{
    debugs(80, 6, "wccpHereIam: Called");

    wccp_here_i_am.id = last_id;
    comm_udp_send(theWccpConnection,
                  &wccp_here_i_am,
                  sizeof(wccp_here_i_am),
                  0);

    if (!eventFind(wccpHereIam, NULL))
        eventAdd("wccpHereIam", wccpHereIam, NULL, 10.0, 1);
}

static void
wccpAssignBuckets(void)
{

    struct wccp_assign_bucket_t *wccp_assign_bucket;
    int wab_len;
    char *buckets;
    int buckets_per_cache;
    unsigned int loop;
    int bucket = 0;
    int *caches;
    int cache_len;
    char *buf;

    debugs(80, 6, "wccpAssignBuckets: Called");
    number_caches = ntohl(wccp_i_see_you.number);

    assert(number_caches > 0);
    assert(number_caches <= WCCP_ACTIVE_CACHES);

    wab_len = sizeof(struct wccp_assign_bucket_t);

    cache_len = WCCP_CACHE_LEN * number_caches;

    buf = (char *)xmalloc(wab_len +
                          WCCP_BUCKETS +
                          cache_len);

    wccp_assign_bucket = (struct wccp_assign_bucket_t *) buf;

    caches = (int *) (buf + wab_len);

    buckets = buf + wab_len + cache_len;

    memset(wccp_assign_bucket, '\0', sizeof(wccp_assign_bucket));

    memset(buckets, 0xFF, WCCP_BUCKETS);

    buckets_per_cache = WCCP_BUCKETS / number_caches;

    for (loop = 0; loop < number_caches; loop++) {
        int i;
        xmemcpy(&caches[loop],
                &wccp_i_see_you.wccp_cache_entry[loop].ip_addr,
                sizeof(*caches));

        for (i = 0; i < buckets_per_cache; i++) {
            assert(bucket < WCCP_BUCKETS);
            buckets[bucket++] = loop;
        }
    }

    while (bucket < WCCP_BUCKETS) {
        buckets[bucket++] = number_caches - 1;
    }

    wccp_assign_bucket->type = htonl(WCCP_ASSIGN_BUCKET);
    wccp_assign_bucket->id = wccp_i_see_you.id;
    wccp_assign_bucket->number = wccp_i_see_you.number;

    comm_udp_send(theWccpConnection,
                  buf,
                  wab_len + WCCP_BUCKETS + cache_len,
                  0);
    last_change = 0;
    xfree(buf);
}

#endif /* USE_WCCP */
