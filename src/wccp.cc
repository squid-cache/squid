/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 80    WCCP Support */

#include "squid.h"

#if USE_WCCP
#include "comm.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "event.h"
#include "fatal.h"
#include "SquidConfig.h"

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
    struct in_addr ip_addr;  // WCCP on-the-wire in 32-bit IPv4-only.
    int revision;
    char hash[WCCP_HASH_SIZE];
    int reserved;
};

struct wccp_i_see_you_t {
    int32_t type;
    int32_t version;
    int32_t change;
    int32_t id;
    int32_t number;

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

static Ip::Address local_ip;

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

    if (!Config.Wccp.router.isAnyAddr())
        if (!eventFind(wccpHereIam, NULL))
            eventAdd("wccpHereIam", wccpHereIam, NULL, 5.0, 1);
}

void
wccpConnectionOpen(void)
{
    debugs(80, 5, "wccpConnectionOpen: Called");

    if (Config.Wccp.router.isAnyAddr()) {
        debugs(80, 2, "WCCPv1 disabled.");
        return;
    }

    if ( !Config.Wccp.router.setIPv4() ) {
        debugs(80, DBG_CRITICAL, "WCCPv1 Disabled. Router " << Config.Wccp.router << " is not an IPv4 address.");
        return;
    }

    if ( !Config.Wccp.address.setIPv4() ) {
        debugs(80, DBG_CRITICAL, "WCCPv1 Disabled. Local address " << Config.Wccp.address << " is not an IPv4 address.");
        return;
    }

    Config.Wccp.address.port(WCCP_PORT);
    Config.Wccp.router.port(WCCP_PORT);

    theWccpConnection = comm_open_listener(SOCK_DGRAM,
                                           IPPROTO_UDP,
                                           Config.Wccp.address,
                                           COMM_NONBLOCKING,
                                           "WCCP Socket");

    if (theWccpConnection < 0)
        fatal("Cannot open WCCP Port");

    Comm::SetSelect(theWccpConnection, COMM_SELECT_READ, wccpHandleUdp, NULL, 0);

    debugs(80, DBG_IMPORTANT, "Accepting WCCPv1 messages on " << Config.Wccp.address << ", FD " << theWccpConnection << ".");

    // Sadly WCCP only does IPv4

    struct sockaddr_in router;
    Config.Wccp.router.getSockAddr(router);
    if (connect(theWccpConnection, (struct sockaddr*)&router, sizeof(router)))
        fatal("Unable to connect WCCP out socket");

    struct sockaddr_in local;
    memset(&local, '\0', sizeof(local));
    socklen_t slen = sizeof(local);
    if (getsockname(theWccpConnection, (struct sockaddr*)&local, &slen))
        fatal("Unable to getsockname on WCCP out socket");

    local_ip = local;
}

void
wccpConnectionClose(void)
{
    if (theWccpConnection > -1) {
        debugs(80, DBG_IMPORTANT, "FD " << theWccpConnection << " Closing WCCPv1 socket");
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
wccpHandleUdp(int sock, void *)
{
    Ip::Address from;
    int len;

    debugs(80, 6, "wccpHandleUdp: Called.");

    Comm::SetSelect(sock, COMM_SELECT_READ, wccpHandleUdp, NULL, 0);

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
        debugs(80, DBG_IMPORTANT, "Ignoring WCCP_I_SEE_YOU from " <<
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

    for (loop = 0; loop < (unsigned) ntohl(wccp_i_see_you.number); ++loop) {
        assert(loop < WCCP_ACTIVE_CACHES);

        if (local_ip > wccp_i_see_you.wccp_cache_entry[loop].ip_addr)
            return 0;

        if (local_ip == wccp_i_see_you.wccp_cache_entry[loop].ip_addr)
            found = 1;
    }

    return found;
}

static void
wccpHereIam(void *)
{
    debugs(80, 6, "wccpHereIam: Called");

    wccp_here_i_am.id = last_id;
    double interval = 10.0; // TODO: make this configurable, possibly negotiate with the router.
    ssize_t sent = comm_udp_send(theWccpConnection, &wccp_here_i_am, sizeof(wccp_here_i_am), 0);

    // if we failed to send the whole lot, try again at a shorter interval (20%)
    if (sent != sizeof(wccp_here_i_am)) {
        int xerrno = errno;
        debugs(80, 2, "ERROR: failed to send WCCP HERE_I_AM packet: " << xstrerr(xerrno));
        interval = 2.0;
    }

    if (!eventFind(wccpHereIam, NULL))
        eventAdd("wccpHereIam", wccpHereIam, NULL, interval, 1);
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

    memset(wccp_assign_bucket, '\0', sizeof(*wccp_assign_bucket));

    memset(buckets, 0xFF, WCCP_BUCKETS);

    buckets_per_cache = WCCP_BUCKETS / number_caches;

    for (loop = 0; loop < number_caches; ++loop) {
        int i;
        memcpy(&caches[loop],
               &wccp_i_see_you.wccp_cache_entry[loop].ip_addr,
               sizeof(*caches));

        for (i = 0; i < buckets_per_cache; ++i) {
            assert(bucket < WCCP_BUCKETS);
            buckets[bucket] = loop;
            ++bucket;
        }
    }

    while (bucket < WCCP_BUCKETS) {
        buckets[bucket] = number_caches - 1;
        ++bucket;
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

