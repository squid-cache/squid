
/*
 * $Id: wccp.cc,v 1.21 2002/04/16 22:43:38 wessels Exp $
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

#if USE_WCCP

#define WCCP_PORT 2048
#define WCCP_REVISION 0
#define WCCP_RESPONSE_SIZE 12448
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
    struct in_addr ip_addr;
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

static int theInWccpConnection = -1;
static int theOutWccpConnection = -1;
static struct wccp_here_i_am_t wccp_here_i_am;
static struct wccp_i_see_you_t wccp_i_see_you;
static int change;
static struct in_addr local_ip;

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
    debug(80, 5) ("wccpInit: Called\n");
    memset(&wccp_here_i_am, '\0', sizeof(wccp_here_i_am));
    wccp_here_i_am.type = htonl(WCCP_HERE_I_AM);
    wccp_here_i_am.version = htonl(Config.Wccp.version);
    wccp_here_i_am.revision = htonl(WCCP_REVISION);
    change = 0;
    if (Config.Wccp.router.s_addr != any_addr.s_addr)
	if (!eventFind(wccpHereIam, NULL))
	    eventAdd("wccpHereIam", wccpHereIam, NULL, 5.0, 1);
}

void
wccpConnectionOpen(void)
{
    u_short port = WCCP_PORT;
    struct sockaddr_in router, local;
    int local_len, router_len;
    debug(80, 5) ("wccpConnectionOpen: Called\n");
    if (Config.Wccp.router.s_addr == any_addr.s_addr) {
	debug(1, 1) ("WCCP Disabled.\n");
	return;
    }
    theInWccpConnection = comm_open(SOCK_DGRAM,
	0,
	Config.Wccp.incoming,
	port,
	COMM_NONBLOCKING,
	"WCCP Socket");
    if (theInWccpConnection < 0)
	fatal("Cannot open WCCP Port");
    commSetSelect(theInWccpConnection,
	COMM_SELECT_READ,
	wccpHandleUdp,
	NULL,
	0);
    debug(1, 1) ("Accepting WCCP messages on port %d, FD %d.\n",
	(int) port, theInWccpConnection);
    if (Config.Wccp.outgoing.s_addr != no_addr.s_addr) {
	theOutWccpConnection = comm_open(SOCK_DGRAM,
	    0,
	    Config.Wccp.outgoing,
	    port,
	    COMM_NONBLOCKING,
	    "WCCP Socket");
	if (theOutWccpConnection < 0)
	    fatal("Cannot open Outgoing WCCP Port");
	commSetSelect(theOutWccpConnection,
	    COMM_SELECT_READ,
	    wccpHandleUdp,
	    NULL, 0);
	debug(1, 1) ("Outgoing WCCP messages on port %d, FD %d.\n",
	    (int) port, theOutWccpConnection);
	fd_note(theOutWccpConnection, "Outgoing WCCP socket");
	fd_note(theInWccpConnection, "Incoming WCCP socket");
    } else {
	theOutWccpConnection = theInWccpConnection;
    }
    router_len = sizeof(router);
    memset(&router, '\0', router_len);
    router.sin_family = AF_INET;
    router.sin_port = htons(port);
    router.sin_addr = Config.Wccp.router;
    if (connect(theOutWccpConnection, (struct sockaddr *) &router, router_len))
	fatal("Unable to connect WCCP out socket");
    local_len = sizeof(local);
    memset(&local, '\0', local_len);
    if (getsockname(theOutWccpConnection, (struct sockaddr *) &local, &local_len))
	fatal("Unable to getsockname on WCCP out socket");
    local_ip.s_addr = local.sin_addr.s_addr;
}

void
wccpConnectionShutdown(void)
{
    if (theInWccpConnection < 0)
	return;
    if (theInWccpConnection != theOutWccpConnection) {
	debug(80, 1) ("FD %d Closing WCCP socket\n", theInWccpConnection);
	comm_close(theInWccpConnection);
    }
    assert(theOutWccpConnection > -1);
    commSetSelect(theOutWccpConnection, COMM_SELECT_READ, NULL, NULL, 0);
}

void
wccpConnectionClose(void)
{
    wccpConnectionShutdown();
    if (theOutWccpConnection > -1) {
	debug(80, 1) ("FD %d Closing WCCP socket\n", theOutWccpConnection);
	comm_close(theOutWccpConnection);
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
    struct sockaddr_in from;
    socklen_t from_len;
    int len;

    debug(80, 6) ("wccpHandleUdp: Called.\n");

    commSetSelect(sock, COMM_SELECT_READ, wccpHandleUdp, NULL, 0);
    from_len = sizeof(struct sockaddr_in);
    memset(&from, '\0', from_len);
    memset(&wccp_i_see_you, '\0', sizeof(wccp_i_see_you));

    statCounter.syscalls.sock.recvfroms++;

    len = recvfrom(sock,
	(void *) &wccp_i_see_you,
	WCCP_RESPONSE_SIZE,
	0,
	(struct sockaddr *) &from,
	&from_len);
    debug(80, 3) ("wccpHandleUdp: %d bytes WCCP pkt from %s: type=%ld, version=%ld, change=%ld, id=%ld, number=%ld\n",
	len,
	inet_ntoa(from.sin_addr),
	ntohl(wccp_i_see_you.type),
	ntohl(wccp_i_see_you.version),
	ntohl(wccp_i_see_you.change),
	ntohl(wccp_i_see_you.id),
	ntohl(wccp_i_see_you.number));
    if (len < 0)
	return;
    if (Config.Wccp.router.s_addr != from.sin_addr.s_addr)
	return;
    if (ntohl(wccp_i_see_you.version) != Config.Wccp.version)
	return;
    if (ntohl(wccp_i_see_you.type) != WCCP_I_SEE_YOU)
	return;
    if (!change) {
	change = wccp_i_see_you.change;
	return;
    }
    if (change != wccp_i_see_you.change) {
	change = wccp_i_see_you.change;
	if (wccpLowestIP() && wccp_i_see_you.number)
	    wccpAssignBuckets();
    }
}

static int
wccpLowestIP(void)
{
    int loop;
    for (loop = 0; loop < ntohl(wccp_i_see_you.number); loop++) {
	if (wccp_i_see_you.wccp_cache_entry[loop].ip_addr.s_addr < local_ip.s_addr)
	    return 0;
    }
    return 1;
}

static void
wccpHereIam(void *voidnotused)
{
    debug(80, 6) ("wccpHereIam: Called\n");

    wccp_here_i_am.id = wccp_i_see_you.id;
    send(theOutWccpConnection,
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
    int loop;
    int number_caches;
    int bucket = 0;
    int *caches;
    int cache_len;
    char *buf;

    debug(80, 6) ("wccpAssignBuckets: Called\n");
    number_caches = ntohl(wccp_i_see_you.number);
    if (number_caches > WCCP_ACTIVE_CACHES)
	number_caches = WCCP_ACTIVE_CACHES;
    wab_len = sizeof(struct wccp_assign_bucket_t);
    cache_len = WCCP_CACHE_LEN * number_caches;

    buf = xmalloc(wab_len +
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
	    &wccp_i_see_you.wccp_cache_entry[loop].ip_addr.s_addr,
	    sizeof(*caches));
	for (i = 0; i < buckets_per_cache; i++) {
	    assert(bucket < WCCP_BUCKETS);
	    buckets[bucket++] = loop;
	}
    }
    wccp_assign_bucket->type = htonl(WCCP_ASSIGN_BUCKET);
    wccp_assign_bucket->id = wccp_i_see_you.id;
    wccp_assign_bucket->number = wccp_i_see_you.number;

    send(theOutWccpConnection,
	buf,
	wab_len + WCCP_BUCKETS + cache_len,
	0);
    change = 0;
    xfree(buf);
}

#endif /* USE_WCCP */
