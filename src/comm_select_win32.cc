
/*
 * $Id: comm_select_win32.cc,v 1.4 2007/04/30 16:56:09 wessels Exp $
 *
 * DEBUG: section 5     Socket Functions
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
#include "comm_select.h"
#include "CacheManager.h"
#include "SquidTime.h"

#ifdef USE_SELECT_WIN32
#include "Store.h"
#include "fde.h"

static int MAX_POLL_TIME = 1000;	/* see also comm_quick_poll_required() */

#ifndef        howmany
#define howmany(x, y)   (((x)+((y)-1))/(y))
#endif
#ifndef        NBBY
#define        NBBY    8
#endif
#define FD_MASK_BYTES sizeof(fd_mask)
#define FD_MASK_BITS (FD_MASK_BYTES*NBBY)

/* STATIC */
static int examine_select(fd_set *, fd_set *);
static int fdIsHttp(int fd);
static int fdIsIcp(int fd);
static int fdIsDns(int fd);
static OBJH commIncomingStats;
static int comm_check_incoming_select_handlers(int nfds, int *fds);
static void comm_select_dns_incoming(void);
static void commUpdateReadBits(int fd, PF * handler);
static void commUpdateWriteBits(int fd, PF * handler);


static struct timeval zero_tv;
static fd_set global_readfds;
static fd_set global_writefds;
static int nreadfds;
static int nwritefds;

/*
 * Automatic tuning for incoming requests:
 *
 * INCOMING sockets are the ICP and HTTP ports.  We need to check these
 * fairly regularly, but how often?  When the load increases, we
 * want to check the incoming sockets more often.  If we have a lot
 * of incoming ICP, then we need to check these sockets more than
 * if we just have HTTP.
 *
 * The variables 'incoming_icp_interval' and 'incoming_http_interval' 
 * determine how many normal I/O events to process before checking
 * incoming sockets again.  Note we store the incoming_interval
 * multipled by a factor of (2^INCOMING_FACTOR) to have some
 * pseudo-floating point precision.
 *
 * The variable 'icp_io_events' and 'http_io_events' counts how many normal
 * I/O events have been processed since the last check on the incoming
 * sockets.  When io_events > incoming_interval, its time to check incoming
 * sockets.
 *
 * Every time we check incoming sockets, we count how many new messages
 * or connections were processed.  This is used to adjust the
 * incoming_interval for the next iteration.  The new incoming_interval
 * is calculated as the current incoming_interval plus what we would
 * like to see as an average number of events minus the number of
 * events just processed.
 *
 *  incoming_interval = incoming_interval + target_average - number_of_events_processed
 *
 * There are separate incoming_interval counters for both HTTP and ICP events
 * 
 * You can see the current values of the incoming_interval's, as well as
 * a histogram of 'incoming_events' by asking the cache manager
 * for 'comm_incoming', e.g.:
 *
 *      % ./client mgr:comm_incoming
 *
 * Caveats:
 *
 *      - We have MAX_INCOMING_INTEGER as a magic upper limit on
 *        incoming_interval for both types of sockets.  At the
 *        largest value the cache will effectively be idling.
 *
 *      - The higher the INCOMING_FACTOR, the slower the algorithm will
 *        respond to load spikes/increases/decreases in demand. A value
 *        between 3 and 8 is recommended.
 */

#define MAX_INCOMING_INTEGER 256
#define INCOMING_FACTOR 5
#define MAX_INCOMING_INTERVAL (MAX_INCOMING_INTEGER << INCOMING_FACTOR)
static int icp_io_events = 0;
static int dns_io_events = 0;
static int http_io_events = 0;
static int incoming_icp_interval = 16 << INCOMING_FACTOR;
static int incoming_dns_interval = 16 << INCOMING_FACTOR;
static int incoming_http_interval = 16 << INCOMING_FACTOR;
#define commCheckICPIncoming (++icp_io_events > (incoming_icp_interval>> INCOMING_FACTOR))
#define commCheckDNSIncoming (++dns_io_events > (incoming_dns_interval>> INCOMING_FACTOR))
#define commCheckHTTPIncoming (++http_io_events > (incoming_http_interval>> INCOMING_FACTOR))

void
commSetSelect(int fd, unsigned int type, PF * handler, void *client_data,
              time_t timeout)
{
    fde *F = &fd_table[fd];
    assert(fd >= 0);
    assert(F->flags.open);
    debugs(5, 5, "commSetSelect: FD " << fd << " type " << type);

    if (type & COMM_SELECT_READ) {
        F->read_handler = handler;
        F->read_data = client_data;
        commUpdateReadBits(fd, handler);
    }

    if (type & COMM_SELECT_WRITE) {
        F->write_handler = handler;
        F->write_data = client_data;
        commUpdateWriteBits(fd, handler);
    }

    if (timeout)
        F->timeout = squid_curtime + timeout;
}


static int
fdIsIcp(int fd)
{
    if (fd == theInIcpConnection)
        return 1;

    if (fd == theOutIcpConnection)
        return 1;

    return 0;
}

static int
fdIsDns(int fd)
{
    if (fd == DnsSocket)
        return 1;

    return 0;
}

static int
fdIsHttp(int fd)
{
    int j;

    for (j = 0; j < NHttpSockets; j++) {
        if (fd == HttpSockets[j])
            return 1;
    }

    return 0;
}

#if DELAY_POOLS
static int slowfdcnt = 0;
static int slowfdarr[SQUID_MAXFD];

static void
commAddSlowFd(int fd)
{
    assert(slowfdcnt < SQUID_MAXFD);
    slowfdarr[slowfdcnt++] = fd;
}

static int
commGetSlowFd(void)
{
    int whichfd, retfd;

    if (!slowfdcnt)
        return -1;

    whichfd = squid_random() % slowfdcnt;

    retfd = slowfdarr[whichfd];

    slowfdarr[whichfd] = slowfdarr[--slowfdcnt];

    return retfd;
}

#endif

static int
comm_check_incoming_select_handlers(int nfds, int *fds)
{
    int i;
    int fd;
    int maxfd = 0;
    PF *hdl = NULL;
    fd_set read_mask;
    fd_set write_mask;
    fd_set errfds;
    FD_ZERO(&errfds);
    FD_ZERO(&read_mask);
    FD_ZERO(&write_mask);
    incoming_sockets_accepted = 0;

    for (i = 0; i < nfds; i++) {
        fd = fds[i];

        if (fd_table[fd].read_handler) {
            FD_SET(fd, &read_mask);

            if (fd > maxfd)
                maxfd = fd;
        }

        if (fd_table[fd].write_handler) {
            FD_SET(fd, &write_mask);

            if (fd > maxfd)
                maxfd = fd;
        }
    }

    if (maxfd++ == 0)
        return -1;

    getCurrentTime();

    statCounter.syscalls.selects++;

    if (select(maxfd, &read_mask, &write_mask, &errfds, &zero_tv) < 1)

        return incoming_sockets_accepted;

    for (i = 0; i < nfds; i++) {
        fd = fds[i];

        if (FD_ISSET(fd, &read_mask)) {
            if ((hdl = fd_table[fd].read_handler) != NULL) {
                fd_table[fd].read_handler = NULL;
                commUpdateReadBits(fd, NULL);
                hdl(fd, fd_table[fd].read_data);
            } else {
                debugs(5, 1, "comm_select_incoming: FD " << fd << " NULL read handler");
            }
        }

        if (FD_ISSET(fd, &write_mask)) {
            if ((hdl = fd_table[fd].write_handler) != NULL) {
                fd_table[fd].write_handler = NULL;
                commUpdateWriteBits(fd, NULL);
                hdl(fd, fd_table[fd].write_data);
            } else {
                debugs(5, 1, "comm_select_incoming: FD " << fd << " NULL write handler");
            }
        }
    }

    return incoming_sockets_accepted;
}

static void
comm_select_icp_incoming(void)
{
    int nfds = 0;
    int fds[2];
    int nevents;
    icp_io_events = 0;

    if (theInIcpConnection >= 0)
        fds[nfds++] = theInIcpConnection;

    if (theInIcpConnection != theOutIcpConnection)
        if (theOutIcpConnection >= 0)
            fds[nfds++] = theOutIcpConnection;

    if (nfds == 0)
        return;

    nevents = comm_check_incoming_select_handlers(nfds, fds);

    incoming_icp_interval += Config.comm_incoming.icp_average - nevents;

    if (incoming_icp_interval < 0)
        incoming_icp_interval = 0;

    if (incoming_icp_interval > MAX_INCOMING_INTERVAL)
        incoming_icp_interval = MAX_INCOMING_INTERVAL;

    if (nevents > INCOMING_ICP_MAX)
        nevents = INCOMING_ICP_MAX;

    statHistCount(&statCounter.comm_icp_incoming, nevents);
}

static void
comm_select_http_incoming(void)
{
    int nfds = 0;
    int fds[MAXHTTPPORTS];
    int j;
    int nevents;
    http_io_events = 0;

    for (j = 0; j < NHttpSockets; j++) {
        if (HttpSockets[j] < 0)
            continue;

        fds[nfds++] = HttpSockets[j];
    }

    nevents = comm_check_incoming_select_handlers(nfds, fds);
    incoming_http_interval += Config.comm_incoming.http_average - nevents;

    if (incoming_http_interval < 0)
        incoming_http_interval = 0;

    if (incoming_http_interval > MAX_INCOMING_INTERVAL)
        incoming_http_interval = MAX_INCOMING_INTERVAL;

    if (nevents > INCOMING_HTTP_MAX)
        nevents = INCOMING_HTTP_MAX;

    statHistCount(&statCounter.comm_http_incoming, nevents);
}

#define DEBUG_FDBITS 0
/* Select on all sockets; call handlers for those that are ready. */
comm_err_t
comm_select(int msec)
{
    fd_set readfds;
    fd_set pendingfds;
    fd_set writefds;
#if DELAY_POOLS

    fd_set slowfds;
#endif

    PF *hdl = NULL;
    int fd;
    int maxfd;
    int num;
    int pending;
    int callicp = 0, callhttp = 0;
    int calldns = 0;
    int j;
#if DEBUG_FDBITS

    int i;
#endif
    struct timeval poll_time;
    double timeout = current_dtime + (msec / 1000.0);
    fde *F;

    int no_bits;
    fd_set errfds;
    FD_ZERO(&errfds);

    do {
        double start;
        getCurrentTime();
        start = current_dtime;
#if DELAY_POOLS

        FD_ZERO(&slowfds);
#endif

        if (commCheckICPIncoming)
            comm_select_icp_incoming();

        if (commCheckDNSIncoming)
            comm_select_dns_incoming();

        if (commCheckHTTPIncoming)
            comm_select_http_incoming();

        callicp = calldns = callhttp = 0;

        maxfd = Biggest_FD + 1;

        xmemcpy(&readfds, &global_readfds, sizeof(global_readfds));

        xmemcpy(&writefds, &global_writefds, sizeof(global_writefds));

        xmemcpy(&errfds, &global_writefds, sizeof(global_writefds));

        /* remove stalled FDs, and deal with pending descriptors */
        pending = 0;

        FD_ZERO(&pendingfds);

        for (j = 0; j < (int) readfds.fd_count; j++) {
            register int readfds_handle = readfds.fd_array[j];
            no_bits = 1;

            for ( fd = Biggest_FD; fd; fd-- ) {
                if ( fd_table[fd].win32.handle == readfds_handle ) {
                    if (fd_table[fd].flags.open) {
                        no_bits = 0;
                        break;
                    }
                }
            }

            if (no_bits)
                continue;

            if (FD_ISSET(fd, &readfds) && fd_table[fd].flags.read_pending) {
                FD_SET(fd, &pendingfds);
                pending++;
            }
        }

#if DEBUG_FDBITS
        for (i = 0; i < maxfd; i++) {
            /* Check each open socket for a handler. */

            if (fd_table[i].read_handler) {
                assert(FD_ISSET(i, &readfds));
            }

            if (fd_table[i].write_handler) {
                assert(FD_ISSET(i, &writefds));
            }
        }

#endif
        if (nreadfds + nwritefds == 0) {
            assert(shutting_down);
            return COMM_SHUTDOWN;
        }

        if (msec > MAX_POLL_TIME)
            msec = MAX_POLL_TIME;

        if (comm_iocallbackpending())
            pending++;

        if (pending)
            msec = 0;

        for (;;) {
            poll_time.tv_sec = msec / 1000;
            poll_time.tv_usec = (msec % 1000) * 1000;
            statCounter.syscalls.selects++;
            num = select(maxfd, &readfds, &writefds, &errfds, &poll_time);
            statCounter.select_loops++;

            if (num >= 0 || pending > 0)
                break;

            if (ignoreErrno(errno))
                break;

            debugs(5, 0, "comm_select: select failure: " << xstrerror());

            examine_select(&readfds, &writefds);

            return COMM_ERROR;

            /* NOTREACHED */
        }

        if (num < 0 && !pending)
            continue;

        getCurrentTime();

        debugs(5, num ? 5 : 8, "comm_select: " << num << "+" << pending << " FDs ready\n");

        statHistCount(&statCounter.select_fds_hist, num);

        if (num == 0 && pending == 0)
            continue;

        /* Scan return fd masks for ready descriptors */

        assert(readfds.fd_count <= (unsigned int) Biggest_FD);

        assert(pendingfds.fd_count <= (unsigned int) Biggest_FD);

        for (j = 0; j < (int) readfds.fd_count; j++) {
            register int readfds_handle = readfds.fd_array[j];
            register int pendingfds_handle = pendingfds.fd_array[j];
            register int osfhandle;
            no_bits = 1;

            for ( fd = Biggest_FD; fd; fd-- ) {
                osfhandle = fd_table[fd].win32.handle;

                if (( osfhandle == readfds_handle ) ||
                        ( osfhandle == pendingfds_handle )) {
                    if (fd_table[fd].flags.open) {
                        no_bits = 0;
                        break;
                    }
                }
            }

            if (no_bits)
                continue;

#if DEBUG_FDBITS

            debugs(5, 9, "FD " << fd << " bit set for reading");

            assert(FD_ISSET(fd, &readfds));

#endif

            if (fdIsIcp(fd)) {
                callicp = 1;
                continue;
            }

            if (fdIsDns(fd)) {
                calldns = 1;
                continue;
            }

            if (fdIsHttp(fd)) {
                callhttp = 1;
                continue;
            }

            F = &fd_table[fd];
            debugs(5, 6, "comm_select: FD " << fd << " ready for reading");

            if (NULL == (hdl = F->read_handler))
                (void) 0;

#if DELAY_POOLS

            else if (FD_ISSET(fd, &slowfds))
                commAddSlowFd(fd);

#endif

            else {
                F->read_handler = NULL;
                commUpdateReadBits(fd, NULL);
                hdl(fd, F->read_data);
                statCounter.select_fds++;

                if (commCheckICPIncoming)
                    comm_select_icp_incoming();

                if (commCheckDNSIncoming)
                    comm_select_dns_incoming();

                if (commCheckHTTPIncoming)
                    comm_select_http_incoming();
            }
        }

        assert(errfds.fd_count <= (unsigned int) Biggest_FD);

        for (j = 0; j < (int) errfds.fd_count; j++) {
            register int errfds_handle = errfds.fd_array[j];

            for ( fd = Biggest_FD; fd; fd-- ) {
                if ( fd_table[fd].win32.handle == errfds_handle )
                    break;
            }

            if (fd_table[fd].flags.open) {
                F = &fd_table[fd];

                if ((hdl = F->write_handler)) {
                    F->write_handler = NULL;
                    commUpdateWriteBits(fd, NULL);
                    hdl(fd, F->write_data);
                    statCounter.select_fds++;
                }
            }
        }

        assert(writefds.fd_count <= (unsigned int) Biggest_FD);

        for (j = 0; j < (int) writefds.fd_count; j++) {
            register int writefds_handle = writefds.fd_array[j];
            no_bits = 1;

            for ( fd = Biggest_FD; fd; fd-- ) {
                if ( fd_table[fd].win32.handle == writefds_handle ) {
                    if (fd_table[fd].flags.open) {
                        no_bits = 0;
                        break;
                    }
                }
            }

            if (no_bits)
                continue;

#if DEBUG_FDBITS

            debugs(5, 9, "FD " << fd << " bit set for writing");

            assert(FD_ISSET(fd, &writefds));

#endif

            if (fdIsIcp(fd)) {
                callicp = 1;
                continue;
            }

            if (fdIsDns(fd)) {
                calldns = 1;
                continue;
            }

            if (fdIsHttp(fd)) {
                callhttp = 1;
                continue;
            }

            F = &fd_table[fd];
            debugs(5, 5, "comm_select: FD " << fd << " ready for writing");

            if ((hdl = F->write_handler)) {
                F->write_handler = NULL;
                commUpdateWriteBits(fd, NULL);
                hdl(fd, F->write_data);
                statCounter.select_fds++;

                if (commCheckICPIncoming)
                    comm_select_icp_incoming();

                if (commCheckDNSIncoming)
                    comm_select_dns_incoming();

                if (commCheckHTTPIncoming)
                    comm_select_http_incoming();


            }
        }

        if (callicp)
            comm_select_icp_incoming();

        if (calldns)
            comm_select_dns_incoming();

        if (callhttp)
            comm_select_http_incoming();

#if DELAY_POOLS

        while ((fd = commGetSlowFd()) != -1) {
            F = &fd_table[fd];
            debugs(5, 6, "comm_select: slow FD " << fd << " selected for reading");

            if ((hdl = F->read_handler)) {
                F->read_handler = NULL;
                commUpdateReadBits(fd, NULL);
                hdl(fd, F->read_data);
                statCounter.select_fds++;

                if (commCheckICPIncoming)
                    comm_select_icp_incoming();

                if (commCheckDNSIncoming)
                    comm_select_dns_incoming();

                if (commCheckHTTPIncoming)
                    comm_select_http_incoming();
            }
        }

#endif
        getCurrentTime();

        statCounter.select_time += (current_dtime - start);

        return COMM_OK;
    } while (timeout > current_dtime)

        ;
    debugs(5, 8, "comm_select: time out: " << squid_curtime);

    return COMM_TIMEOUT;
}

static void
comm_select_dns_incoming(void)
{
    int nfds = 0;
    int fds[2];
    int nevents;
    dns_io_events = 0;

    if (DnsSocket < 0)
        return;

    fds[nfds++] = DnsSocket;

    nevents = comm_check_incoming_select_handlers(nfds, fds);

    if (nevents < 0)
        return;

    incoming_dns_interval += Config.comm_incoming.dns_average - nevents;

    if (incoming_dns_interval < Config.comm_incoming.dns_min_poll)
        incoming_dns_interval = Config.comm_incoming.dns_min_poll;

    if (incoming_dns_interval > MAX_INCOMING_INTERVAL)
        incoming_dns_interval = MAX_INCOMING_INTERVAL;

    if (nevents > INCOMING_DNS_MAX)
        nevents = INCOMING_DNS_MAX;

    statHistCount(&statCounter.comm_dns_incoming, nevents);
}

void
comm_select_init(void)
{
    zero_tv.tv_sec = 0;
    zero_tv.tv_usec = 0;
    FD_ZERO(&global_readfds);
    FD_ZERO(&global_writefds);
    nreadfds = nwritefds = 0;
}

void
commSelectRegisterWithCacheManager(CacheManager & manager)
{
    manager.registerAction("comm_select_incoming",
                           "comm_incoming() stats",
                           commIncomingStats, 0, 1);
}

/*
 * examine_select - debug routine.
 *
 * I spend the day chasing this core dump that occurs when both the client
 * and the server side of a cache fetch simultaneoulsy abort the
 * connection.  While I haven't really studied the code to figure out how
 * it happens, the snippet below may prevent the cache from exitting:
 * 
 * Call this from where the select loop fails.
 */
static int
examine_select(fd_set * readfds, fd_set * writefds)
{
    int fd = 0;
    fd_set read_x;
    fd_set write_x;

    struct timeval tv;
    close_handler *ch = NULL;
    fde *F = NULL;

    struct stat sb;
    debugs(5, 0, "examine_select: Examining open file descriptors...");

    for (fd = 0; fd < Squid_MaxFD; fd++) {
        FD_ZERO(&read_x);
        FD_ZERO(&write_x);
        tv.tv_sec = tv.tv_usec = 0;

        if (FD_ISSET(fd, readfds))
            FD_SET(fd, &read_x);
        else if (FD_ISSET(fd, writefds))
            FD_SET(fd, &write_x);
        else
            continue;

        statCounter.syscalls.selects++;

        errno = 0;

        if (!fstat(fd, &sb)) {
            debugs(5, 5, "FD " << fd << " is valid.");
            continue;
        }

        F = &fd_table[fd];
        debugs(5, 0, "FD " << fd << ": " << xstrerror());
        debugs(5, 0, "WARNING: FD " << fd << " has handlers, but it's invalid.");
        debugs(5, 0, "FD " << fd << " is a " << fdTypeStr[F->type] << " called '" << F->desc << "'");
        debugs(5, 0, "tmout:" << F->timeout_handler << " read:" << F->read_handler << " write:" << F->write_handler);

        for (ch = F->closeHandler; ch; ch = ch->next)
            debugs(5, 0, " close handler: " << ch->handler);

        if (F->closeHandler) {
            commCallCloseHandlers(fd);
        } else if (F->timeout_handler) {
            debugs(5, 0, "examine_select: Calling Timeout Handler");
            F->timeout_handler(fd, F->timeout_data);
        }

        F->closeHandler = NULL;
        F->timeout_handler = NULL;
        F->read_handler = NULL;
        F->write_handler = NULL;
        FD_CLR(fd, readfds);
        FD_CLR(fd, writefds);
    }

    return 0;
}


static void
commIncomingStats(StoreEntry * sentry)
{
    StatCounters *f = &statCounter;
    storeAppendPrintf(sentry, "Current incoming_icp_interval: %d\n",
                      incoming_icp_interval >> INCOMING_FACTOR);
    storeAppendPrintf(sentry, "Current incoming_dns_interval: %d\n",
                      incoming_dns_interval >> INCOMING_FACTOR);
    storeAppendPrintf(sentry, "Current incoming_http_interval: %d\n",
                      incoming_http_interval >> INCOMING_FACTOR);
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "Histogram of events per incoming socket type\n");
    storeAppendPrintf(sentry, "ICP Messages handled per comm_select_icp_incoming() call:\n");
    statHistDump(&f->comm_icp_incoming, sentry, statHistIntDumper);
    storeAppendPrintf(sentry, "DNS Messages handled per comm_select_dns_incoming() call:\n");
    statHistDump(&f->comm_dns_incoming, sentry, statHistIntDumper);
    storeAppendPrintf(sentry, "HTTP Messages handled per comm_select_http_incoming() call:\n");
    statHistDump(&f->comm_http_incoming, sentry, statHistIntDumper);
}

void
commUpdateReadBits(int fd, PF * handler)
{
    if (handler && !FD_ISSET(fd, &global_readfds)) {
        FD_SET(fd, &global_readfds);
        nreadfds++;
    } else if (!handler && FD_ISSET(fd, &global_readfds)) {
        FD_CLR(fd, &global_readfds);
        nreadfds--;
    }
}

void
commUpdateWriteBits(int fd, PF * handler)
{
    if (handler && !FD_ISSET(fd, &global_writefds)) {
        FD_SET(fd, &global_writefds);
        nwritefds++;
    } else if (!handler && FD_ISSET(fd, &global_writefds)) {
        FD_CLR(fd, &global_writefds);
        nwritefds--;
    }
}

/* Called by async-io or diskd to speed up the polling */
void
comm_quick_poll_required(void)
{
    MAX_POLL_TIME = 10;
}

#endif /* USE_SELECT_WIN32 */
