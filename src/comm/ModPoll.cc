/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Socket Functions */

#include "squid.h"

#if USE_POLL
#include "anyp/PortCfg.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "ICP.h"
#include "mgr/Registration.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "Store.h"

#include <cerrno>
#if HAVE_POLL_H
#include <poll.h>
#endif

/* Needed for poll() on Linux at least */
#if USE_POLL
#ifndef POLLRDNORM
#define POLLRDNORM POLLIN
#endif
#ifndef POLLWRNORM
#define POLLWRNORM POLLOUT
#endif
#endif

static int MAX_POLL_TIME = 1000;    /* see also Comm::QuickPollRequired() */

#ifndef        howmany
#define howmany(x, y)   (((x)+((y)-1))/(y))
#endif
#ifndef        NBBY
#define        NBBY    8
#endif
#define FD_MASK_BYTES sizeof(fd_mask)
#define FD_MASK_BITS (FD_MASK_BYTES*NBBY)

/* STATIC */
static int fdIsTcpListen(int fd);
static int fdIsUdpListen(int fd);
static int fdIsDns(int fd);
static OBJH commIncomingStats;
static int comm_check_incoming_poll_handlers(int nfds, int *fds);
static void comm_poll_dns_incoming(void);

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
 * The variable 'udp_io_events' and 'tcp_io_events' counts how many normal
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
 * There are separate incoming_interval counters for TCP-based, UDP-based, and DNS events
 *
 * You can see the current values of the incoming_interval's, as well as
 * a histogram of 'incoming_events' by asking the cache manager
 * for 'comm_incoming', e.g.:
 *
 *      % ./client mgr:comm_poll_incoming
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
static int udp_io_events = 0; ///< I/O events passed since last UDP receiver socket poll
static int dns_io_events = 0; ///< I/O events passed since last DNS socket poll
static int tcp_io_events = 0; ///< I/O events passed since last TCP listening socket poll
static int incoming_udp_interval = 16 << INCOMING_FACTOR;
static int incoming_dns_interval = 16 << INCOMING_FACTOR;
static int incoming_tcp_interval = 16 << INCOMING_FACTOR;
#define commCheckUdpIncoming (++udp_io_events > (incoming_udp_interval>> INCOMING_FACTOR))
#define commCheckDnsIncoming (++dns_io_events > (incoming_dns_interval>> INCOMING_FACTOR))
#define commCheckTcpIncoming (++tcp_io_events > (incoming_tcp_interval>> INCOMING_FACTOR))

void
Comm::SetSelect(int fd, unsigned int type, PF * handler, void *client_data, time_t timeout)
{
    fde *F = &fd_table[fd];
    assert(fd >= 0);
    assert(F->flags.open);
    debugs(5, 5, HERE << "FD " << fd << ", type=" << type <<
           ", handler=" << handler << ", client_data=" << client_data <<
           ", timeout=" << timeout);

    if (type & COMM_SELECT_READ) {
        F->read_handler = handler;
        F->read_data = client_data;
    }

    if (type & COMM_SELECT_WRITE) {
        F->write_handler = handler;
        F->write_data = client_data;
    }

    if (timeout)
        F->timeout = squid_curtime + timeout;
}

void
Comm::ResetSelect(int fd)
{
}

static int
fdIsUdpListen(int fd)
{
    if (icpIncomingConn != NULL && icpIncomingConn->fd == fd)
        return 1;

    if (icpOutgoingConn != NULL && icpOutgoingConn->fd == fd)
        return 1;

    return 0;
}

static int
fdIsDns(int fd)
{
    if (fd == DnsSocketA)
        return 1;

    if (fd == DnsSocketB)
        return 1;

    return 0;
}

static int
fdIsTcpListen(int fd)
{
    for (AnyP::PortCfgPointer s = HttpPortList; s != NULL; s = s->next) {
        if (s->listenConn != NULL && s->listenConn->fd == fd)
            return 1;
    }

    return 0;
}

static int
comm_check_incoming_poll_handlers(int nfds, int *fds)
{
    int i;
    int fd;
    PF *hdl = NULL;
    int npfds;

    struct pollfd pfds[3 + MAXTCPLISTENPORTS];
    PROF_start(comm_check_incoming);
    incoming_sockets_accepted = 0;

    for (i = npfds = 0; i < nfds; ++i) {
        int events;
        fd = fds[i];
        events = 0;

        if (fd_table[fd].read_handler)
            events |= POLLRDNORM;

        if (fd_table[fd].write_handler)
            events |= POLLWRNORM;

        if (events) {
            pfds[npfds].fd = fd;
            pfds[npfds].events = events;
            pfds[npfds].revents = 0;
            ++npfds;
        }
    }

    if (!nfds) {
        PROF_stop(comm_check_incoming);
        return -1;
    }

    getCurrentTime();
    ++ statCounter.syscalls.selects;

    if (poll(pfds, npfds, 0) < 1) {
        PROF_stop(comm_check_incoming);
        return incoming_sockets_accepted;
    }

    for (i = 0; i < npfds; ++i) {
        int revents;

        if (((revents = pfds[i].revents) == 0) || ((fd = pfds[i].fd) == -1))
            continue;

        if (revents & (POLLRDNORM | POLLIN | POLLHUP | POLLERR)) {
            if ((hdl = fd_table[fd].read_handler)) {
                fd_table[fd].read_handler = NULL;
                hdl(fd, fd_table[fd].read_data);
            } else if (pfds[i].events & POLLRDNORM)
                debugs(5, DBG_IMPORTANT, "comm_poll_incoming: FD " << fd << " NULL read handler");
        }

        if (revents & (POLLWRNORM | POLLOUT | POLLHUP | POLLERR)) {
            if ((hdl = fd_table[fd].write_handler)) {
                fd_table[fd].write_handler = NULL;
                hdl(fd, fd_table[fd].write_data);
            } else if (pfds[i].events & POLLWRNORM)
                debugs(5, DBG_IMPORTANT, "comm_poll_incoming: FD " << fd << " NULL write_handler");
        }
    }

    PROF_stop(comm_check_incoming);
    return incoming_sockets_accepted;
}

static void
comm_poll_udp_incoming(void)
{
    int nfds = 0;
    int fds[2];
    int nevents;
    udp_io_events = 0;

    if (Comm::IsConnOpen(icpIncomingConn)) {
        fds[nfds] = icpIncomingConn->fd;
        ++nfds;
    }

    if (icpIncomingConn != icpOutgoingConn && Comm::IsConnOpen(icpOutgoingConn)) {
        fds[nfds] = icpOutgoingConn->fd;
        ++nfds;
    }

    if (nfds == 0)
        return;

    nevents = comm_check_incoming_poll_handlers(nfds, fds);

    incoming_udp_interval += Config.comm_incoming.udp.average - nevents;

    if (incoming_udp_interval < Config.comm_incoming.udp.min_poll)
        incoming_udp_interval = Config.comm_incoming.udp.min_poll;

    if (incoming_udp_interval > MAX_INCOMING_INTERVAL)
        incoming_udp_interval = MAX_INCOMING_INTERVAL;

    if (nevents > INCOMING_UDP_MAX)
        nevents = INCOMING_UDP_MAX;

    statCounter.comm_udp_incoming.count(nevents);
}

static void
comm_poll_tcp_incoming(void)
{
    int nfds = 0;
    int fds[MAXTCPLISTENPORTS];
    int j;
    int nevents;
    tcp_io_events = 0;

    // XXX: only poll sockets that won't be deferred. But how do we identify them?

    for (j = 0; j < NHttpSockets; ++j) {
        if (HttpSockets[j] < 0)
            continue;

        fds[nfds] = HttpSockets[j];
        ++nfds;
    }

    nevents = comm_check_incoming_poll_handlers(nfds, fds);
    incoming_tcp_interval = incoming_tcp_interval
                            + Config.comm_incoming.tcp.average - nevents;

    if (incoming_tcp_interval < Config.comm_incoming.tcp.min_poll)
        incoming_tcp_interval = Config.comm_incoming.tcp.min_poll;

    if (incoming_tcp_interval > MAX_INCOMING_INTERVAL)
        incoming_tcp_interval = MAX_INCOMING_INTERVAL;

    if (nevents > INCOMING_TCP_MAX)
        nevents = INCOMING_TCP_MAX;

    statCounter.comm_tcp_incoming.count(nevents);
}

/* poll all sockets; call handlers for those that are ready. */
Comm::Flag
Comm::DoSelect(int msec)
{
    struct pollfd pfds[SQUID_MAXFD];

    PF *hdl = NULL;
    int fd;
    int maxfd;
    unsigned long nfds;
    unsigned long npending;
    int num;
    int calldns = 0, calludp = 0, calltcp = 0;
    double timeout = current_dtime + (msec / 1000.0);

    do {
        double start;
        getCurrentTime();
        start = current_dtime;

        if (commCheckUdpIncoming)
            comm_poll_udp_incoming();

        if (commCheckDnsIncoming)
            comm_poll_dns_incoming();

        if (commCheckTcpIncoming)
            comm_poll_tcp_incoming();

        PROF_start(comm_poll_prep_pfds);

        calldns = calludp = calltcp = 0;

        nfds = 0;

        npending = 0;

        maxfd = Biggest_FD + 1;

        for (int i = 0; i < maxfd; ++i) {
            int events;
            events = 0;
            /* Check each open socket for a handler. */

            if (fd_table[i].read_handler)
                events |= POLLRDNORM;

            if (fd_table[i].write_handler)
                events |= POLLWRNORM;

            if (events) {
                pfds[nfds].fd = i;
                pfds[nfds].events = events;
                pfds[nfds].revents = 0;
                ++nfds;

                if ((events & POLLRDNORM) && fd_table[i].flags.read_pending)
                    ++npending;
            }
        }

        PROF_stop(comm_poll_prep_pfds);

        if (npending)
            msec = 0;

        if (msec > MAX_POLL_TIME)
            msec = MAX_POLL_TIME;

        /* nothing to do
         *
         * Note that this will only ever trigger when there are no log files
         * and stdout/err/in are all closed too.
         */
        if (nfds == 0 && npending == 0) {
            if (shutting_down)
                return Comm::SHUTDOWN;
            else
                return Comm::IDLE;
        }

        for (;;) {
            PROF_start(comm_poll_normal);
            ++ statCounter.syscalls.selects;
            num = poll(pfds, nfds, msec);
            ++ statCounter.select_loops;
            PROF_stop(comm_poll_normal);

            if (num >= 0 || npending > 0)
                break;

            if (ignoreErrno(errno))
                continue;

            debugs(5, DBG_CRITICAL, "comm_poll: poll failure: " << xstrerror());

            assert(errno != EINVAL);

            return Comm::COMM_ERROR;

            /* NOTREACHED */
        }

        getCurrentTime();

        debugs(5, num ? 5 : 8, "comm_poll: " << num << "+" << npending << " FDs ready");
        statCounter.select_fds_hist.count(num);

        if (num == 0 && npending == 0)
            continue;

        /* scan each socket but the accept socket. Poll this
         * more frequently to minimize losses due to the 5 connect
         * limit in SunOS */
        PROF_start(comm_handle_ready_fd);

        for (size_t loopIndex = 0; loopIndex < nfds; ++loopIndex) {
            fde *F;
            int revents = pfds[loopIndex].revents;
            fd = pfds[loopIndex].fd;

            if (fd == -1)
                continue;

            if (fd_table[fd].flags.read_pending)
                revents |= POLLIN;

            if (revents == 0)
                continue;

            if (fdIsUdpListen(fd)) {
                calludp = 1;
                continue;
            }

            if (fdIsDns(fd)) {
                calldns = 1;
                continue;
            }

            if (fdIsTcpListen(fd)) {
                calltcp = 1;
                continue;
            }

            F = &fd_table[fd];

            if (revents & (POLLRDNORM | POLLIN | POLLHUP | POLLERR)) {
                debugs(5, 6, "comm_poll: FD " << fd << " ready for reading");

                if ((hdl = F->read_handler)) {
                    PROF_start(comm_read_handler);
                    F->read_handler = NULL;
                    F->flags.read_pending = false;
                    hdl(fd, F->read_data);
                    PROF_stop(comm_read_handler);
                    ++ statCounter.select_fds;

                    if (commCheckUdpIncoming)
                        comm_poll_udp_incoming();

                    if (commCheckDnsIncoming)
                        comm_poll_dns_incoming();

                    if (commCheckTcpIncoming)
                        comm_poll_tcp_incoming();
                }
            }

            if (revents & (POLLWRNORM | POLLOUT | POLLHUP | POLLERR)) {
                debugs(5, 6, "comm_poll: FD " << fd << " ready for writing");

                if ((hdl = F->write_handler)) {
                    PROF_start(comm_write_handler);
                    F->write_handler = NULL;
                    hdl(fd, F->write_data);
                    PROF_stop(comm_write_handler);
                    ++ statCounter.select_fds;

                    if (commCheckUdpIncoming)
                        comm_poll_udp_incoming();

                    if (commCheckDnsIncoming)
                        comm_poll_dns_incoming();

                    if (commCheckTcpIncoming)
                        comm_poll_tcp_incoming();
                }
            }

            if (revents & POLLNVAL) {
                AsyncCall::Pointer ch;
                debugs(5, DBG_CRITICAL, "WARNING: FD " << fd << " has handlers, but it's invalid.");
                debugs(5, DBG_CRITICAL, "FD " << fd << " is a " << fdTypeStr[F->type]);
                debugs(5, DBG_CRITICAL, "--> " << F->desc);
                debugs(5, DBG_CRITICAL, "tmout:" << F->timeoutHandler << "read:" <<
                       F->read_handler << " write:" << F->write_handler);

                for (ch = F->closeHandler; ch != NULL; ch = ch->Next())
                    debugs(5, DBG_CRITICAL, " close handler: " << ch);

                if (F->closeHandler != NULL) {
                    commCallCloseHandlers(fd);
                } else if (F->timeoutHandler != NULL) {
                    debugs(5, DBG_CRITICAL, "comm_poll: Calling Timeout Handler");
                    ScheduleCallHere(F->timeoutHandler);
                }

                F->closeHandler = NULL;
                F->timeoutHandler = NULL;
                F->read_handler = NULL;
                F->write_handler = NULL;

                if (F->flags.open)
                    fd_close(fd);
            }
        }

        PROF_stop(comm_handle_ready_fd);

        if (calludp)
            comm_poll_udp_incoming();

        if (calldns)
            comm_poll_dns_incoming();

        if (calltcp)
            comm_poll_tcp_incoming();

        getCurrentTime();

        statCounter.select_time += (current_dtime - start);

        return Comm::OK;
    } while (timeout > current_dtime);

    debugs(5, 8, "comm_poll: time out: " << squid_curtime << ".");

    return Comm::TIMEOUT;
}

static void
comm_poll_dns_incoming(void)
{
    int nfds = 0;
    int fds[2];
    int nevents;
    dns_io_events = 0;

    if (DnsSocketA < 0 && DnsSocketB < 0)
        return;

    if (DnsSocketA >= 0) {
        fds[nfds] = DnsSocketA;
        ++nfds;
    }

    if (DnsSocketB >= 0) {
        fds[nfds] = DnsSocketB;
        ++nfds;
    }

    nevents = comm_check_incoming_poll_handlers(nfds, fds);

    if (nevents < 0)
        return;

    incoming_dns_interval += Config.comm_incoming.dns.average - nevents;

    if (incoming_dns_interval < Config.comm_incoming.dns.min_poll)
        incoming_dns_interval = Config.comm_incoming.dns.min_poll;

    if (incoming_dns_interval > MAX_INCOMING_INTERVAL)
        incoming_dns_interval = MAX_INCOMING_INTERVAL;

    if (nevents > INCOMING_DNS_MAX)
        nevents = INCOMING_DNS_MAX;

    statCounter.comm_dns_incoming.count(nevents);
}

static void
commPollRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("comm_poll_incoming",
                        "comm_incoming() stats",
                        commIncomingStats, 0, 1);
}

void
Comm::SelectLoopInit(void)
{
    commPollRegisterWithCacheManager();
}

static void
commIncomingStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "Current incoming_udp_interval: %d\n",
                      incoming_udp_interval >> INCOMING_FACTOR);
    storeAppendPrintf(sentry, "Current incoming_dns_interval: %d\n",
                      incoming_dns_interval >> INCOMING_FACTOR);
    storeAppendPrintf(sentry, "Current incoming_tcp_interval: %d\n",
                      incoming_tcp_interval >> INCOMING_FACTOR);
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "Histogram of events per incoming socket type\n");
    storeAppendPrintf(sentry, "ICP Messages handled per comm_poll_udp_incoming() call:\n");
    statCounter.comm_udp_incoming.dump(sentry, statHistIntDumper);
    storeAppendPrintf(sentry, "DNS Messages handled per comm_poll_dns_incoming() call:\n");
    statCounter.comm_dns_incoming.dump(sentry, statHistIntDumper);
    storeAppendPrintf(sentry, "HTTP Messages handled per comm_poll_tcp_incoming() call:\n");
    statCounter.comm_tcp_incoming.dump(sentry, statHistIntDumper);
}

/* Called by async-io or diskd to speed up the polling */
void
Comm::QuickPollRequired(void)
{
    MAX_POLL_TIME = 10;
}

#endif /* USE_POLL */

