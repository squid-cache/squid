/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Socket Functions */

#include "squid.h"

#if USE_SELECT_WIN32
#include "anyp/PortCfg.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "fde.h"
#include "ICP.h"
#include "mgr/Registration.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "StatHist.h"
#include "Store.h"

#include <cerrno>

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
static int examine_select(fd_set *, fd_set *);
static int fdIsTcpListener(int fd);
static int fdIsUdpListener(int fd);
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
 * The variables 'incoming_udp_interval' and 'incoming_tcp_interval'
 * determine how many normal I/O events to process before checking
 * incoming sockets again.  Note we store the incoming_interval
 * multiplied by a factor of (2^INCOMING_FACTOR) to have some
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
 * There are separate incoming_interval counters for DNS, UDP and TCP events
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
static int udp_io_events = 0;
static int dns_io_events = 0;
static int tcp_io_events = 0;
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
    assert(F->flags.open || (!handler && !client_data && !timeout));
    debugs(5, 5, HERE << "FD " << fd << ", type=" << type <<
           ", handler=" << handler << ", client_data=" << client_data <<
           ", timeout=" << timeout);

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
fdIsUdpListener(int fd)
{
    if (icpIncomingConn != NULL && fd == icpIncomingConn->fd)
        return 1;

    if (icpOutgoingConn != NULL && fd == icpOutgoingConn->fd)
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
fdIsTcpListener(int fd)
{
    for (AnyP::PortCfgPointer s = HttpPortList; s != NULL; s = s->next) {
        if (s->listenConn != NULL && s->listenConn->fd == fd)
            return 1;
    }

    return 0;
}

static int
comm_check_incoming_select_handlers(int nfds, int *fds)
{
    int i;
    int fd;
    int maxfd = 0;
    PF *hdl = NULL;
    fd_set read_mask;
    fd_set write_mask;
    FD_ZERO(&read_mask);
    FD_ZERO(&write_mask);
    incoming_sockets_accepted = 0;

    for (i = 0; i < nfds; ++i) {
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

    ++ statCounter.syscalls.selects;

    if (select(maxfd, &read_mask, &write_mask, NULL, &zero_tv) < 1)
        return incoming_sockets_accepted;

    for (i = 0; i < nfds; ++i) {
        fd = fds[i];

        if (FD_ISSET(fd, &read_mask)) {
            if ((hdl = fd_table[fd].read_handler) != NULL) {
                fd_table[fd].read_handler = NULL;
                commUpdateReadBits(fd, NULL);
                hdl(fd, fd_table[fd].read_data);
            } else {
                debugs(5, DBG_IMPORTANT, "comm_select_incoming: FD " << fd << " NULL read handler");
            }
        }

        if (FD_ISSET(fd, &write_mask)) {
            if ((hdl = fd_table[fd].write_handler) != NULL) {
                fd_table[fd].write_handler = NULL;
                commUpdateWriteBits(fd, NULL);
                hdl(fd, fd_table[fd].write_data);
            } else {
                debugs(5, DBG_IMPORTANT, "comm_select_incoming: FD " << fd << " NULL write handler");
            }
        }
    }

    return incoming_sockets_accepted;
}

static void
comm_select_udp_incoming(void)
{
    int nfds = 0;
    int fds[2];
    int nevents;
    udp_io_events = 0;

    if (Comm::IsConnOpen(icpIncomingConn)) {
        fds[nfds] = icpIncomingConn->fd;
        ++nfds;
    }

    if (Comm::IsConnOpen(icpOutgoingConn) && icpIncomingConn != icpOutgoingConn) {
        fds[nfds] = icpOutgoingConn->fd;
        ++nfds;
    }

    if (nfds == 0)
        return;

    nevents = comm_check_incoming_select_handlers(nfds, fds);

    incoming_udp_interval += Config.comm_incoming.udp.average - nevents;

    if (incoming_udp_interval < 0)
        incoming_udp_interval = 0;

    if (incoming_udp_interval > MAX_INCOMING_INTERVAL)
        incoming_udp_interval = MAX_INCOMING_INTERVAL;

    if (nevents > INCOMING_UDP_MAX)
        nevents = INCOMING_UDP_MAX;

    statCounter.comm_udp_incoming.count(nevents);
}

static void
comm_select_tcp_incoming(void)
{
    int nfds = 0;
    int fds[MAXTCPLISTENPORTS];
    int nevents;
    tcp_io_events = 0;

    // XXX: only poll sockets that won't be deferred. But how do we identify them?

    for (AnyP::PortCfgPointer s = HttpPortList; s != NULL; s = s->next) {
        if (Comm::IsConnOpen(s->listenConn)) {
            fds[nfds] = s->listenConn->fd;
            ++nfds;
        }
    }

    nevents = comm_check_incoming_select_handlers(nfds, fds);
    incoming_tcp_interval += Config.comm_incoming.tcp.average - nevents;

    if (incoming_tcp_interval < 0)
        incoming_tcp_interval = 0;

    if (incoming_tcp_interval > MAX_INCOMING_INTERVAL)
        incoming_tcp_interval = MAX_INCOMING_INTERVAL;

    if (nevents > INCOMING_TCP_MAX)
        nevents = INCOMING_TCP_MAX;

    statCounter.comm_tcp_incoming.count(nevents);
}

#define DEBUG_FDBITS 0
/* Select on all sockets; call handlers for those that are ready. */
Comm::Flag
Comm::DoSelect(int msec)
{
    fd_set readfds;
    fd_set pendingfds;
    fd_set writefds;

    PF *hdl = NULL;
    int fd;
    int maxfd;
    int num;
    int pending;
    int calldns = 0, calludp = 0, calltcp = 0;
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

        if (commCheckUdpIncoming)
            comm_select_udp_incoming();

        if (commCheckDnsIncoming)
            comm_select_dns_incoming();

        if (commCheckTcpIncoming)
            comm_select_tcp_incoming();

        calldns = calludp = calltcp = 0;

        maxfd = Biggest_FD + 1;

        memcpy(&readfds, &global_readfds, sizeof(global_readfds));

        memcpy(&writefds, &global_writefds, sizeof(global_writefds));

        memcpy(&errfds, &global_writefds, sizeof(global_writefds));

        /* remove stalled FDs, and deal with pending descriptors */
        pending = 0;

        FD_ZERO(&pendingfds);

        for (j = 0; j < (int) readfds.fd_count; ++j) {
            register int readfds_handle = readfds.fd_array[j];
            no_bits = 1;

            for ( fd = Biggest_FD; fd; --fd ) {
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
                ++pending;
            }
        }

#if DEBUG_FDBITS
        for (i = 0; i < maxfd; ++i) {
            /* Check each open socket for a handler. */

            if (fd_table[i].read_handler) {
                assert(FD_ISSET(i, readfds));
            }

            if (fd_table[i].write_handler) {
                assert(FD_ISSET(i, writefds));
            }
        }

#endif
        if (nreadfds + nwritefds == 0) {
            assert(shutting_down);
            return Comm::SHUTDOWN;
        }

        if (msec > MAX_POLL_TIME)
            msec = MAX_POLL_TIME;

        if (pending)
            msec = 0;

        for (;;) {
            poll_time.tv_sec = msec / 1000;
            poll_time.tv_usec = (msec % 1000) * 1000;
            ++ statCounter.syscalls.selects;
            num = select(maxfd, &readfds, &writefds, &errfds, &poll_time);
            int xerrno = errno;
            ++ statCounter.select_loops;

            if (num >= 0 || pending > 0)
                break;

            if (ignoreErrno(xerrno))
                break;

            debugs(5, DBG_CRITICAL, MYNAME << "WARNING: select failure: " << xstrerr(xerrno));

            examine_select(&readfds, &writefds);

            return Comm::COMM_ERROR;

            /* NOTREACHED */
        }

        if (num < 0 && !pending)
            continue;

        getCurrentTime();

        debugs(5, num ? 5 : 8, "comm_select: " << num << "+" << pending << " FDs ready");

        statCounter.select_fds_hist.count(num);

        if (num == 0 && pending == 0)
            continue;

        /* Scan return fd masks for ready descriptors */
        assert(readfds.fd_count <= (unsigned int) Biggest_FD);
        assert(pendingfds.fd_count <= (unsigned int) Biggest_FD);

        for (j = 0; j < (int) readfds.fd_count; ++j) {
            register int readfds_handle = readfds.fd_array[j];
            register int pendingfds_handle = pendingfds.fd_array[j];
            register int osfhandle;
            no_bits = 1;

            for ( fd = Biggest_FD; fd; --fd ) {
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

            assert(FD_ISSET(fd, readfds));

#endif

            if (fdIsUdpListener(fd)) {
                calludp = 1;
                continue;
            }

            if (fdIsDns(fd)) {
                calldns = 1;
                continue;
            }

            if (fdIsTcpListener(fd)) {
                calltcp = 1;
                continue;
            }

            F = &fd_table[fd];
            debugs(5, 6, "comm_select: FD " << fd << " ready for reading");

            if ((hdl = F->read_handler)) {
                F->read_handler = NULL;
                commUpdateReadBits(fd, NULL);
                hdl(fd, F->read_data);
                ++ statCounter.select_fds;

                if (commCheckUdpIncoming)
                    comm_select_udp_incoming();

                if (commCheckDnsIncoming)
                    comm_select_dns_incoming();

                if (commCheckTcpIncoming)
                    comm_select_tcp_incoming();
            }
        }

        assert(errfds.fd_count <= (unsigned int) Biggest_FD);

        for (j = 0; j < (int) errfds.fd_count; ++j) {
            register int errfds_handle = errfds.fd_array[j];

            for ( fd = Biggest_FD; fd; --fd ) {
                if ( fd_table[fd].win32.handle == errfds_handle )
                    break;
            }

            if (fd_table[fd].flags.open) {
                F = &fd_table[fd];

                if ((hdl = F->write_handler)) {
                    F->write_handler = NULL;
                    commUpdateWriteBits(fd, NULL);
                    hdl(fd, F->write_data);
                    ++ statCounter.select_fds;
                }
            }
        }

        assert(writefds.fd_count <= (unsigned int) Biggest_FD);

        for (j = 0; j < (int) writefds.fd_count; ++j) {
            register int writefds_handle = writefds.fd_array[j];
            no_bits = 1;

            for ( fd = Biggest_FD; fd; --fd ) {
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

            assert(FD_ISSET(fd, writefds));

#endif

            if (fdIsUdpListener(fd)) {
                calludp = 1;
                continue;
            }

            if (fdIsDns(fd)) {
                calldns = 1;
                continue;
            }

            if (fdIsTcpListener(fd)) {
                calltcp = 1;
                continue;
            }

            F = &fd_table[fd];
            debugs(5, 6, "comm_select: FD " << fd << " ready for writing");

            if ((hdl = F->write_handler)) {
                F->write_handler = NULL;
                commUpdateWriteBits(fd, NULL);
                hdl(fd, F->write_data);
                ++ statCounter.select_fds;

                if (commCheckUdpIncoming)
                    comm_select_udp_incoming();

                if (commCheckDnsIncoming)
                    comm_select_dns_incoming();

                if (commCheckTcpIncoming)
                    comm_select_tcp_incoming();
            }
        }

        if (calludp)
            comm_select_udp_incoming();

        if (calldns)
            comm_select_dns_incoming();

        if (calltcp)
            comm_select_tcp_incoming();

        getCurrentTime();

        statCounter.select_time += (current_dtime - start);

        return Comm::OK;
    } while (timeout > current_dtime);
    debugs(5, 8, "comm_select: time out: " << squid_curtime);

    return Comm::TIMEOUT;
}

static void
comm_select_dns_incoming(void)
{
    int nfds = 0;
    int fds[3];
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

    nevents = comm_check_incoming_select_handlers(nfds, fds);

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

void
Comm::SelectLoopInit(void)
{
    zero_tv.tv_sec = 0;
    zero_tv.tv_usec = 0;
    FD_ZERO(&global_readfds);
    FD_ZERO(&global_writefds);
    nreadfds = nwritefds = 0;

    Mgr::RegisterAction("comm_select_incoming",
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
    AsyncCall::Pointer ch = NULL;
    fde *F = NULL;

    struct stat sb;
    debugs(5, DBG_CRITICAL, "examine_select: Examining open file descriptors...");

    for (fd = 0; fd < Squid_MaxFD; ++fd) {
        FD_ZERO(&read_x);
        FD_ZERO(&write_x);
        tv.tv_sec = tv.tv_usec = 0;

        if (FD_ISSET(fd, readfds))
            FD_SET(fd, &read_x);
        else if (FD_ISSET(fd, writefds))
            FD_SET(fd, &write_x);
        else
            continue;

        ++ statCounter.syscalls.selects;
        errno = 0;

        if (!fstat(fd, &sb)) {
            debugs(5, 5, "FD " << fd << " is valid.");
            continue;
        }
        int xerrno = errno;

        F = &fd_table[fd];
        debugs(5, DBG_CRITICAL, "fstat(FD " << fd << "): " << xstrerr(xerrno));
        debugs(5, DBG_CRITICAL, "WARNING: FD " << fd << " has handlers, but it's invalid.");
        debugs(5, DBG_CRITICAL, "FD " << fd << " is a " << fdTypeStr[F->type] << " called '" << F->desc << "'");
        debugs(5, DBG_CRITICAL, "tmout:" << F->timeoutHandler << " read:" << F->read_handler << " write:" << F->write_handler);

        for (ch = F->closeHandler; ch != NULL; ch = ch->Next())
            debugs(5, DBG_CRITICAL, " close handler: " << ch);

        if (F->closeHandler != NULL) {
            commCallCloseHandlers(fd);
        } else if (F->timeoutHandler != NULL) {
            debugs(5, DBG_CRITICAL, "examine_select: Calling Timeout Handler");
            ScheduleCallHere(F->timeoutHandler);
        }

        F->closeHandler = NULL;
        F->timeoutHandler = NULL;
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
    storeAppendPrintf(sentry, "Current incoming_udp_interval: %d\n",
                      incoming_udp_interval >> INCOMING_FACTOR);
    storeAppendPrintf(sentry, "Current incoming_dns_interval: %d\n",
                      incoming_dns_interval >> INCOMING_FACTOR);
    storeAppendPrintf(sentry, "Current incoming_tcp_interval: %d\n",
                      incoming_tcp_interval >> INCOMING_FACTOR);
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "Histogram of events per incoming socket type\n");
    storeAppendPrintf(sentry, "ICP Messages handled per comm_select_udp_incoming() call:\n");
    statCounter.comm_udp_incoming.dump(sentry, statHistIntDumper);
    storeAppendPrintf(sentry, "DNS Messages handled per comm_select_dns_incoming() call:\n");
    statCounter.comm_dns_incoming.dump(sentry, statHistIntDumper);
    storeAppendPrintf(sentry, "HTTP Messages handled per comm_select_tcp_incoming() call:\n");
    statCounter.comm_tcp_incoming.dump(sentry, statHistIntDumper);
}

void
commUpdateReadBits(int fd, PF * handler)
{
    if (handler && !FD_ISSET(fd, &global_readfds)) {
        FD_SET(fd, &global_readfds);
        ++nreadfds;
    } else if (!handler && FD_ISSET(fd, &global_readfds)) {
        FD_CLR(fd, &global_readfds);
        --nreadfds;
    }
}

void
commUpdateWriteBits(int fd, PF * handler)
{
    if (handler && !FD_ISSET(fd, &global_writefds)) {
        FD_SET(fd, &global_writefds);
        ++nwritefds;
    } else if (!handler && FD_ISSET(fd, &global_writefds)) {
        FD_CLR(fd, &global_writefds);
        --nwritefds;
    }
}

/* Called by async-io or diskd to speed up the polling */
void
Comm::QuickPollRequired(void)
{
    MAX_POLL_TIME = 10;
}

#endif /* USE_SELECT_WIN32 */

