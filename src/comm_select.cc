

/*
 * $Id: comm_select.cc,v 1.1 1998/07/21 17:03:49 wessels Exp $
 *
 * DEBUG: section 5     Socket Functions
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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

#if USE_ASYNC_IO
#define MAX_POLL_TIME 10
#else
#define MAX_POLL_TIME 1000
#endif

/* STATIC */
#if !HAVE_POLL
static int examine_select(fd_set *, fd_set *);
#endif
static int fdIsHttp(int fd);
static int fdIsIcp(int fd);
static int commDeferRead(int fd);
static void checkTimeouts(void);
static OBJH commIncomingStats;
#if HAVE_POLL
static int comm_check_incoming_poll_handlers(int nfds, int *fds);
#else
static int comm_check_incoming_select_handlers(int nfds, int *fds);
#endif

static struct timeval zero_tv;

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
 *  incoming_interval = incoming_interval + 1 - number_of_events_processed
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
static int http_io_events = 0;
static int incoming_icp_interval = 16 << INCOMING_FACTOR;
static int incoming_http_interval = 16 << INCOMING_FACTOR;
#define commCheckICPIncoming (++icp_io_events > (incoming_icp_interval>> INCOMING_FACTOR))
#define commCheckHTTPIncoming (++http_io_events > (incoming_http_interval>> INCOMING_FACTOR))

static int
commDeferRead(int fd)
{
    fde *F = &fd_table[fd];
    if (F->defer_check == NULL)
	return 0;
    return F->defer_check(fd, F->defer_data);
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
fdIsHttp(int fd)
{
    int j;
    for (j = 0; j < NHttpSockets; j++) {
	if (fd == HttpSockets[j])
	    return 1;
    }
    return 0;
}

#if HAVE_POLL
static int
comm_check_incoming_poll_handlers(int nfds, int *fds)
{
    int i;
    int fd;
    int incame = 0;
    PF *hdl = NULL;
    int npfds;
    struct pollfd pfds[3 + MAXHTTPPORTS];
    for (i = npfds = 0; i < nfds; i++) {
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
	    npfds++;
	}
    }
    if (!nfds)
	return incame;
#if !ALARM_UPDATES_TIME
    getCurrentTime();
#endif
    if (poll(pfds, npfds, 0) < 1)
	return incame;
    for (i = 0; i < npfds; i++) {
	int revents;
	if (((revents = pfds[i].revents) == 0) || ((fd = pfds[i].fd) == -1))
	    continue;
	if (revents & (POLLRDNORM | POLLIN | POLLHUP | POLLERR)) {
	    if ((hdl = fd_table[fd].read_handler)) {
		fd_table[fd].read_handler = NULL;
		hdl(fd, &incame);
	    } else
		debug(5, 1) ("comm_poll_incoming: NULL read handler\n");
	}
	if (revents & (POLLWRNORM | POLLOUT | POLLHUP | POLLERR)) {
	    if ((hdl = fd_table[fd].write_handler)) {
		fd_table[fd].write_handler = NULL;
		hdl(fd, &incame);
	    } else
		debug(5, 1) ("comm_poll_incoming: NULL write handler\n");
	}
    }
    return incame;
}

static void
comm_poll_icp_incoming(void)
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
    nevents = comm_check_incoming_poll_handlers(nfds, fds);
    incoming_icp_interval = incoming_icp_interval + 1 - nevents;
    if (incoming_icp_interval < 0)
	incoming_icp_interval = 0;
    if (incoming_icp_interval > MAX_INCOMING_INTERVAL)
	incoming_icp_interval = MAX_INCOMING_INTERVAL;
    if (nevents > INCOMING_ICP_MAX)
	nevents = INCOMING_ICP_MAX;
    statHistCount(&Counter.comm_icp_incoming, nevents);
}

static void
comm_poll_http_incoming(void)
{
    int nfds = 0;
    int fds[MAXHTTPPORTS];
    int j;
    int nevents;
    http_io_events = 0;
    for (j = 0; j < NHttpSockets; j++) {
	if (HttpSockets[j] < 0)
	    continue;
	if (commDeferRead(HttpSockets[j]))
	    continue;
	fds[nfds++] = HttpSockets[j];
    }
    nevents = comm_check_incoming_poll_handlers(nfds, fds);
    incoming_http_interval = incoming_http_interval + 1 - nevents;
    if (incoming_http_interval < 0)
	incoming_http_interval = 0;
    if (incoming_http_interval > MAX_INCOMING_INTERVAL)
	incoming_http_interval = MAX_INCOMING_INTERVAL;
    if (nevents > INCOMING_HTTP_MAX)
	nevents = INCOMING_HTTP_MAX;
    statHistCount(&Counter.comm_http_incoming, nevents);
}

/* poll all sockets; call handlers for those that are ready. */
int
comm_poll(int msec)
{
    struct pollfd pfds[SQUID_MAXFD];
    PF *hdl = NULL;
    int fd;
    int i;
    int maxfd;
    unsigned long nfds;
    int num;
    int callicp = 0, callhttp = 0;
    static time_t last_timeout = 0;
    double timeout = current_dtime + (msec / 1000.0);
    do {
#if !ALARM_UPDATES_TIME
	getCurrentTime();
#endif
	if (shutting_down) {
	    serverConnectionsClose();
	    dnsShutdownServers();
	    redirectShutdownServers();
	    /* shutting_down will be set to
	     * +1 for SIGTERM
	     * -1 for SIGINT */
	    if (shutting_down > 0)
		setSocketShutdownLifetimes(Config.shutdownLifetime);
	    else
		setSocketShutdownLifetimes(1);
	}
#if USE_ASYNC_IO
	aioCheckCallbacks();
#endif
	if (commCheckICPIncoming)
	    comm_poll_icp_incoming();
	if (commCheckHTTPIncoming)
	    comm_poll_http_incoming();
	callicp = callhttp = 0;
	nfds = 0;
	maxfd = Biggest_FD + 1;
	for (i = 0; i < maxfd; i++) {
	    int events;
	    events = 0;
	    /* Check each open socket for a handler. */
	    if (fd_table[i].read_handler && !commDeferRead(i))
		events |= POLLRDNORM;
	    if (fd_table[i].write_handler)
		events |= POLLWRNORM;
	    if (events) {
		pfds[nfds].fd = i;
		pfds[nfds].events = events;
		pfds[nfds].revents = 0;
		nfds++;
	    }
	}
	if (shutting_down)
	    debug(5, 2) ("comm_poll: Still waiting on %d FDs\n", nfds);
	if (nfds == 0)
	    return COMM_SHUTDOWN;
	if (msec > MAX_POLL_TIME)
	    msec = MAX_POLL_TIME;
	for (;;) {
	    num = poll(pfds, nfds, msec);
	    Counter.select_loops++;
	    if (num >= 0)
		break;
	    if (ignoreErrno(errno))
		continue;
	    debug(5, 0) ("comm_poll: poll failure: %s\n", xstrerror());
	    assert(errno != EINVAL);
	    return COMM_ERROR;
	    /* NOTREACHED */
	}
	debug(5, num ? 5 : 8) ("comm_poll: %d sockets ready\n", num);
	/* Check timeout handlers ONCE each second. */
	if (squid_curtime > last_timeout) {
	    last_timeout = squid_curtime;
	    checkTimeouts();
	}
	if (num == 0)
	    continue;
	/* scan each socket but the accept socket. Poll this 
	 * more frequently to minimize losses due to the 5 connect 
	 * limit in SunOS */
	for (i = 0; i < nfds; i++) {
	    int revents;
	    if (((revents = pfds[i].revents) == 0) || ((fd = pfds[i].fd) == -1))
		continue;
	    if (fdIsIcp(fd)) {
		callicp = 1;
		continue;
	    }
	    if (fdIsHttp(fd)) {
		callhttp = 1;
		continue;
	    }
	    if (revents & (POLLRDNORM | POLLIN | POLLHUP | POLLERR)) {
		debug(5, 6) ("comm_poll: FD %d ready for reading\n", fd);
		if ((hdl = fd_table[fd].read_handler)) {
		    fd_table[fd].read_handler = NULL;
		    hdl(fd, fd_table[fd].read_data);
		}
		if (commCheckICPIncoming)
		    comm_poll_icp_incoming();
		if (commCheckHTTPIncoming)
		    comm_poll_http_incoming();
	    }
	    if (revents & (POLLWRNORM | POLLOUT | POLLHUP | POLLERR)) {
		debug(5, 5) ("comm_poll: FD %d ready for writing\n", fd);
		if ((hdl = fd_table[fd].write_handler)) {
		    fd_table[fd].write_handler = NULL;
		    hdl(fd, fd_table[fd].write_data);
		}
		if (commCheckICPIncoming)
		    comm_poll_icp_incoming();
		if (commCheckHTTPIncoming)
		    comm_poll_http_incoming();
	    }
	    if (revents & POLLNVAL) {
		close_handler *ch;
		fde *F = &fd_table[fd];
		debug(5, 0) ("WARNING: FD %d has handlers, but it's invalid.\n", fd);
		debug(5, 0) ("FD %d is a %s\n", fd, fdTypeStr[fd_table[fd].type]);
		debug(5, 0) ("--> %s\n", fd_table[fd].desc);
		debug(5, 0) ("tmout:%p read:%p write:%p\n",
		    F->timeout_handler,
		    F->read_handler,
		    F->write_handler);
		for (ch = F->close_handler; ch; ch = ch->next)
		    debug(5, 0) (" close handler: %p\n", ch->handler);
		if (F->close_handler) {
		    commCallCloseHandlers(fd);
		} else if (F->timeout_handler) {
		    debug(5, 0) ("comm_poll: Calling Timeout Handler\n");
		    F->timeout_handler(fd, F->timeout_data);
		}
		F->close_handler = NULL;
		F->timeout_handler = NULL;
		F->read_handler = NULL;
		F->write_handler = NULL;
		if (F->open != 0)
		    fd_close(fd);
	    }
	}
	if (callicp)
	    comm_poll_icp_incoming();
	if (callhttp)
	    comm_poll_http_incoming();
	return COMM_OK;
    } while (timeout > current_dtime);
    debug(5, 8) ("comm_poll: time out: %d.\n", squid_curtime);
    return COMM_TIMEOUT;
}

#else

static int
comm_check_incoming_select_handlers(int nfds, int *fds)
{
    int i;
    int fd;
    int incame = 0;
    int maxfd = 0;
    PF *hdl = NULL;
    fd_set read_mask;
    fd_set write_mask;
    FD_ZERO(&read_mask);
    FD_ZERO(&write_mask);
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
	return incame;
#if !ALARM_UPDATES_TIME
    getCurrentTime();
#endif
    if (select(maxfd, &read_mask, &write_mask, NULL, &zero_tv) < 1)
	return incame;
    for (i = 0; i < nfds; i++) {
	fd = fds[i];
	if (FD_ISSET(fd, &read_mask)) {
	    if ((hdl = fd_table[fd].read_handler) != NULL) {
		fd_table[fd].read_handler = NULL;
		hdl(fd, &incame);
	    } else {
		debug(5, 1) ("comm_select_incoming: NULL read handler\n");
	    }
	}
	if (FD_ISSET(fd, &write_mask)) {
	    if ((hdl = fd_table[fd].write_handler) != NULL) {
		fd_table[fd].write_handler = NULL;
		hdl(fd, &incame);
	    } else {
		debug(5, 1) ("comm_select_incoming: NULL write handler\n");
	    }
	}
    }
    return incame;
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
    incoming_icp_interval = incoming_icp_interval + 1 - nevents;
    if (incoming_icp_interval < 0)
	incoming_icp_interval = 0;
    if (incoming_icp_interval > MAX_INCOMING_INTERVAL)
	incoming_icp_interval = MAX_INCOMING_INTERVAL;
    if (nevents > INCOMING_ICP_MAX)
	nevents = INCOMING_ICP_MAX;
    statHistCount(&Counter.comm_icp_incoming, nevents);
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
	if (commDeferRead(HttpSockets[j]))
	    continue;
	fds[nfds++] = HttpSockets[j];
    }
    nevents = comm_check_incoming_select_handlers(nfds, fds);
    incoming_http_interval = incoming_http_interval + 1 - nevents;
    if (incoming_http_interval < 0)
	incoming_http_interval = 0;
    if (incoming_http_interval > MAX_INCOMING_INTERVAL)
	incoming_http_interval = MAX_INCOMING_INTERVAL;
    if (nevents > INCOMING_HTTP_MAX)
	nevents = INCOMING_HTTP_MAX;
    statHistCount(&Counter.comm_http_incoming, nevents);
}

/* Select on all sockets; call handlers for those that are ready. */
int
comm_select(int msec)
{
    fd_set readfds;
    fd_set writefds;
    PF *hdl = NULL;
    int fd;
    int i;
    int maxfd;
    int nfds;
    int num;
    int callicp = 0, callhttp = 0;
    static time_t last_timeout = 0;
    struct timeval poll_time;
    double timeout = current_dtime + (msec / 1000.0);
    do {
#if !ALARM_UPDATES_TIME
	getCurrentTime();
#endif
#if USE_ASYNC_IO
	aioCheckCallbacks();
#endif
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	if (shutting_down) {
	    serverConnectionsClose();
	    dnsShutdownServers();
	    redirectShutdownServers();
	    /* shutting_down will be set to
	     * +1 for SIGTERM
	     * -1 for SIGINT */
	    if (shutting_down > 0)
		setSocketShutdownLifetimes(Config.shutdownLifetime);
	    else
		setSocketShutdownLifetimes(1);
	}
	if (commCheckICPIncoming)
	    comm_select_icp_incoming();
	if (commCheckHTTPIncoming)
	    comm_select_http_incoming();
	callicp = callhttp = 0;
	nfds = 0;
	maxfd = Biggest_FD + 1;
	for (i = 0; i < maxfd; i++) {
	    /* Check each open socket for a handler. */
	    if (fd_table[i].read_handler && !commDeferRead(i)) {
		nfds++;
		FD_SET(i, &readfds);
	    }
	    if (fd_table[i].write_handler) {
		nfds++;
		FD_SET(i, &writefds);
	    }
	}
	if (shutting_down)
	    debug(5, 2) ("comm_select: Still waiting on %d FDs\n", nfds);
	if (nfds == 0)
	    return COMM_SHUTDOWN;
	if (msec > MAX_POLL_TIME)
	    msec = MAX_POLL_TIME;
	for (;;) {
	    poll_time.tv_sec = msec / 1000;
	    poll_time.tv_usec = (msec % 1000) * 1000;
	    num = select(maxfd, &readfds, &writefds, NULL, &poll_time);
	    Counter.select_loops++;
	    if (num >= 0)
		break;
	    if (ignoreErrno(errno))
		break;
	    debug(50, 0) ("comm_select: select failure: %s\n",
		xstrerror());
	    examine_select(&readfds, &writefds);
	    return COMM_ERROR;
	    /* NOTREACHED */
	}
	if (num < 0)
	    continue;
	debug(5, num ? 5 : 8) ("comm_select: %d sockets ready at %d\n",
	    num, (int) squid_curtime);
	/* Check lifetime and timeout handlers ONCE each second.
	 * Replaces brain-dead check every time through the loop! */
	if (squid_curtime > last_timeout) {
	    last_timeout = squid_curtime;
	    checkTimeouts();
	}
	if (num == 0)
	    continue;
	/* scan each socket but the accept socket. Poll this 
	 * more frequently to minimize losses due to the 5 connect 
	 * limit in SunOS */
	for (fd = 0; fd < maxfd; fd++) {
	    if (!FD_ISSET(fd, &readfds) && !FD_ISSET(fd, &writefds))
		continue;
	    if (fdIsIcp(fd)) {
		callicp = 1;
		continue;
	    }
	    if (fdIsHttp(fd)) {
		callhttp = 1;
		continue;
	    }
	    if (FD_ISSET(fd, &readfds)) {
		debug(5, 6) ("comm_select: FD %d ready for reading\n", fd);
		if (fd_table[fd].read_handler) {
		    hdl = fd_table[fd].read_handler;
		    fd_table[fd].read_handler = NULL;
		    hdl(fd, fd_table[fd].read_data);
		}
		if (commCheckICPIncoming)
		    comm_select_icp_incoming();
		if (commCheckHTTPIncoming)
		    comm_select_http_incoming();
	    }
	    if (FD_ISSET(fd, &writefds)) {
		debug(5, 5) ("comm_select: FD %d ready for writing\n", fd);
		if (fd_table[fd].write_handler) {
		    hdl = fd_table[fd].write_handler;
		    fd_table[fd].write_handler = NULL;
		    hdl(fd, fd_table[fd].write_data);
		}
		if (commCheckICPIncoming)
		    comm_select_icp_incoming();
		if (commCheckHTTPIncoming)
		    comm_select_http_incoming();
	    }
	}
	if (callicp)
	    comm_select_icp_incoming();
	if (callhttp)
	    comm_select_http_incoming();
	return COMM_OK;
    } while (timeout > current_dtime);
    debug(5, 8) ("comm_select: time out: %d\n", (int) squid_curtime);
    return COMM_TIMEOUT;
}
#endif

void
comm_select_init(void)
{
    zero_tv.tv_sec = 0;
    zero_tv.tv_usec = 0;
    cachemgrRegister("comm_incoming",
	"comm_incoming() stats",
	commIncomingStats, 0, 1);
}

#if !HAVE_POLL
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
    int num;
    struct timeval tv;
    close_handler *ch = NULL;
    fde *F = NULL;
    debug(5, 0) ("examine_select: Examining open file descriptors...\n");
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
	num = select(Squid_MaxFD, &read_x, &write_x, NULL, &tv);
	if (num > -1) {
	    debug(5, 5) ("FD %d is valid.\n", fd);
	    continue;
	}
	F = &fd_table[fd];
	debug(5, 0) ("FD %d: %s\n", fd, xstrerror());
	debug(5, 0) ("WARNING: FD %d has handlers, but it's invalid.\n", fd);
	debug(5, 0) ("FD %d is a %s called '%s'\n",
	    fd,
	    fdTypeStr[fd_table[fd].type],
	    F->desc);
	debug(5, 0) ("tmout:%p read:%p write:%p\n",
	    F->timeout_handler,
	    F->read_handler,
	    F->write_handler);
	for (ch = F->close_handler; ch; ch = ch->next)
	    debug(5, 0) (" close handler: %p\n", ch->handler);
	if (F->close_handler) {
	    commCallCloseHandlers(fd);
	} else if (F->timeout_handler) {
	    debug(5, 0) ("examine_select: Calling Timeout Handler\n");
	    F->timeout_handler(fd, F->timeout_data);
	}
	F->close_handler = NULL;
	F->timeout_handler = NULL;
	F->read_handler = NULL;
	F->write_handler = NULL;
	FD_CLR(fd, readfds);
	FD_CLR(fd, writefds);
    }
    return 0;
}
#endif

static void
checkTimeouts(void)
{
    int fd;
    fde *F = NULL;
    PF *callback;
    for (fd = 0; fd <= Biggest_FD; fd++) {
	F = &fd_table[fd];
	if (F->open != FD_OPEN)
	    continue;
	if (F->timeout == 0)
	    continue;
	if (F->timeout > squid_curtime)
	    continue;
	debug(5, 5) ("checkTimeouts: FD %d Expired\n", fd);
	if (F->timeout_handler) {
	    debug(5, 5) ("checkTimeouts: FD %d: Call timeout handler\n", fd);
	    callback = F->timeout_handler;
	    F->timeout_handler = NULL;
	    callback(fd, F->timeout_data);
	} else {
	    debug(5, 5) ("checkTimeouts: FD %d: Forcing comm_close()\n", fd);
	    comm_close(fd);
	}
    }
}

static void
commIncomingStats(StoreEntry * sentry)
{
    StatCounters *f = &Counter;
    storeAppendPrintf(sentry, "Current incoming_icp_interval: %d\n",
	incoming_icp_interval >> INCOMING_FACTOR);
    storeAppendPrintf(sentry, "Current incoming_http_interval: %d\n",
	incoming_http_interval >> INCOMING_FACTOR);
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "Histogram of events per incoming socket type\n");
#ifdef HAVE_POLL
    storeAppendPrintf(sentry, "ICP Messages handled per comm_poll_icp_incoming() call:\n");
#else
    storeAppendPrintf(sentry, "ICP Messages handled per comm_select_icp_incoming() call:\n");
#endif
    statHistDump(&f->comm_icp_incoming, sentry, statHistIntDumper);
#ifdef HAVE_POLL
    storeAppendPrintf(sentry, "HTTP Messages handled per comm_poll_http_incoming() call:\n");
#else
    storeAppendPrintf(sentry, "HTTP Messages handled per comm_select_http_incoming() call:\n");
#endif
    statHistDump(&f->comm_http_incoming, sentry, statHistIntDumper);
}
