/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Socket Functions */

/*
 * This is a very simple driver for Solaris /dev/poll.
 *
 * The updates are batched, one trip through the comm loop.
 * (like libevent.) We keep a pointer into the structs so we
 * can zero out an entry in the poll list if its active.
 *
 * Ported by Peter Payne from Squid 2.7.STABLE9 comm_devpoll.c
 * on August 11, 2010 at 3pm (GMT+0100 Europe/London).
 *
 * Last modified 2010-10-08
 */

/*
 * There are several poll types in Squid, ALL of which are compiled and linked
 * in. Thus conditional compile-time flags are used to prevent the different
 * modules from creating several versions of the same function simultaneously.
 */

#include "squid.h"

#if USE_DEVPOLL

#include "comm/Loops.h"
#include "fd.h"
#include "fde.h"
#include "mgr/Registration.h"
#include "StatCounters.h"
#include "StatHist.h"
#include "Store.h"

#include <cerrno>
#include <climits>
#if HAVE_SYS_DEVPOLL_H
/* Solaris /dev/poll support, see "man -s 7D poll" */
#include <sys/devpoll.h>
#endif

#define DEBUG_DEVPOLL 0

// OPEN_MAX is defined in <climits>
#define DEVPOLL_UPDATESIZE  OPEN_MAX
#define DEVPOLL_QUERYSIZE   OPEN_MAX

/* TYPEDEFS */
typedef short pollfd_events_t; /* type of pollfd.events from sys/poll.h */

/* STRUCTURES */
/** \brief Current state */
struct _devpoll_state {
    pollfd_events_t state; /**< current known state of file handle */
};

/** \brief Update list
 *
 * This structure contains an array of settings to send to the /dev/poll
 * interface. Rather than send changes to /dev/poll one at a time they
 * are pushed onto this array (updating cur to indicate how many of the
 * pfds structure elements have been set) until it is full before it
 * is written out the API.
 */
static struct {
    struct pollfd *pfds; /**< ptr to array of struct pollfd config elements */
    int cur; /**< index of last written element of array, or -1 if none */
    int size; /**< maximum number of elements in array */
} devpoll_update;

/* STATIC VARIABLES */
static int devpoll_fd; /**< handle to /dev/poll device */
static int max_poll_time = 1000; /**< maximum milliseconds to spend in poll */

static struct _devpoll_state *devpoll_state; /**< array of socket states */
static struct dvpoll do_poll; /**< data struct for storing poll results */
static int dpoll_nfds; /**< maximum number of poll results */

/* PROTOTYPES */
static void commDevPollRegisterWithCacheManager(void);

/* PRIVATE FUNCTIONS */
/** \brief Write batched file descriptor event changes to poll device
 *
 * Writes out the static array of file descriptor event changes to the
 * poll device. This is done only when necessary (i.e. just before
 * the poll device is queried during the select call, and whenever
 * the number of changes to store in the array exceeds the size of the
 * array).
 */
static void
comm_flush_updates(void)
{
    int i;
    if (devpoll_update.cur == -1)
        return; /* array of changes to make is empty */

    debugs(
        5,
        DEBUG_DEVPOLL ? 0 : 8,
        (devpoll_update.cur + 1) << " fds queued"
    );

    i = write(
            devpoll_fd, /* open handle to /dev/poll */
            devpoll_update.pfds, /* pointer to array of struct pollfd */
            (devpoll_update.cur + 1) * sizeof(struct pollfd) /* bytes to process */
        );
    assert(i > 0);
    assert(static_cast<size_t>(i) == (sizeof(struct pollfd) * (devpoll_update.cur + 1)));
    devpoll_update.cur = -1; /* reset size of array, no elements remain */
}

/** \brief Register change in desired polling state for file descriptor
 *
 * Prevents unnecessary calls to the /dev/poll API by queueing changes
 * in the devpoll_update array. If the array fills up the comm_flush_updates
 * function is called.
 *
 * @param fd file descriptor to register change with
 * @param events events to register (usually POLLIN, POLLOUT, or POLLREMOVE)
 */
static void
comm_update_fd(int fd, int events)
{
    debugs(
        5,
        DEBUG_DEVPOLL ? 0 : 8,
        "FD " << fd << ", events=" << events
    );

    /* Is the array already full and in need of flushing? */
    if (devpoll_update.cur != -1 && (devpoll_update.cur == devpoll_update.size))
        comm_flush_updates();

    /* Push new event onto array */
    ++ devpoll_update.cur;
    devpoll_update.pfds[devpoll_update.cur].fd = fd;
    devpoll_update.pfds[devpoll_update.cur].events = events;
    devpoll_update.pfds[devpoll_update.cur].revents = 0;
}

static void commIncomingStats(StoreEntry *sentry)
{
    storeAppendPrintf(sentry, "Total number of devpoll loops: %ld\n", statCounter.select_loops);
    storeAppendPrintf(sentry, "Histogram of returned filedescriptors\n");
    statCounter.select_fds_hist.dump(sentry, statHistIntDumper);
}

static void
commDevPollRegisterWithCacheManager(void)
{
    Mgr::RegisterAction(
        "comm_devpoll_incoming",
        "comm_incoming() stats",
        commIncomingStats,
        0,
        1
    );
}

/* PUBLIC FUNCTIONS */

/** \brief Initialise /dev/poll support
 *
 * Allocates memory, opens /dev/poll device handle.
 */
void
Comm::SelectLoopInit(void)
{
    /* allocate memory first before attempting to open poll device */
    /* This tracks the FD devpoll offset+state */
    devpoll_state = (struct _devpoll_state *)xcalloc(
                        SQUID_MAXFD, sizeof(struct _devpoll_state)
                    );

    /* And this is the stuff we use to read events */
    do_poll.dp_fds = (struct pollfd *)xcalloc(
                         DEVPOLL_QUERYSIZE, sizeof(struct pollfd)
                     );
    dpoll_nfds = DEVPOLL_QUERYSIZE;

    devpoll_update.pfds = (struct pollfd *)xcalloc(
                              DEVPOLL_UPDATESIZE, sizeof(struct pollfd)
                          );
    devpoll_update.cur = -1;
    devpoll_update.size = DEVPOLL_UPDATESIZE;

    /* attempt to open /dev/poll device */
    devpoll_fd = open("/dev/poll", O_RDWR);
    if (devpoll_fd < 0) {
        int xerrno = errno;
        fatalf("comm_select_init: can't open /dev/poll: %s\n", xstrerr(xerrno));
    }

    fd_open(devpoll_fd, FD_UNKNOWN, "devpoll ctl");

    commDevPollRegisterWithCacheManager();
}

/** \brief Set polling state of file descriptor and callback functions
 *
 * Sets requested polling state for given file handle along with
 * desired callback function in the event the request event triggers.
 *
 * Note that setting a polling state with a NULL callback function will
 * clear the polling for that event on that file descriptor.
 *
 * @param fd file descriptor to change
 * @param type may be COMM_SELECT_READ (input) or COMM_SELECT_WRITE (output)
 * @param handler callback function, or NULL to stop type of polling
 * @param client_data pointer to be provided to call back function
 * @param timeout if non-zero then timeout relative to now
 */
void
Comm::SetSelect(int fd, unsigned int type, PF * handler, void *client_data, time_t timeout)
{
    assert(fd >= 0);
    debugs(5, 5, "FD " << fd << ", type=" << type <<
           ", handler=" << handler << ", client_data=" << client_data <<
           ", timeout=" << timeout);

    /* POLLIN/POLLOUT are defined in <sys/poll.h> */
    fde *F = &fd_table[fd];
    if (!F->flags.open) {
        /* remove from poll set */
        comm_update_fd( fd, POLLREMOVE );
        devpoll_state[fd].state = 0;
        return;
    }

    pollfd_events_t state_old = devpoll_state[fd].state;
    pollfd_events_t state_new = 0; /* new state (derive from old state) */

    if ( type & COMM_SELECT_READ ) {
        if ( handler != NULL ) {
            // Hack to keep the events flowing if there is data immediately ready
            if (F->flags.read_pending)
                state_new |= POLLOUT;
            /* we want to POLLIN */
            state_new |= POLLIN;
        } else {
            ; /* we want to clear POLLIN because handler is NULL */
        }

        F->read_handler = handler;
        F->read_data = client_data;
    } else if ( state_old & POLLIN ) {
        /* we're not changing reading state so take from existing */
        state_new |= POLLIN;
    }

    if ( type & COMM_SELECT_WRITE ) {
        if ( handler != NULL ) {
            /* we want to POLLOUT */
            state_new |= POLLOUT;
        } else {
            ; /* we want to clear POLLOUT because handler is NULL */
        }

        F->write_handler = handler;
        F->write_data = client_data;
    } else if ( state_old & POLLOUT ) {
        /* we're not changing writing state so take from existing */
        state_new |= POLLOUT;
    }

    if ( pollfd_events_t bits_changed = (state_old ^ state_new) ) {
        /* something has changed, update /dev/poll of what to listen for */

        /* did any bits clear? (in which case a poll remove is necessary) */
        if ( bits_changed & state_old ) {
            comm_update_fd( fd, POLLREMOVE );
            /* existing state cleared, so update with all required events */
            if ( state_new )
                comm_update_fd( fd, state_new );
        } else {
            /* only update with new required event */
            if ( pollfd_events_t newly_set_only = (bits_changed & state_new) )
                comm_update_fd( fd, newly_set_only );
        }

        devpoll_state[fd].state = state_new;
    }

    if (timeout)
        F->timeout = squid_curtime + timeout;
}

/** \brief Do poll and trigger callback functions as appropriate
 *
 * Check all connections for new connections and input data that is to be
 * processed. Also check for connections with data queued and whether we can
 * write it out.
 *
 * Called to do the new-style IO, courtesy of of squid (like most of this
 * new IO code). This routine handles the stuff we've hidden in
 * comm_setselect and fd_table[] and calls callbacks for IO ready
 * events.
 *
 * @param msec milliseconds to poll for (limited by max_poll_time)
 */
Comm::Flag
Comm::DoSelect(int msec)
{
    int num, i;
    fde *F;
    PF *hdl;

    if (msec > max_poll_time)
        msec = max_poll_time;

    for (;;) {
        do_poll.dp_timeout = msec;
        do_poll.dp_nfds = dpoll_nfds;

        comm_flush_updates(); /* ensure latest changes are sent to /dev/poll */

        num = ioctl(devpoll_fd, DP_POLL, &do_poll);
        ++ statCounter.select_loops;

        if (num >= 0)
            break; /* no error, skip out of loop */

        if (ignoreErrno(errno))
            break; /* error is one we may ignore, skip out of loop */

        /* error during poll */
        getCurrentTime();
        return Comm::COMM_ERROR;
    }

    getCurrentTime();

    statCounter.select_fds_hist.count(num);

    if (num == 0)
        return Comm::TIMEOUT; /* no error */

    for (i = 0; i < num; ++i) {
        int fd = (int)do_poll.dp_fds[i].fd;
        F = &fd_table[fd];
        debugs(
            5,
            DEBUG_DEVPOLL ? 0 : 8,
            "got FD " << fd
            << ",events=" << std::hex << do_poll.dp_fds[i].revents
            << ",monitoring=" << devpoll_state[fd].state
            << ",F->read_handler=" << F->read_handler
            << ",F->write_handler=" << F->write_handler
        );

        /* handle errors */
        if (do_poll.dp_fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            debugs(5, DEBUG_DEVPOLL ? 0 : 8,
                   "ERROR: devpoll event failure: fd " << fd
                  );
            continue;
        }

        /* check if file descriptor has data to read */
        if (do_poll.dp_fds[i].revents & POLLIN || F->flags.read_pending) {
            if ( (hdl = F->read_handler) != NULL ) {
                debugs(
                    5,
                    DEBUG_DEVPOLL ? 0 : 8,
                    "Calling read handler on FD " << fd
                );
                F->read_handler = NULL;
                hdl(fd, F->read_data);
                ++ statCounter.select_fds;
            } else {
                debugs(
                    5,
                    DEBUG_DEVPOLL ? 0 : 8,
                    "no read handler for FD " << fd
                );
                // remove interest since no handler exist for this event.
                SetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
            }
        }

        /* check if file descriptor is ready to write */
        if (do_poll.dp_fds[i].revents & POLLOUT) {
            if ((hdl = F->write_handler) != NULL) {
                debugs(
                    5,
                    DEBUG_DEVPOLL ? 0 : 8,
                    "Calling write handler on FD " << fd
                );
                F->write_handler = NULL;
                hdl(fd, F->write_data);
                ++ statCounter.select_fds;
            } else {
                debugs(
                    5,
                    DEBUG_DEVPOLL ? 0 : 8,
                    "no write handler for FD " << fd
                );
                // remove interest since no handler exist for this event.
                SetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
            }
        }
    }

    return Comm::OK;
}

void
Comm::QuickPollRequired(void)
{
    max_poll_time = 10;
}

#endif /* USE_DEVPOLL */

