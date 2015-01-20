/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 42    ICMP Pinger program */

#define SQUID_HELPER 1

/**
 \defgroup pinger pinger
 \ingroup ExternalPrograms
 \par
 *   Although it would be possible for Squid to send and receive
 *   ICMP messages directly, we use an external process for
 *   two important reasons:
 *
 \li Because squid handles many filedescriptors simultaneously,
 *   we get much more accurate RTT measurements when ICMP is
 *   handled by a separate process.
 *
 \li Superuser privileges are required to send and receive ICMP.
 *   Rather than require Squid to be started as root, we prefer
 *   to have the smaller and simpler pinger program installed
 *   with setuid permissions.
 *
 \par
 *   If you want to use Squid's ICMP features (highly recommended!)
 *   When USE_ICMP is defined, Squid will send ICMP pings
 *   to origin server sites.
 *   This information is used in numerous ways:
 \li  - Sent in ICP replies so neighbor caches know how close
 *      you are to the source.
 \li  - For finding the closest instance of a URN.
 \li  - With the 'test_reachability' option.  Squid will return
 *      ICP_OP_MISS_NOFETCH for sites which it cannot ping.
 */

#include "squid.h"
#include "Debug.h"
#include "SquidTime.h"

#if USE_ICMP

#include "Icmp4.h"
#include "Icmp6.h"
#include "IcmpPinger.h"
#include "ip/tools.h"

#if _SQUID_WINDOWS_

#if HAVE_WINSOCK2_H
#include <winsock2.h>
#elif HAVE_WINSOCK_H
#include <winsock.h>
#endif
#include <process.h>
#include "fde.h"

#define PINGER_TIMEOUT 5

/* windows uses the control socket for feedback to squid */
#define LINK_TO_SQUID squid_link

// windows still requires WSAFD but there are too many dependancy problems
// to just link to win32.cc where it is normally defined.

int
Win32__WSAFDIsSet(int fd, fd_set FAR * set)
{
    fde *F = &fd_table[fd];
    SOCKET s = F->win32.handle;

    return __WSAFDIsSet(s, set);
}

#else

#define PINGER_TIMEOUT 10

/* non-windows use STDOUT for feedback to squid */
#define LINK_TO_SQUID   1

#endif  /* _SQUID_WINDOWS_ */

// ICMP Engines are declared global here so they can call each other easily.
IcmpPinger control;
Icmp4 icmp4;
Icmp6 icmp6;

int icmp_pkts_sent = 0;

/**
 \ingroup pinger
 \par This is the pinger external process.
 *
 \param argc Ignored.
 \param argv Ignored.
 */
int
main(int argc, char *argv[])
{
    fd_set R;
    int x;
    int max_fd = 0;

    struct timeval tv;
    const char *debug_args = "ALL,10";
    char *t;
    time_t last_check_time = 0;

    /*
     * cevans - do this first. It grabs a raw socket. After this we can
     * drop privs
     */
    int icmp4_worker = -1;
    int icmp6_worker = -1;
    int squid_link = -1;

    /** start by initializing the pinger debug cache.log-pinger. */
    if ((t = getenv("SQUID_DEBUG")))
        debug_args = xstrdup(t);

    getCurrentTime();

    // determine IPv4 or IPv6 capabilities before using sockets.
    Ip::ProbeTransport();

    _db_init(NULL, debug_args);

    debugs(42, DBG_CRITICAL, "pinger: Initialising ICMP pinger ...");

    icmp4_worker = icmp4.Open();
    if (icmp4_worker < 0) {
        debugs(42, DBG_CRITICAL, "pinger: Unable to start ICMP pinger.");
    }
    max_fd = max(max_fd, icmp4_worker);

#if USE_IPV6
    icmp6_worker = icmp6.Open();
    if (icmp6_worker <0 ) {
        debugs(42, DBG_CRITICAL, "pinger: Unable to start ICMPv6 pinger.");
    }
    max_fd = max(max_fd, icmp6_worker);
#endif

    /** abort if neither worker could open a socket. */
    if (icmp4_worker < 0 && icmp6_worker < 0) {
        debugs(42, DBG_CRITICAL, "FATAL: pinger: Unable to open any ICMP sockets.");
        exit(1);
    }

    if ( (squid_link = control.Open()) < 0) {
        debugs(42, DBG_CRITICAL, "FATAL: pinger: Unable to setup Pinger control sockets.");
        icmp4.Close();
        icmp6.Close();
        exit(1); // fatal error if the control channel fails.
    }
    max_fd = max(max_fd, squid_link);

    if (setgid(getgid()) < 0) {
        debugs(42, DBG_CRITICAL, "FATAL: pinger: setgid(" << getgid() << ") failed: " << xstrerror());
        icmp4.Close();
        icmp6.Close();
        exit (1);
    }
    if (setuid(getuid()) < 0) {
        debugs(42, DBG_CRITICAL, "FATAL: pinger: setuid(" << getuid() << ") failed: " << xstrerror());
        icmp4.Close();
        icmp6.Close();
        exit (1);
    }

    last_check_time = squid_curtime;

    for (;;) {
        tv.tv_sec = PINGER_TIMEOUT;
        tv.tv_usec = 0;
        FD_ZERO(&R);
        if (icmp4_worker >= 0) {
            FD_SET(icmp4_worker, &R);
        }
        if (icmp6_worker >= 0) {
            FD_SET(icmp6_worker, &R);
        }

        FD_SET(squid_link, &R);
        x = select(10, &R, NULL, NULL, &tv);
        getCurrentTime();

        if (x < 0) {
            debugs(42, DBG_CRITICAL, HERE << " FATAL Shutdown. select()==" << x << ", ERR: " << xstrerror());
            control.Close();
            exit(1);
        }

        if (FD_ISSET(squid_link, &R)) {
            control.Recv();
        }

        if (icmp6_worker >= 0 && FD_ISSET(icmp6_worker, &R)) {
            icmp6.Recv();
        }
        if (icmp4_worker >= 0 && FD_ISSET(icmp4_worker, &R)) {
            icmp4.Recv();
        }

        if (PINGER_TIMEOUT + last_check_time < squid_curtime) {
            if (send(LINK_TO_SQUID, &tv, 0, 0) < 0) {
                debugs(42, DBG_CRITICAL, "pinger: Closing. No requests in last " << PINGER_TIMEOUT << " seconds.");
                control.Close();
                exit(1);
            }

            last_check_time = squid_curtime;
        }
    }

    /* NOTREACHED */
    return 0;
}

#else /* !USE_ICMP */

#include <ostream>
int
main(int argc, char *argv[])
{
    std::cerr << argv[0] << ": ICMP support not compiled in." << std::endl;
    return 1;
}

#endif /* USE_ICMP */

