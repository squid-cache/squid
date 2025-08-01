/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
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
#include "debug/Stream.h"

#if USE_ICMP

#include "base/Stopwatch.h"
#include "compat/select.h"
#include "compat/socket.h"
#include "Icmp4.h"
#include "Icmp6.h"
#include "IcmpPinger.h"
#include "ip/tools.h"
#include "time/gadgets.h"

#if HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif

#if _SQUID_WINDOWS_

#include <process.h>

#include "fde.h"

/* windows uses the control socket for feedback to squid */
#define LINK_TO_SQUID squid_link

// windows still requires WSAFD but there are too many dependency problems
// to just link to win32.cc where it is normally defined.

int
Win32__WSAFDIsSet(int fd, fd_set FAR * set)
{
    fde *F = &fd_table[fd];
    SOCKET s = F->win32.handle;

    return __WSAFDIsSet(s, set);
}

#else

/* non-windows use STDOUT for feedback to squid */
#define LINK_TO_SQUID   1

#endif  /* _SQUID_WINDOWS_ */

using namespace std::literals::chrono_literals;
static const auto PingerTimeout = 10s;

// ICMP Engines are declared global here so they can call each other easily.
IcmpPinger control;
Icmp4 icmp4;
Icmp6 icmp6;

int icmp_pkts_sent = 0;

/**
 \ingroup pinger
 \par This is the pinger external process.
 */
int
main(int, char **)
{
    fd_set R;
    int max_fd = 0;

    /*
     * cevans - do this first. It grabs a raw socket. After this we can
     * drop privs
     */
    int icmp4_worker = -1;
    int icmp6_worker = -1;
    int squid_link = -1;

    Debug::NameThisHelper("pinger");

    getCurrentTime();

    // determine IPv4 or IPv6 capabilities before using sockets.
    Ip::ProbeTransport();

    debugs(42, DBG_CRITICAL, "Initialising ICMP pinger ...");

    icmp4_worker = icmp4.Open();
    if (icmp4_worker < 0) {
        debugs(42, DBG_CRITICAL, "ERROR: Unable to start ICMP pinger.");
    }
    max_fd = max(max_fd, icmp4_worker);

#if USE_IPV6
    icmp6_worker = icmp6.Open();
    if (icmp6_worker <0 ) {
        debugs(42, DBG_CRITICAL, "ERROR: Unable to start ICMPv6 pinger.");
    }
    max_fd = max(max_fd, icmp6_worker);
#endif

    /** abort if neither worker could open a socket. */
    if (icmp4_worker < 0 && icmp6_worker < 0) {
        debugs(42, DBG_CRITICAL, "FATAL: Unable to open any ICMP sockets.");
        exit(EXIT_FAILURE);
    }

    if ( (squid_link = control.Open()) < 0) {
        debugs(42, DBG_CRITICAL, "FATAL: Unable to setup Pinger control sockets.");
        icmp4.Close();
        icmp6.Close();
        exit(EXIT_FAILURE); // fatal error if the control channel fails.
    }
    max_fd = max(max_fd, squid_link);

    if (setgid(getgid()) < 0) {
        int xerrno = errno;
        debugs(42, DBG_CRITICAL, "FATAL: setgid(" << getgid() << ") failed: " << xstrerr(xerrno));
        icmp4.Close();
        icmp6.Close();
        exit(EXIT_FAILURE);
    }
    if (setuid(getuid()) < 0) {
        int xerrno = errno;
        debugs(42, DBG_CRITICAL, "FATAL: setuid(" << getuid() << ") failed: " << xstrerr(xerrno));
        icmp4.Close();
        icmp6.Close();
        exit(EXIT_FAILURE);
    }

#if HAVE_LIBCAP
    // Drop remaining capabilities (if installed as non-setuid setcap cap_net_raw=ep).
    // If pinger binary was installed setuid root, setuid() above already dropped all
    // capabilities, and this is no-op.
    cap_t caps;
    caps = cap_init();
    if (!caps) {
        int xerrno = errno;
        debugs(42, DBG_CRITICAL, "FATAL: cap_init() failed: " << xstrerr(xerrno));
        icmp4.Close();
        icmp6.Close();
        exit(EXIT_FAILURE);
    } else {
        if (cap_set_proc(caps) != 0) {
            int xerrno = errno;
            // cap_set_proc(cap_init()) is expected to never fail
            debugs(42, DBG_CRITICAL, "FATAL: cap_set_proc(none) failed: " << xstrerr(xerrno));
            cap_free(caps);
            icmp4.Close();
            icmp6.Close();
            exit(EXIT_FAILURE);
        }
        cap_free(caps);
    }
#endif

    for (;;) {
        struct timeval tv;
        tv.tv_sec = std::chrono::seconds(PingerTimeout).count();
        tv.tv_usec = 0;
        FD_ZERO(&R);
        if (icmp4_worker >= 0) {
            FD_SET(icmp4_worker, &R);
        }
        if (icmp6_worker >= 0) {
            FD_SET(icmp6_worker, &R);
        }

        FD_SET(squid_link, &R);
        Stopwatch timer;
        timer.resume();
        const auto x = xselect(max_fd+1, &R, nullptr, nullptr, &tv);
        getCurrentTime();

        if (x < 0) {
            int xerrno = errno;
            debugs(42, DBG_CRITICAL, "FATAL: select()==" << x << ", ERR: " << xstrerr(xerrno));
            control.Close();
            exit(EXIT_FAILURE);
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

        const auto delay = std::chrono::duration_cast<std::chrono::seconds>(timer.total());
        if (delay >= PingerTimeout) {
            if (xsend(LINK_TO_SQUID, &tv, 0, 0) < 0) {
                debugs(42, DBG_CRITICAL, "Closing. No requests in last " << delay.count() << " seconds.");
                control.Close();
                exit(EXIT_FAILURE);
            }
        }
    }

    /* NOTREACHED */
    return EXIT_SUCCESS;
}

#else /* !USE_ICMP */

#include <ostream>
int
main(int, char *argv[])
{
    std::cerr << argv[0] << ": ICMP support not compiled in." << std::endl;
    return EXIT_FAILURE;
}

#endif /* USE_ICMP */

