/*
 * $Id$
 *
 * DEBUG: section 42    ICMP Pinger program
 * AUTHOR: Duane Wessels
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
#include "SquidTime.h"

#if USE_ICMP

#include "Icmp4.h"
#include "Icmp6.h"
#include "IcmpPinger.h"

#ifdef _SQUID_MSWIN_

#if HAVE_WINSOCK2_H
#include <winsock2.h>
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
#define LINK_TO_SQUID	1

#endif	/* _SQUID_MSWIN_ */

// ICMP Engines are declared global here so they can call each other easily.
IcmpPinger control;
Icmp4 icmp4;
#if USE_IPV6
Icmp6 icmp6;
#endif

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
#if USE_IPV6
    int icmp6_worker = -1;
#endif
    int squid_link = -1;

    /** start by initializing the pinger debug cache.log-pinger. */
    if ((t = getenv("SQUID_DEBUG")))
        debug_args = xstrdup(t);

    getCurrentTime();

    _db_init(NULL, debug_args);

    debugs(42, 0, "pinger: Initialising ICMP pinger ...");

    icmp4_worker = icmp4.Open();
    if (icmp4_worker < 0) {
        debugs(42, 0, "pinger: Unable to start ICMP pinger.");
    }
    max_fd = max(max_fd, icmp4_worker);

#if USE_IPV6
    icmp6_worker = icmp6.Open();
    if (icmp6_worker <0 ) {
        debugs(42, 0, "pinger: Unable to start ICMPv6 pinger.");
    }
    max_fd = max(max_fd, icmp6_worker);
#endif

    /** abort if neither worker could open a socket. */
    if (icmp4_worker == -1) {
#if USE_IPV6
        if (icmp6_worker == -1)
#endif
        {
            debugs(42, 0, "FATAL: pinger: Unable to open any ICMP sockets.");
            exit(1);
        }
    }

    if ( (squid_link = control.Open()) < 0) {
        debugs(42, 0, "FATAL: pinger: Unable to setup Pinger control sockets.");
        icmp4.Close();
#if USE_IPV6
        icmp6.Close();
#endif
        exit(1); // fatal error if the control channel fails.
    }
    max_fd = max(max_fd, squid_link);

    setgid(getgid());
    setuid(getuid());

    last_check_time = squid_curtime;

    for (;;) {
        tv.tv_sec = PINGER_TIMEOUT;
        tv.tv_usec = 0;
        FD_ZERO(&R);
        if (icmp4_worker >= 0) {
            FD_SET(icmp4_worker, &R);
        }
#if USE_IPV6

        if (icmp6_worker >= 0) {
            FD_SET(icmp6_worker, &R);
        }
#endif
        FD_SET(squid_link, &R);
        x = select(10, &R, NULL, NULL, &tv);
        getCurrentTime();

        if (x < 0) {
            debugs(42, 0, HERE << " FATAL Shutdown. select()==" << x << ", ERR: " << xstrerror());
            control.Close();
            exit(1);
        }

        if (FD_ISSET(squid_link, &R)) {
            control.Recv();
        }

#if USE_IPV6
        if (icmp6_worker >= 0 && FD_ISSET(icmp6_worker, &R)) {
            icmp6.Recv();
        }
#endif

        if (icmp4_worker >= 0 && FD_ISSET(icmp4_worker, &R)) {
            icmp4.Recv();
        }

        if (PINGER_TIMEOUT + last_check_time < squid_curtime) {
            if (send(LINK_TO_SQUID, &tv, 0, 0) < 0) {
                debugs(42, 0, "pinger: Closing. No requests in last " << PINGER_TIMEOUT << " seconds.");
                control.Close();
                exit(1);
            }

            last_check_time = squid_curtime;
        }
    }

    /* NOTREACHED */
    return 0;
}

#else
#include <stdio.h>
int
main(int argc, char *argv[])
{
    fprintf(stderr, "%s: ICMP support not compiled in.\n", argv[0]);
    return 1;
}

#endif /* USE_ICMP */
