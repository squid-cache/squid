/*
 * $Id$
 *
 * DEBUG: section 37    ICMP Routines
 * AUTHOR: Duane Wessels, Amos Jeffries
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
#include "icmp/IcmpSquid.h"
#include "icmp/net_db.h"
#include "ip/tools.h"
#include "comm.h"
#include "SquidTime.h"

// Instance global to be available in main() and elsewhere.
IcmpSquid icmpEngine;

#if USE_ICMP

#define S_ICMP_ECHO     1
#if DEAD_CODE
#define S_ICMP_ICP      2
#endif
#define S_ICMP_DOM      3

static void * hIpc;
static pid_t pid;

#endif /* USE_ICMP */


IcmpSquid::IcmpSquid() : Icmp()
{
    ; // nothing new.
}

IcmpSquid::~IcmpSquid()
{
    Close();
}


#if USE_ICMP

void
IcmpSquid::SendEcho(IpAddress &to, int opcode, const char *payload, int len)
{
    static pingerEchoData pecho;
    int x, slen;

    /** \li Does nothing if the pinger socket is not available. */
    if (icmp_sock < 0) {
        debugs(37, 2, HERE << " Socket Closed. Aborted send to " << pecho.to << ", opcode " << opcode << ", len " << pecho.psize);
        return;
    }

    /** \li  If no payload is given or is set as NULL it will ignore payload and len */
    if (!payload)
        len = 0;

    /** \li Otherwise if len is 0, uses strlen() to detect length of payload.
     \bug This will result in part of the payload being truncated if it contains a NULL character.
     \bug Or it may result in a buffer over-run if the payload is not nul-terminated properly.
     */
    else if (payload && len == 0)
        len = strlen(payload);

    /** \li
     \bug If length specified or auto-detected is greater than the possible payload squid will die with an assert.
     \todo This should perhapse be reduced to a truncated payload? or no payload. A WARNING is due anyway.
     */
    assert(len <= PINGER_PAYLOAD_SZ);

    pecho.to = to;

    pecho.opcode = (unsigned char) opcode;

    pecho.psize = len;

    if (len > 0)
        xmemcpy(pecho.payload, payload, len);

    slen = sizeof(pingerEchoData) - PINGER_PAYLOAD_SZ + pecho.psize;

    debugs(37, 2, HERE << "to " << pecho.to << ", opcode " << opcode << ", len " << pecho.psize);

    x = comm_udp_send(icmp_sock, (char *)&pecho, slen, 0);

    if (x < 0) {
        debugs(37, 1, HERE << "send: " << xstrerror());

        /** \li  If the send results in ECONNREFUSED or EPIPE errors from helper, will cleanly shutdown the module. */
        /** \todo This should try restarting the helper a few times?? before giving up? */
        if (errno == ECONNREFUSED || errno == EPIPE) {
            Close();
            return;
        }
        /** All other send errors are ignored. */
    } else if (x != slen) {
        debugs(37, 1, HERE << "Wrote " << x << " of " << slen << " bytes");
    }
}

// static Callback to wrap the squid-side ICMP handler.
// the IcmpSquid::Recv cannot be declared both static and virtual.
static void
icmpSquidRecv(int unused1, void *unused2)
{
    icmpEngine.Recv();
}

void
IcmpSquid::Recv()
{
    int n;
    static int fail_count = 0;
    pingerReplyData preply;
    static IpAddress F;

    commSetSelect(icmp_sock, COMM_SELECT_READ, icmpSquidRecv, NULL, 0);
    memset(&preply, '\0', sizeof(pingerReplyData));
    n = comm_udp_recv(icmp_sock,
                      (char *) &preply,
                      sizeof(pingerReplyData),
                      0);

    if (n < 0 && EAGAIN != errno) {
        debugs(37, 1, HERE << "recv: " << xstrerror());

        if (errno == ECONNREFUSED)
            Close();

        if (errno == ECONNRESET)
            Close();

        if (++fail_count == 10)
            Close();

        return;
    }

    fail_count = 0;

    /** If its a test probe from the pinger. Do nothing. */
    if (n == 0) {
        return;
    }

    F = preply.from;

    F.SetPort(0);

    switch (preply.opcode) {

    case S_ICMP_ECHO:
        debugs(37,4, HERE << " ICMP_ECHO of " << preply.from << " gave: hops=" << preply.hops <<", rtt=" << preply.rtt);
        break;

    case S_ICMP_DOM:
        debugs(37,4, HERE << " DomainPing of " << preply.from << " gave: hops=" << preply.hops <<", rtt=" << preply.rtt);
        netdbHandlePingReply(F, preply.hops, preply.rtt);
        break;

    default:
        debugs(37, 1, HERE << "Bad opcode: " << preply.opcode << " from " << F);
        break;
    }
}

#endif /* USE_ICMP */

void
IcmpSquid::DomainPing(IpAddress &to, const char *domain)
{
#if USE_ICMP
    debugs(37, 4, HERE << "'" << domain << "' (" << to << ")");
    SendEcho(to, S_ICMP_DOM, domain, 0);
#endif
}

int
IcmpSquid::Open(void)
{
#if USE_ICMP
    const char *args[2];
    int rfd;
    int wfd;
    IpAddress localhost;

    /* User configured disabled. */
    if (!Config.pinger.enable) {
        Close();
        return -1;
    }

    args[0] = "(pinger)";
    args[1] = NULL;
    localhost.SetLocalhost();

    /*
     * Do NOT use IPC_DGRAM (=IPC_UNIX_DGRAM) here because you can't
     * send() more than 4096 bytes on a socketpair() socket (at
     * least on FreeBSD).
     */
    pid = ipcCreate(IPC_UDP_SOCKET,
                    Config.pinger.program,
                    args,
                    "Pinger Socket",
                    localhost,
                    &rfd,
                    &wfd,
                    &hIpc);

    if (pid < 0)
        return -1;

    assert(rfd == wfd);

    icmp_sock = rfd;

    fd_note(icmp_sock, "pinger");

    commSetSelect(icmp_sock, COMM_SELECT_READ, icmpSquidRecv, NULL, 0);

    commSetTimeout(icmp_sock, -1, NULL, NULL);

    debugs(37, 1, HERE << "Pinger socket opened on FD " << icmp_sock);

    /* Tests the pinger immediately using localhost */
    if (Ip::EnableIpv6)
        SendEcho(localhost, S_ICMP_ECHO, "ip6-localhost");
    if (localhost.SetIPv4())
        SendEcho(localhost, S_ICMP_ECHO, "localhost");

#ifdef _SQUID_MSWIN_

    debugs(37, 4, HERE << "Pinger handle: 0x" << std::hex << hIpc << std::dec << ", PID: " << pid);

#endif /* _SQUID_MSWIN_ */
    return icmp_sock;
#else /* USE_ICMP */
    return -1;
#endif /* USE_ICMP */
}

void
IcmpSquid::Close(void)
{
#if USE_ICMP

    if (icmp_sock < 0)
        return;

    debugs(37, 1, HERE << "Closing Pinger socket on FD " << icmp_sock);

#ifdef _SQUID_MSWIN_

    send(icmp_sock, (const void *) "$shutdown\n", 10, 0);

#endif

    comm_close(icmp_sock);

#ifdef _SQUID_MSWIN_

    if (hIpc) {
        if (WaitForSingleObject(hIpc, 12000) != WAIT_OBJECT_0) {
            getCurrentTime();
            debugs(37, 0, HERE << "WARNING: (pinger," << pid << ") didn't exit in 12 seconds");
        }

        CloseHandle(hIpc);
    }

#endif
    icmp_sock = -1;

#endif
}
