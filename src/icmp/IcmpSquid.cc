/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 37    ICMP Routines */

#include "squid.h"
#include "comm.h"
#include "comm/Loops.h"
#include "compat/socket.h"
#include "defines.h"
#include "fd.h"
#include "icmp/IcmpConfig.h"
#include "icmp/IcmpSquid.h"
#include "icmp/net_db.h"
#include "ip/tools.h"
#include "SquidConfig.h"
#include "SquidIpc.h"

#include <cerrno>

// Instance global to be available in main() and elsewhere.
IcmpSquid icmpEngine;

#if USE_ICMP

#define S_ICMP_ECHO     1
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
IcmpSquid::SendEcho(Ip::Address &to, int opcode, const char *payload, int len)
{
    static pingerEchoData pecho;
    int x, slen;

    /** \li Does nothing if the pinger socket is not available. */
    if (icmp_sock < 0) {
        debugs(37, 2, " Socket Closed. Aborted send to " << pecho.to << ", opcode " << opcode << ", len " << pecho.psize);
        return;
    }

    /** \li  If no payload is given or is set as NULL it will ignore payload and len */
    if (!payload)
        len = 0;

    /** \li Otherwise if len is 0, uses strlen() to detect length of payload.
     * XXX: This will result in part of the payload being truncated if it contains a NUL character.
     *      Or it may result in a buffer over-read if the payload is not NUL-terminated properly.
     */
    else if (payload && len == 0)
        len = strlen(payload);

    // XXX: If length specified or auto-detected is greater than the possible payload squid will die with an assert.
    // TODO: This should perhapse be reduced to a truncated payload? or no payload. A WARNING is due anyway.
    assert(len <= PINGER_PAYLOAD_SZ);

    pecho.to = to;

    pecho.opcode = (unsigned char) opcode;

    pecho.psize = len;

    if (len > 0)
        memcpy(pecho.payload, payload, len);

    slen = sizeof(pingerEchoData) - PINGER_PAYLOAD_SZ + pecho.psize;

    debugs(37, 2, "to " << pecho.to << ", opcode " << opcode << ", len " << pecho.psize);

    x = comm_udp_send(icmp_sock, (char *)&pecho, slen, 0);

    if (x < 0) {
        int xerrno = errno;
        debugs(37, DBG_IMPORTANT, MYNAME << "send: " << xstrerr(xerrno));

        /** \li  If the send results in ECONNREFUSED or EPIPE errors from helper, will cleanly shutdown the module. */
        // TODO: try restarting the helper a few times before giving up?
        if (xerrno == ECONNREFUSED || xerrno == EPIPE) {
            Close();
            return;
        }
        /** All other send errors are ignored. */
    } else if (x != slen) {
        debugs(37, DBG_IMPORTANT, "Wrote " << x << " of " << slen << " bytes");
    }
}

// static Callback to wrap the squid-side ICMP handler.
// the IcmpSquid::Recv cannot be declared both static and virtual.
static void
icmpSquidRecv(int, void *)
{
    icmpEngine.Recv();
}

void
IcmpSquid::Recv()
{
    int n;
    static int fail_count = 0;
    pingerReplyData preply;
    static Ip::Address F;

    Comm::SetSelect(icmp_sock, COMM_SELECT_READ, icmpSquidRecv, nullptr, 0);
    n = comm_udp_recv(icmp_sock,
                      (char *) &preply,
                      sizeof(pingerReplyData),
                      0);

    if (n < 0 && EAGAIN != errno) {
        int xerrno = errno;
        debugs(37, DBG_IMPORTANT, MYNAME << "recv: " << xstrerr(xerrno));

        if (xerrno == ECONNREFUSED)
            Close();

        if (xerrno == ECONNRESET)
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

    F.port(0);

    switch (preply.opcode) {

    case S_ICMP_ECHO:
        debugs(37,4, " ICMP_ECHO of " << preply.from << " gave: hops=" << preply.hops <<", rtt=" << preply.rtt);
        break;

    case S_ICMP_DOM:
        debugs(37,4, " DomainPing of " << preply.from << " gave: hops=" << preply.hops <<", rtt=" << preply.rtt);
        netdbHandlePingReply(F, preply.hops, preply.rtt);
        break;

    default:
        debugs(37, DBG_IMPORTANT, "ERROR: Bad opcode: " << preply.opcode << " from " << F);
        break;
    }
}

#endif /* USE_ICMP */

void
IcmpSquid::DomainPing(Ip::Address &to, const char *domain)
{
#if USE_ICMP
    debugs(37, 4, "'" << domain << "' (" << to << ")");
    SendEcho(to, S_ICMP_DOM, domain, 0);
#else
    (void)to;
    (void)domain;
#endif
}

int
IcmpSquid::Open(void)
{
#if USE_ICMP
    const char *args[2];
    int rfd;
    int wfd;
    Ip::Address localhost;

    /* User configured disabled. */
    if (!IcmpCfg.enable) {
        Close();
        return -1;
    }

    args[0] = "(pinger)";
    args[1] = nullptr;
    localhost.setLocalhost();

    /*
     * Do NOT use IPC_DGRAM (=IPC_UNIX_DGRAM) here because you can't
     * send() more than 4096 bytes on a socketpair() socket (at
     * least on FreeBSD).
     */
    pid = ipcCreate(IPC_UDP_SOCKET,
                    IcmpCfg.program.c_str(),
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

    Comm::SetSelect(icmp_sock, COMM_SELECT_READ, icmpSquidRecv, nullptr, 0);

    commUnsetFdTimeout(icmp_sock);

    debugs(37, DBG_IMPORTANT, "Pinger socket opened on FD " << icmp_sock);

    /* Tests the pinger immediately using localhost */
    if (Ip::EnableIpv6)
        SendEcho(localhost, S_ICMP_ECHO, "ip6-localhost");
    if (localhost.setIPv4())
        SendEcho(localhost, S_ICMP_ECHO, "localhost");

#if _SQUID_WINDOWS_

    debugs(37, 4, "Pinger handle: 0x" << std::hex << hIpc << std::dec << ", PID: " << pid);

#endif /* _SQUID_WINDOWS_ */
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

    debugs(37, DBG_IMPORTANT, "Closing Pinger socket on FD " << icmp_sock);

#if _SQUID_WINDOWS_

    xsend(icmp_sock, (const void *) "$shutdown\n", 10, 0);

#endif

    comm_close(icmp_sock);

#if _SQUID_WINDOWS_

    if (hIpc) {
        if (WaitForSingleObject(hIpc, 12000) != WAIT_OBJECT_0) {
            getCurrentTime();
            debugs(37, DBG_CRITICAL, "WARNING: (pinger," << pid << ") didn't exit in 12 seconds");
        }

        CloseHandle(hIpc);
    }

#endif
    icmp_sock = -1;

#endif
}

