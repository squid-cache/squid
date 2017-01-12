/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 42    ICMP Pinger program */

#define SQUID_HELPER 1

#include "squid.h"

#if USE_ICMP

#include "Debug.h"
#include "Icmp4.h"
#include "Icmp6.h"
#include "IcmpPinger.h"
#include "SquidTime.h"

#include <cerrno>

IcmpPinger::IcmpPinger() : Icmp()
{
    // these start invalid. Setup properly in Open()
    socket_from_squid = -1;
    socket_to_squid = -1;
}

IcmpPinger::~IcmpPinger()
{
    Close();
}

#if _SQUID_WINDOWS_
void
Win32SockCleanup(void)
{
    WSACleanup();
    return;
}
#endif

int
IcmpPinger::Open(void)
{
#if _SQUID_WINDOWS_

    WSADATA wsaData;
    WSAPROTOCOL_INFO wpi;
    char buf[sizeof(wpi)];
    int x;

    struct sockaddr_in PS;
    int xerrno;

    WSAStartup(2, &wsaData);
    atexit(Win32SockCleanup);

    getCurrentTime();
    _db_init(NULL, "ALL,1");
    setmode(0, O_BINARY);
    setmode(1, O_BINARY);
    x = read(0, buf, sizeof(wpi));

    if (x < (int)sizeof(wpi)) {
        xerrno = errno;
        getCurrentTime();
        debugs(42, DBG_CRITICAL, MYNAME << " read: FD 0: " << xstrerr(xerrno));
        write(1, "ERR\n", 4);
        return -1;
    }

    memcpy(&wpi, buf, sizeof(wpi));

    write(1, "OK\n", 3);
    x = read(0, buf, sizeof(PS));

    if (x < (int)sizeof(PS)) {
        xerrno = errno;
        getCurrentTime();
        debugs(42, DBG_CRITICAL, MYNAME << " read: FD 0: " << xstrerr(xerrno));
        write(1, "ERR\n", 4);
        return -1;
    }

    memcpy(&PS, buf, sizeof(PS));

    icmp_sock = WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &wpi, 0, 0);

    if (icmp_sock == -1) {
        xerrno = errno;
        getCurrentTime();
        debugs(42, DBG_CRITICAL, MYNAME << "WSASocket: " << xstrerr(xerrno));
        write(1, "ERR\n", 4);
        return -1;
    }

    x = connect(icmp_sock, (struct sockaddr *) &PS, sizeof(PS));

    if (SOCKET_ERROR == x) {
        xerrno = errno;
        getCurrentTime();
        debugs(42, DBG_CRITICAL, MYNAME << "connect: " << xstrerr(xerrno));
        write(1, "ERR\n", 4);
        return -1;
    }

    write(1, "OK\n", 3);
    memset(buf, 0, sizeof(buf));
    x = recv(icmp_sock, (void *) buf, sizeof(buf), 0);

    if (x < 3) {
        xerrno = errno;
        debugs(42, DBG_CRITICAL, MYNAME << "recv: " << xstrerr(xerrno));
        return -1;
    }

    x = send(icmp_sock, (const void *) buf, strlen(buf), 0);
    xerrno = errno;

    if (x < 3 || strncmp("OK\n", buf, 3)) {
        debugs(42, DBG_CRITICAL, MYNAME << "recv: " << xstrerr(xerrno));
        return -1;
    }

    getCurrentTime();
    debugs(42, DBG_IMPORTANT, "pinger: Squid socket opened");

    /* windows uses a socket stream as a dual-direction channel */
    socket_to_squid = icmp_sock;
    socket_from_squid = icmp_sock;

    return icmp_sock;

#else /* !_SQUID_WINDOWS_ */

    /* non-windows apps use stdin/out pipes as the squid channel(s) */
    socket_from_squid = 0; // use STDIN macro ??
    socket_to_squid = 1; // use STDOUT macro ??
    return socket_to_squid;
#endif
}

void
IcmpPinger::Close(void)
{
#if _SQUID_WINDOWS_

    shutdown(icmp_sock, SD_BOTH);
    close(icmp_sock);
    icmp_sock = -1;
#endif

    /* also shutdown the helper engines */
    icmp4.Close();
    icmp6.Close();
}

void
IcmpPinger::Recv(void)
{
    static pingerEchoData pecho;
    int n;
    int guess_size;

    memset(&pecho, '\0', sizeof(pecho));
    n = recv(socket_from_squid, &pecho, sizeof(pecho), 0);

    if (n < 0) {
        debugs(42, DBG_IMPORTANT, "Pinger exiting.");
        Close();
        exit(1);
    }

    if (0 == n) {
        /* EOF indicator */
        debugs(42, DBG_CRITICAL, HERE << "EOF encountered. Pinger exiting.\n");
        errno = 0;
        Close();
        exit(1);
    }

    guess_size = n - (sizeof(pingerEchoData) - PINGER_PAYLOAD_SZ);

    if (guess_size != pecho.psize) {
        debugs(42, 2, HERE << "size mismatch, guess=" << guess_size << ", psize=" << pecho.psize);
        /* don't process this message, but keep running */
        return;
    }

    /* pass request for ICMPv6 handing */
    if (pecho.to.isIPv6()) {
        debugs(42, 2, HERE << " Pass " << pecho.to << " off to ICMPv6 module.");
        icmp6.SendEcho(pecho.to,
                       pecho.opcode,
                       pecho.payload,
                       pecho.psize);
    }

    /* pass the packet for ICMP handling */
    else if (pecho.to.isIPv4()) {
        debugs(42, 2, HERE << " Pass " << pecho.to << " off to ICMPv4 module.");
        icmp4.SendEcho(pecho.to,
                       pecho.opcode,
                       pecho.payload,
                       pecho.psize);
    } else {
        debugs(42, DBG_IMPORTANT, HERE << " IP has unknown Type. " << pecho.to );
    }
}

void
IcmpPinger::SendResult(pingerReplyData &preply, int len)
{
    debugs(42, 2, HERE << "return result to squid. len=" << len);

    if (send(socket_to_squid, &preply, len, 0) < 0) {
        int xerrno = errno;
        debugs(42, DBG_CRITICAL, "pinger: FATAL error on send: " << xstrerr(xerrno));
        Close();
        exit(1);
    }
}

#endif /* USE_ICMP */

