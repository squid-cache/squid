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

#include "squid.h"

#if USE_ICMP

#include "SquidTime.h"
#include "IcmpPinger.h"
#include "Icmp4.h"
#include "Icmp6.h"
#include "Debug.h"

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

#ifdef _SQUID_MSWIN_
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
#ifdef _SQUID_MSWIN_

    WSADATA wsaData;
    WSAPROTOCOL_INFO wpi;
    char buf[sizeof(wpi)];
    int x;

    struct sockaddr_in PS;

    WSAStartup(2, &wsaData);
    atexit(Win32SockCleanup);

    getCurrentTime();
    _db_init(NULL, "ALL,1");
    setmode(0, O_BINARY);
    setmode(1, O_BINARY);
    x = read(0, buf, sizeof(wpi));

    if (x < (int)sizeof(wpi)) {
        getCurrentTime();
        debugs(42, 0, HERE << "read: FD 0: " << xstrerror());
        write(1, "ERR\n", 4);
        return -1;
    }

    xmemcpy(&wpi, buf, sizeof(wpi));

    write(1, "OK\n", 3);
    x = read(0, buf, sizeof(PS));

    if (x < (int)sizeof(PS)) {
        getCurrentTime();
        debugs(42, 0, HERE << "read: FD 0: " << xstrerror());
        write(1, "ERR\n", 4);
        return -1;
    }

    xmemcpy(&PS, buf, sizeof(PS));

    icmp_sock = WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &wpi, 0, 0);

    if (icmp_sock == -1) {
        getCurrentTime();
        debugs(42, 0, HERE << "WSASocket: " << xstrerror());
        write(1, "ERR\n", 4);
        return -1;
    }

    x = connect(icmp_sock, (struct sockaddr *) &PS, sizeof(PS));

    if (SOCKET_ERROR == x) {
        getCurrentTime();
        debugs(42, 0, HERE << "connect: " << xstrerror());
        write(1, "ERR\n", 4);
        return -1;
    }

    write(1, "OK\n", 3);
    memset(buf, 0, sizeof(buf));
    x = recv(icmp_sock, (void *) buf, sizeof(buf), 0);

    if (x < 3) {
        debugs(42, 0, HERE << "recv: " << xstrerror());
        return -1;
    }

    x = send(icmp_sock, (const void *) buf, strlen(buf), 0);

    if (x < 3 || strncmp("OK\n", buf, 3)) {
        debugs(42, 0, HERE << "recv: " << xstrerror());
        return -1;
    }

    getCurrentTime();
    debugs(42, 1, "pinger: Squid socket opened");

    /* windows uses a socket stream as a dual-direction channel */
    socket_to_squid = icmp_sock;
    socket_from_squid = icmp_sock;

    return icmp_sock;

#else /* !_SQUID_MSWIN_ */

    /* non-windows apps use stdin/out pipes as the squid channel(s) */
    socket_from_squid = 0; // use STDIN macro ??
    socket_to_squid = 1; // use STDOUT macro ??
    return socket_to_squid;
#endif
}

void
IcmpPinger::Close(void)
{
#ifdef _SQUID_MSWIN_

    shutdown(icmp_sock, SD_BOTH);
    close(icmp_sock);
    icmp_sock = -1;
#endif

    /* also shutdown the helper engines */
    icmp4.Close();
#if USE_IPV6
    icmp6.Close();
#endif
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
        debugs(42, 1, "Pinger exiting.");
        Close();
        exit(1);
    }

    if (0 == n) {
        /* EOF indicator */
        debugs(42, 0, HERE << "EOF encountered. Pinger exiting.\n");
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

#if USE_IPV6
    /* pass request for ICMPv6 handing */
    if (pecho.to.IsIPv6()) {
        debugs(42, 2, HERE << " Pass " << pecho.to << " off to ICMPv6 module.");
        icmp6.SendEcho(pecho.to,
                       pecho.opcode,
                       pecho.payload,
                       pecho.psize);
    }
#endif

    /* pass the packet for ICMP handling */
    else if (pecho.to.IsIPv4()) {
        debugs(42, 2, HERE << " Pass " << pecho.to << " off to ICMPv4 module.");
        icmp4.SendEcho(pecho.to,
                       pecho.opcode,
                       pecho.payload,
                       pecho.psize);
    } else {
        debugs(42, 1, HERE << " IP has unknown Type. " << pecho.to );
    }
}

void
IcmpPinger::SendResult(pingerReplyData &preply, int len)
{
    debugs(42, 2, HERE << "return result to squid. len=" << len);

    if (send(socket_to_squid, &preply, len, 0) < 0) {
        debugs(42, 0, "pinger: FATAL error on send: " << xstrerror());
        Close();
        exit(1);
    }
}

#endif /* USE_ICMP */
