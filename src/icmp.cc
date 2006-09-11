
/*
 * $Id: icmp.cc,v 1.89 2006/09/11 09:36:06 serassio Exp $
 *
 * DEBUG: section 37    ICMP Routines
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


#include "squid.h"
#include "comm.h"
#include "SquidTime.h"

#if USE_ICMP

#define S_ICMP_ECHO	1
#if ALLOW_SOURCE_PING
#define S_ICMP_ICP	2
#endif
#define S_ICMP_DOM	3

static PF icmpRecv;
static void icmpSend(pingerEchoData * pkt, int len);
#if ALLOW_SOURCE_PING

static void icmpHandleSourcePing(const struct sockaddr_in *from, const char *buf);
#endif

static void * hIpc;
static pid_t pid;

static void

icmpSendEcho(struct IN_ADDR to, int opcode, const char *payload, int len)
{
    static pingerEchoData pecho;

    if (payload && len == 0)
        len = strlen(payload);

    assert(len <= PINGER_PAYLOAD_SZ);

    pecho.to = to;

    pecho.opcode = (unsigned char) opcode;

    pecho.psize = len;

    xmemcpy(pecho.payload, payload, len);

    icmpSend(&pecho, sizeof(pingerEchoData) - PINGER_PAYLOAD_SZ + len);
}

static void
icmpRecv(int unused1, void *unused2)
{
    int n;
    static int fail_count = 0;
    pingerReplyData preply;

    static struct sockaddr_in F;
    commSetSelect(icmp_sock, COMM_SELECT_READ, icmpRecv, NULL, 0);
    memset(&preply, '\0', sizeof(pingerReplyData));
    n = comm_udp_recv(icmp_sock,
                      (char *) &preply,
                      sizeof(pingerReplyData),
                      0);

    if (n < 0 && EAGAIN != errno) {
        debug(37, 1) ("icmpRecv: recv: %s\n", xstrerror());

        if (errno == ECONNREFUSED)
            icmpClose();

        if (errno == ECONNRESET)
            icmpClose();

        if (++fail_count == 10)
            icmpClose();

        return;
    }

    fail_count = 0;

    if (n == 0)			/* test probe from pinger */
        return;

    F.sin_family = AF_INET;

    F.sin_addr = preply.from;

    F.sin_port = 0;

    switch (preply.opcode) {

    case S_ICMP_ECHO:
        break;
#if ALLOW_SOURCE_PING

    case S_ICMP_ICP:
        icmpHandleSourcePing(&F, preply.payload);
        break;
#endif

    case S_ICMP_DOM:
        netdbHandlePingReply(&F, preply.hops, preply.rtt);
        break;

    default:
        debug(37, 1) ("icmpRecv: Bad opcode: %d\n", (int) preply.opcode);
        break;
    }
}

static void
icmpSend(pingerEchoData * pkt, int len)
{
    int x;

    if (icmp_sock < 0)
        return;

    debug(37, 2) ("icmpSend: to %s, opcode %d, len %d\n",
                  inet_ntoa(pkt->to), (int) pkt->opcode, pkt->psize);

    x = comm_udp_send(icmp_sock, (char *) pkt, len, 0);

    if (x < 0) {
        debug(37, 1) ("icmpSend: send: %s\n", xstrerror());

        if (errno == ECONNREFUSED || errno == EPIPE) {
            icmpClose();
            return;
        }
    } else if (x != len) {
        debug(37, 1) ("icmpSend: Wrote %d of %d bytes\n", x, len);
    }
}

#if ALLOW_SOURCE_PING
static void

icmpHandleSourcePing(const struct sockaddr_in *from, const char *buf)
{
    const cache_key *key;
    icp_common_t header;
    const char *url;
    xmemcpy(&header, buf, sizeof(icp_common_t));
    url = buf + sizeof(icp_common_t);
    key = icpGetCacheKey(url, (int) header.reqnum);
    debug(37, 3) ("icmpHandleSourcePing: from %s, key '%s'\n",
                  inet_ntoa(from->sin_addr), storeKeyText(key));
    /* call neighborsUdpAck even if ping_status != PING_WAITING */
    neighborsUdpAck(key, &header, from);
}

#endif

#endif /* USE_ICMP */

#if ALLOW_SOURCE_PING
void

icmpSourcePing(struct IN_ADDR to, const icp_common_t * header, const char *url)
{
#if USE_ICMP
    char *payload;
    int len;
    int ulen;
    debug(37, 3) ("icmpSourcePing: '%s'\n", url);

    if ((ulen = strlen(url)) > MAX_URL)
        return;

    payload = memAllocate(MEM_8K_BUF);

    len = sizeof(icp_common_t);

    xmemcpy(payload, header, len);

    strcpy(payload + len, url);

    len += ulen + 1;

    icmpSendEcho(to, S_ICMP_ICP, payload, len);

    memFree(payload, MEM_8K_BUF);

#endif
}

#endif

void

icmpDomainPing(struct IN_ADDR to, const char *domain)
{
#if USE_ICMP
    debug(37, 3) ("icmpDomainPing: '%s'\n", domain);
    icmpSendEcho(to, S_ICMP_DOM, domain, 0);
#endif
}

void
icmpOpen(void)
{
#if USE_ICMP
    const char *args[2];
    int rfd;
    int wfd;
    args[0] = "(pinger)";
    args[1] = NULL;
    pid = ipcCreate(IPC_DGRAM,
                    Config.Program.pinger,
                    args,
                    "Pinger Socket",
                    &rfd,
                    &wfd,
                    &hIpc);

    if (pid < 0)
        return;

    assert(rfd == wfd);

    icmp_sock = rfd;

    fd_note(icmp_sock, "pinger");

    commSetSelect(icmp_sock, COMM_SELECT_READ, icmpRecv, NULL, 0);

    commSetTimeout(icmp_sock, -1, NULL, NULL);

    debug(37, 1) ("Pinger socket opened on FD %d\n", icmp_sock);

#ifdef _SQUID_MSWIN_

    debug(37, 4) ("Pinger handle: 0x%x, PID: %d\n", (unsigned)hIpc, pid);

#endif
#endif
}

void
icmpClose(void)
{
#if USE_ICMP

    if (icmp_sock < 0)
        return;

    debug(37, 1) ("Closing Pinger socket on FD %d\n", icmp_sock);

#ifdef _SQUID_MSWIN_

    send(icmp_sock, (const void *) "$shutdown\n", 10, 0);

#endif

    comm_close(icmp_sock);

#ifdef _SQUID_MSWIN_

    if (hIpc) {
        if (WaitForSingleObject(hIpc, 12000) != WAIT_OBJECT_0) {
            getCurrentTime();
            debug(37, 1)
            ("icmpClose: WARNING: (pinger,%ld) didn't exit in 12 seconds\n",
             (long int)pid);
        }

        CloseHandle(hIpc);
    }

#endif
    icmp_sock = -1;

#endif
}
