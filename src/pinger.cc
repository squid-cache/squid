
/*
 * $Id: pinger.cc,v 1.9 1996/10/15 23:32:54 wessels Exp $
 *
 * DEBUG: section 37    ICMP Routines
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"
#include "pinger.h"

/* Junk so we can link with debug.o */
int opt_syslog_enable = 0;
volatile int unbuffered_logs = 1;
char w_space[] = " \t\n\r";
char appname[] = "pinger";
struct timeval current_time;
time_t squid_curtime;
struct SquidConfig Config;

#if USE_ICMP

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#ifndef _SQUID_LINUX_
#define icmphdr icmp
#define iphdr ip
#endif

#ifdef _SQUID_LINUX_
#define icmp_type type
#define icmp_code code
#define icmp_cksum checksum
#define icmp_id un.echo.id
#define icmp_seq un.echo.sequence
#define icmp_gwaddr un.gateway
#define ip_hl ihl
#define ip_v version
#define ip_tos tos
#define ip_len tot_len
#define ip_id id
#define ip_off frag_off
#define ip_ttl ttl
#define ip_p protocol
#define ip_sum check
#define ip_src saddr
#define ip_dst daddr
#endif

#define MAX_PAYLOAD (8192 - sizeof(struct icmphdr) - sizeof (char) - sizeof(struct timeval) - 1)

typedef struct {
    struct timeval tv;
    unsigned char opcode;
    char payload[MAX_PAYLOAD];
} icmpEchoData;

int icmp_sock = -1;
int icmp_ident = -1;
int icmp_pkts_sent = 0;

static char *icmpPktStr[] =
{
    "Echo Reply",
    "ICMP 1",
    "ICMP 2",
    "Destination Unreachable",
    "Source Quench",
    "Redirect",
    "ICMP 6",
    "ICMP 7",
    "Echo",
    "ICMP 9",
    "ICMP 10",
    "Time Exceeded",
    "Parameter Problem",
    "Timestamp",
    "Timestamp Reply",
    "Info Request",
    "Info Reply",
    "Out of Range Type"
};

static int in_cksum _PARAMS((unsigned short *ptr, int size));
static void pingerRecv _PARAMS((void));
static void pingerLog _PARAMS((struct icmphdr * icmp,
	struct in_addr addr,
	int rtt,
	int hops));
static int ipHops _PARAMS((int ttl));
static void pingerSendtoSquid _PARAMS((pingerReplyData * preply));

void
pingerOpen(void)
{
    struct protoent *proto = NULL;
    if ((proto = getprotobyname("icmp")) == 0) {
	debug(37, 0, "pingerOpen: unknown protocol: icmp\n");
	exit(1);
    }
    icmp_sock = socket(PF_INET, SOCK_RAW, proto->p_proto);
    if (icmp_sock < 0) {
	debug(37, 0, "pingerOpen: icmp_sock: %s\n", xstrerror());
	exit(1);
    }
    icmp_ident = getpid() & 0xffff;
    debug(37, 0, "ICMP socket opened\n", icmp_sock);
}

void
pingerClose(void)
{
    close(icmp_sock);
    icmp_sock = -1;
    icmp_ident = 0;
}

static void
pingerSendEcho(struct in_addr to, int opcode, char *payload, int len)
{
    LOCAL_ARRAY(char, pkt, 8192);
    struct icmphdr *icmp = NULL;
    icmpEchoData *echo;
    int icmp_pktsize = sizeof(struct icmphdr);
    int x;
    struct sockaddr_in S;
    memset(pkt, '\0', 8192);
    icmp = (struct icmphdr *) (void *) pkt;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = icmp_ident;
    icmp->icmp_seq = icmp_pkts_sent++;
    echo = (icmpEchoData *) (icmp + 1);
    echo->opcode = (unsigned char) opcode;
    echo->tv = current_time;
    icmp_pktsize += sizeof(icmpEchoData) - MAX_PAYLOAD;
    if (payload) {
	if (len > MAX_PAYLOAD)
	    len = MAX_PAYLOAD;
	xmemcpy(echo->payload, payload, len);
	icmp_pktsize += len;
    }
    icmp->icmp_cksum = in_cksum((u_short *) icmp, icmp_pktsize);
    S.sin_family = AF_INET;
    S.sin_addr = to;
    S.sin_port = 0;
    x = sendto(icmp_sock,
	pkt,
	icmp_pktsize,
	0,
	(struct sockaddr *) &S,
	sizeof(struct sockaddr_in));
    pingerLog(icmp, to, 0, 0);
}

static void
pingerRecv(void)
{
    int n;
    int fromlen;
    struct sockaddr_in from;
    int iphdrlen = 20;
    struct iphdr *ip = NULL;
    register struct icmphdr *icmp = NULL;
    LOCAL_ARRAY(char, pkt, 8192);
    struct timeval now;
    icmpEchoData *echo;
    static pingerReplyData preply;

    fromlen = sizeof(from);
    n = recvfrom(icmp_sock,
	pkt,
	8192,
	0,
	(struct sockaddr *) &from,
	&fromlen);
    gettimeofday(&now, NULL);
    debug(37, 9, "pingerRecv: %d bytes from %s\n", n, inet_ntoa(from.sin_addr));
    ip = (struct iphdr *) (void *) pkt;
#if HAVE_IP_HL
    iphdrlen = ip->ip_hl << 2;
#else /* HAVE_IP_HL */
#if BYTE_ORDER == BIG_ENDIAN
    iphdrlen = (ip->ip_vhl >> 4) << 2;
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
    iphdrlen = (ip->ip_vhl & 0xF) << 2;
#endif
#endif /* HAVE_IP_HL */
    icmp = (struct icmphdr *) (void *) (pkt + iphdrlen);
    if (icmp->icmp_type != ICMP_ECHOREPLY)
	return;
    if (icmp->icmp_id != icmp_ident)
	return;
    echo = (icmpEchoData *) (void *) (icmp + 1);
    preply.from = from.sin_addr;
    preply.opcode = echo->opcode;
    preply.hops = ipHops(ip->ip_ttl);
    preply.rtt = tvSubMsec(echo->tv, now);
    preply.psize = n - iphdrlen - (sizeof(icmpEchoData) - 8192);
    pingerSendtoSquid(&preply);
    pingerLog(icmp, from.sin_addr, preply.rtt, preply.hops);
}


static int
in_cksum(unsigned short *ptr, int size)
{
    register long sum;
    unsigned short oddbyte;
    register unsigned short answer;
    sum = 0;
    while (size > 1) {
	sum += *ptr++;
	size -= 2;
    }
    if (size == 1) {
	oddbyte = 0;
	*((unsigned char *) &oddbyte) = *(unsigned char *) ptr;
	sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

static void
pingerLog(struct icmphdr *icmp, struct in_addr addr, int rtt, int hops)
{
    debug(37, 2, "pingerLog: %9d.%06d %-16s %d %-15.15s %dms %d hops\n",
	(int) current_time.tv_sec,
	(int) current_time.tv_usec,
	inet_ntoa(addr),
	(int) icmp->icmp_type,
	icmpPktStr[icmp->icmp_type],
	rtt,
	hops);
}

static int
ipHops(int ttl)
{
    if (ttl < 32)
	return 32 - ttl;
    if (ttl < 64)
	return 62 - ttl;	/* 62 = (64+60)/2 */
    if (ttl < 128)
	return 128 - ttl;
    if (ttl < 192)
	return 192 - ttl;
    return 255 - ttl;
}

static int
pingerReadRequest(void)
{
    static pingerEchoData pecho;
    int n;
    int guess_size;
    memset((char *) &pecho, '\0', sizeof(pecho));
    n = recv(0, (char *) &pecho, sizeof(pecho), 0);
    if (n < 0) {
	perror("recv");
	return n;
    }
    guess_size = n - (sizeof(pingerEchoData) - 8192);
    if (guess_size != pecho.psize)
	fprintf(stderr, "size mismatch, guess=%d psize=%d\n",
	    guess_size, pecho.psize);
    pingerSendEcho(pecho.to,
	pecho.opcode,
	pecho.payload,
	pecho.psize);
    return n;
}

static void
pingerSendtoSquid(pingerReplyData * preply)
{
    int len = sizeof(pingerReplyData) - 8192 + preply->psize;
    if (send(1, preply, len, 0) < 0) {
	debug(37, 0, "pinger: send: %s\n", xstrerror());
	exit(1);
    }
}

time_t
getCurrentTime(void)
{
#if GETTIMEOFDAY_NO_TZP
    gettimeofday(&current_time);
#else
    gettimeofday(&current_time, NULL);
#endif
    return squid_curtime = current_time.tv_sec;
}


int
main(int argc, char *argv[])
{
    fd_set R;
    int x;
    struct timeval tv;
    char *debug_args = "ALL,1";
    char *t;
    time_t last_check_time = 0;

    if ((t = getenv("SQUID_DEBUG")))
	debug_args = xstrdup(t);
    getCurrentTime();
    _db_init(NULL, debug_args);

    pingerOpen();
    for (;;) {
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	FD_ZERO(&R);
	FD_SET(0, &R);
	FD_SET(icmp_sock, &R);
	x = select(icmp_sock + 1, &R, NULL, NULL, &tv);
	getCurrentTime();
	if (x < 0)
	    return 1;
	if (FD_ISSET(0, &R))
	    if (pingerReadRequest() < 0)
		return 1;
	if (FD_ISSET(icmp_sock, &R))
	    pingerRecv();
	if (10 + last_check_time > squid_curtime) {
	    if (send(1, &tv, 0, 0) < 0)
		return 1;
	    last_check_time = squid_curtime;
	}
    }
    /* NOTREACHED */
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
