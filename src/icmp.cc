
#include "squid.h"

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

int icmp_sock = -1;

static int icmp_ident = -1;
static int icmp_pkts_sent = 0;

static int in_cksum __P((unsigned short *ptr, int size));

void
icmpOpen(void)
{
    struct protoent *proto = NULL;
    if ((proto = getprotobyname("icmp")) == 0) {
	debug(37, 0, "icmpOpen: unknown protocol: icmp\n");
	return;
    }
    enter_suid();
    if ((icmp_sock = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) {
	debug(37, 0, "icmpOpen: icmp_sock: %s\n", xstrerror());
	return;
    }
    leave_suid();
    icmp_ident = getpid() & 0xffff;
    debug(37, 0, "icmpOpen: icmp_sock opened on FD %d\n", icmp_sock);
}

void 
icmpClose(void)
{
    comm_close(icmp_sock);
    icmp_sock = -1;
    icmp_ident = 0;
}

void
icmpSendEcho(struct in_addr to, char *payload, int len)
{
    char *pkt = NULL;
    struct icmphdr *icp = NULL;
    struct timeval *tv;
    int icmp_pktsize = sizeof(struct icmphdr) + sizeof(struct timeval);
    int i;
    pkt = get_free_8k_page();
    memset(pkt, '\0', 8192);
    icp = (struct icmphdr *) pkt;
    icp->icmp_type = ICMP_ECHO;
    icp->icmp_code = 0;
    icp->icmp_cksum = 0;
    icp->icmp_id = icmp_ident;
    icp->icmp_seq = icmp_pkts_sent++;
    tv = (struct timeval *) (pkt + sizeof(struct icmphdr));
    *tv = current_time;
    if (payload) {
	if (len > (8192 - icmp_pktsize))
	    len = 8192 - icmp_pktsize;
	memcpy(pkt + icmp_pktsize, payload, len);
	icmp_pktsize += len;
    }
    icp->icmp_cksum = in_cksum((u_short *) icp, icmp_pktsize);
    i = sendto(icmp_sock, pkt, icmp_pktsize, 0,
	(struct sockaddr *) &to, sizeof(struct sockaddr_in));
    if (i < 0)
	debug(37, 0, "icmpSendEcho: sendto: %s\n", xstrerror());
    else if (i != icmp_pktsize)
	debug(37, 0, "icmpSendEcho: Only wrote %d of %d bytes\n",
	    i, icmp_pktsize);
}

void 
icmpRecv(void)
{
}


int 
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
