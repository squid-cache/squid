
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

#define S_ICMP_ECHO	1
#define S_ICMP_ICP	2
#define S_ICMP_DOM	3

typedef struct _icmpQueueData {
    struct sockaddr_in to;
    char *msg;
    int len;
    struct _icmpQueueData *next;
    void (*free) __P((void *));
} icmpQueueData;

#define MAX_PAYLOAD (8192 - sizeof(struct icmphdr) - sizeof (char) - sizeof(struct timeval) - 1)

typedef struct {
    struct timeval tv;
    unsigned char opcode;
    char payload[MAX_PAYLOAD];
} icmpEchoData;

static icmpQueueData *IcmpQueueHead = NULL;

int icmp_sock = -1;

static int icmp_ident = -1;
static int icmp_pkts_sent = 0;

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

static int in_cksum __P((unsigned short *ptr, int size));
static void icmpRecv __P((int, void *));
static void icmpQueueSend __P((struct in_addr,
	char *msg,
	int len,
	void          (*free) __P((void *))));
static void icmpSend __P((int fd, icmpQueueData * queue));
static void icmpLog __P((struct icmphdr * icmp,
	struct in_addr addr,
	int rtt,
	int hops));
static int ipHops __P((int ttl));
static void icmpProcessReply __P((struct sockaddr_in * from,
	struct icmphdr * icmp,
	int hops));
static void icmpHandleSourcePing __P((struct sockaddr_in * from, char *buf));

void
icmpOpen(void)
{
    struct protoent *proto = NULL;
    if ((proto = getprotobyname("icmp")) == 0) {
	debug(37, 0, "icmpOpen: unknown protocol: icmp\n");
	return;
    }
    enter_suid();
    icmp_sock = comm_open(SOCK_RAW,
	proto->p_proto,
	Config.Addrs.udp_outgoing,
	0,
	COMM_NONBLOCKING,
	"ICMP Socket");
    leave_suid();
    if (icmp_sock < 0) {
	debug(37, 0, "icmpOpen: icmp_sock: %s\n", xstrerror());
	return;
    }
    icmp_ident = getpid() & 0xffff;
    comm_set_select_handler(icmp_sock,
	COMM_SELECT_READ,
	(PF) icmpRecv,
	(void *) -1);
    debug(37, 0, "icmpOpen: icmp_sock opened on FD %d\n", icmp_sock);
}

void
icmpClose(void)
{
    comm_close(icmp_sock);
    icmp_sock = -1;
    icmp_ident = 0;
}

static void
icmpSendEcho(struct in_addr to, int opcode, char *payload, int len)
{
    char *pkt = NULL;
    struct icmphdr *icmp = NULL;
    icmpEchoData *echo;
    int icmp_pktsize = sizeof(struct icmphdr);
    pkt = get_free_8k_page();
    memset(pkt, '\0', 8192);
    icmp = (struct icmphdr *) pkt;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = icmp_ident;
    icmp->icmp_seq = icmp_pkts_sent++;
    echo = (icmpEchoData *) (icmp + 1);
    /* echo = (icmpEchoData *) (pkt + icmp_pktsize); */
    echo->opcode = (unsigned char) opcode;
    echo->tv = current_time;
    icmp_pktsize += sizeof(icmpEchoData) - MAX_PAYLOAD;
    if (payload) {
	if (len == 0)
	    len = strlen(payload);
	if (len > MAX_PAYLOAD)
	    len = MAX_PAYLOAD;
	memcpy(echo->payload, payload, len);
	icmp_pktsize += len;
    }
    icmp->icmp_cksum = in_cksum((u_short *) icmp, icmp_pktsize);
    icmpQueueSend(to, pkt, icmp_pktsize, put_free_8k_page);
}

static void
icmpProcessReply(struct sockaddr_in *from, struct icmphdr *icmp, int hops)
{
    int rtt;
    icmpEchoData *echo = (icmpEchoData *) (icmp + 1);
    rtt = tvSubMsec(echo->tv, current_time);
    icmpLog(icmp, from->sin_addr, rtt, hops);
    switch (echo->opcode) {
    case S_ICMP_ECHO:
	break;
    case S_ICMP_ICP:
	icmpHandleSourcePing(from, echo->payload);
	break;
    case S_ICMP_DOM:
	break;
    default:
	debug(37, 0, "icmpProcessReply: Bad opcode: %d\n", (int) echo->opcode);
	break;
    }
}

static void
icmpRecv(int unused1, void *unused2)
{
    int n;
    int fromlen;
    struct sockaddr_in from;
    int iphdrlen;
    struct iphdr *ip = NULL;
    register struct icmphdr *icmp = NULL;
    char *pkt = get_free_8k_page();
    int hops;

    comm_set_select_handler(icmp_sock,
	COMM_SELECT_READ,
	(PF) icmpRecv,
	(void *) -1);
    fromlen = sizeof(from);
    n = recvfrom(icmp_sock,
	pkt,
	8192,
	0,
	(struct sockaddr *) &from,
	&fromlen);
    debug(37, 9, "icmpRecv: %d bytes from %s\n", n, inet_ntoa(from.sin_addr));
    ip = (struct iphdr *) pkt;
    iphdrlen = ip->ip_hl << 2;
    icmp = (struct icmphdr *) (pkt + iphdrlen);
    if (icmp->icmp_type != ICMP_ECHOREPLY)
	return;
    if (icmp->icmp_id != icmp_ident)
	return;
    hops = ipHops(ip->ip_ttl);
    icmpProcessReply(&from, icmp, hops);
    put_free_8k_page(pkt);
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
icmpQueueSend(struct in_addr to,
    char *pkt,
    int len,
    void (*free) __P((void *)))
{
    icmpQueueData *q = NULL;
    icmpQueueData **H = NULL;
    debug(37, 3, "icmpQueueSend: Queueing %d bytes for %s\n", len, inet_ntoa(to));
    q = xcalloc(1, sizeof(icmpQueueData));
    q->to.sin_family = AF_INET;
    q->to.sin_addr = to;
    q->msg = pkt;
    q->len = len;
    q->free = free;
    for (H = &IcmpQueueHead; *H; H = &(*H)->next);
    *H = q;
    comm_set_select_handler(icmp_sock,
	COMM_SELECT_WRITE,
	(PF) icmpSend,
	(void *) IcmpQueueHead);
}

void
icmpSend(int fd, icmpQueueData * queue)
{
    int x;
    while ((queue = IcmpQueueHead)) {
	x = sendto(fd,
	    queue->msg,
	    queue->len,
	    0,
	    (struct sockaddr *) &queue->to,
	    sizeof(struct sockaddr_in));
	if (x < 0) {
	    if (errno == EWOULDBLOCK || errno == EAGAIN)
		break;		/* don't de-queue */
	    else
		debug(37, 0, "icmpSend: sendto: %s\n", xstrerror());
	} else if (x != queue->len) {
	    debug(37, 0, "icmpSend: Wrote %d of %d bytes\n", x, queue->len);
	}
	IcmpQueueHead = queue->next;
	icmpLog((struct icmphdr *) queue->msg, queue->to.sin_addr, 0, 0);
	if (queue->free)
	    queue->free(queue->msg);
	safe_free(queue);
    }
    /* Reinstate handler if needed */
    if (IcmpQueueHead) {
	comm_set_select_handler(fd,
	    COMM_SELECT_WRITE,
	    (PF) icmpSend,
	    (void *) IcmpQueueHead);
    } else {
	comm_set_select_handler(fd,
	    COMM_SELECT_WRITE,
	    NULL,
	    NULL);
    }
}

static void
icmpLog(struct icmphdr *icmp, struct in_addr addr, int rtt, int hops)
{
    debug(0, 0, "icmpLog: %9d.%06d %-16s %d %-15.15s %dms %d hops\n",
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

void
icmpPing(struct in_addr to)
{
    icmpSendEcho(to, S_ICMP_ECHO, NULL, 0);
}

void
icmpSourcePing(struct in_addr to, icp_common_t * header, char *url)
{
    char *payload;
    int len;
    int ulen;
    debug(37, 3, "icmpSourcePing: '%s'\n", url);
    if ((ulen = strlen(url)) > MAX_URL)
	return;
    payload = get_free_8k_page();
    len = sizeof(icp_common_t);
    memcpy(payload, header, len);
    strcpy(payload + len, url);
    len += ulen + 1;
    icmpSendEcho(to, S_ICMP_ICP, payload, len);
    put_free_8k_page(payload);
}

void
icmpDomainPing(struct in_addr to, char *domain)
{
    icmpSendEcho(to, S_ICMP_DOM, domain, 0);
}

static void
icmpHandleSourcePing(struct sockaddr_in *from, char *buf)
{
    char *key;
    StoreEntry *entry;
    icp_common_t header;
    char *url;
    memcpy(&header, buf, sizeof(icp_common_t));
    url = buf + sizeof(icp_common_t);
    if (neighbors_do_private_keys && header.reqnum) {
	key = storeGeneratePrivateKey(url, METHOD_GET, header.reqnum);
    } else {
	key = storeGeneratePublicKey(url, METHOD_GET);
    }
    debug(37, 3, "icmpHandleSourcePing: from %s, key=%s\n",
	inet_ntoa(from->sin_addr),
	key);
    if ((entry = storeGet(key)) == NULL)
	return;
    if (entry->lock_count == 0)
	return;
    /* call neighborsUdpAck even if ping_status != PING_WAITING */
    neighborsUdpAck(icmp_sock,
	url,
	&header,
	from,
	entry,
	NULL,
	0);
}
