
/*
 * DEBUG: section 31    HTCP
 */

#include "squid.h"

typedef struct _Countstr Countstr;
typedef struct _htcpHeader htcpHeader;
typedef struct _htcpDataHeader htcpDataHeader;
typedef struct _htcpAuthHeader htcpAuthHeader;
typedef struct _htcpStuff htcpStuff;

struct _Countstr {
    u_short length;
    char *text;
};

struct _htcpHeader {
    u_short length;
    u_char major;
    u_char minor;
};

struct _htcpDataHeader {
    u_short length;
    u_char opcode:4;
    u_char response:4;
    u_char reserved:6;
    u_char F1:1;
    /* RR == 0 --> F1 = RESPONSE DESIRED FLAG */
    /* RR == 1 --> F1 = MESSAGE OVERALL FLAG */
    u_char RR:1;
    /* RR == 0 --> REQUEST */
    /* RR == 1 --> RESPONSE */
    u_num32 msg_id;
};

struct _htcpAuthHeader {
    u_short length;
    time_t sig_time;
    time_t sig_expire;
    Countstr key_name;
    Countstr signature;
};

struct _htcpStuff {
    int op;
    int rr;
    int f1;
    int response;
    const char *method;
    const char *uri;
    const char *version;
    const char *req_hdrs;
};

enum {
    HTCP_NOP,
    HTCP_TST,
    HTCP_MON,
    HTCP_SET,
    HTCP_CLR
};

/*
 * values for htcpDataHeader->response
 */
enum {
    AUTH_REQUIRED,
    AUTH_FAILURE,
    OPCODE_UNIMPLEMENTED,
    MAJOR_VERSION_UNSUPPORTED,
    MINOR_VERSION_UNSUPPORTED,
    INVALID_OPCODE
};

/*
 * values for htcpDataHeader->RR
 */
enum {
    RR_REQUEST,
    RR_RESPONSE
};

static u_num32 msg_id_counter = 0;
static int htcpInSocket = -1;
static int htcpOutSocket = -1;

ssize_t
htcpBuildAuth(char *buf, size_t buflen)
{
    htcpAuthHeader auth;
    size_t copy_sz = 0;
    assert(2 == sizeof(u_short));
    auth.length = htons(2);
    copy_sz += 2;
    assert(buflen >= copy_sz);
    xmemcpy(buf, &auth, copy_sz);
    return copy_sz;
}

ssize_t
htcpBuildCountstr(char *buf, size_t buflen, const char *s)
{
    u_short length;
    size_t len = strlen(s);
    off_t off = 0;
    if (buflen - off < 2)
	return -1;
    length = htons((u_short) len);
    xmemcpy(buf + off, &length, 2);
    off += 2;
    if (buflen - off < len)
	return -1;
    xmemcpy(buf + off, s, len);
    off += len;
    return off;
}


ssize_t
htcpBuildSpecifier(char *buf, size_t buflen, htcpStuff * stuff)
{
    ssize_t off = 0;
    ssize_t s;
    s = htcpBuildCountstr(buf + off, buflen - off, stuff->method);
    if (s < 0)
	return s;
    off += s;
    s = htcpBuildCountstr(buf + off, buflen - off, stuff->uri);
    if (s < 0)
	return s;
    off += s;
    s = htcpBuildCountstr(buf + off, buflen - off, stuff->version);
    if (s < 0)
	return s;
    off += s;
    s = htcpBuildCountstr(buf + off, buflen - off, stuff->req_hdrs);
    if (s < 0)
	return s;
    off += s;
    return off;
}

ssize_t
htcpBuildTstOpData(char *buf, size_t buflen, htcpStuff * stuff)
{
    return htcpBuildSpecifier(buf, buflen, stuff);
}

ssize_t
htcpBuildOpData(char *buf, size_t buflen, htcpStuff * stuff)
{
    ssize_t off = 0;
    switch (stuff->op) {
    case HTCP_TST:
	off = htcpBuildTstOpData(buf + off, buflen, stuff);
	break;
    default:
	assert(0);
	break;
    }
    return off;
}

ssize_t
htcpBuildData(char *buf, size_t buflen, htcpStuff * stuff)
{
    ssize_t off = 0;
    ssize_t op_data_sz;
    size_t hdr_sz = sizeof(htcpDataHeader);
    htcpDataHeader hdr;
    if (buflen < hdr_sz)
	return -1;
    off += hdr_sz;		/* skip! */
    op_data_sz = htcpBuildOpData(buf + off, buflen - off, stuff);
    if (op_data_sz < 0)
	return op_data_sz;
    off += op_data_sz;
    hdr.length = (u_short) off;
    hdr.opcode = stuff->op;
    hdr.response = stuff->response;
    hdr.RR = stuff->rr;
    hdr.F1 = stuff->f1;
    hdr.msg_id = ++msg_id_counter;
    /* convert multi-byte fields */
    hdr.length = htons(hdr.length);
    hdr.msg_id = htons(hdr.msg_id);
    xmemcpy(buf, &hdr, hdr_sz);
    return off;
}

char *
htcpBuildPacket(htcpStuff * stuff, ssize_t * len)
{
    size_t buflen = 8192;
    size_t s;
    ssize_t off = 0;
    size_t hdr_sz = sizeof(htcpHeader);
    htcpHeader hdr;
    char *buf = xcalloc(buflen, 1);
    /* skip the header -- we don't know the overall length */
    if (buflen < hdr_sz)
	return NULL;
    off += hdr_sz;
    s = htcpBuildData(buf + off, buflen - off, stuff);
    if (s < 0)
	return NULL;
    off += s;
    s = htcpBuildAuth(buf + off, buflen - off);
    if (s < 0)
	return NULL;
    off += s;
    hdr.length = (u_short) off;
    hdr.major = 0;
    hdr.minor = 0;
    xmemcpy(buf, &hdr, hdr_sz);
    *len = off;
    return buf;
}

void
htcpSend(const char *buf, int len, peer * p)
{
    int x;
    x = comm_udp_sendto(htcpOutSocket,
	&p->in_addr,
	sizeof(struct sockaddr_in),
	buf,
	len);
    if (x < 0)
	debug(31, 0) ("htcpSend: FD %d sendto: %s\n", htcpOutSocket, xstrerror());
}

void
htcpRecv(int fd, void *data)
{
    char buf[8192];
    int x;
    x = recv(fd, buf, 8192, 0);
    debug(31, 0) ("htcpRecv: FD %d, %d bytes\n", fd, x);
}

void
htcpQuery(StoreEntry * e, request_t * req, peer * p)
{
    char *pkt;
    ssize_t pktlen;
    int x;
    char vbuf[32];
    htcpStuff stuff;
    snprintf(vbuf, 32, "%3.1f", req->http_ver);
    stuff.op = HTCP_TST;
    stuff.rr = RR_REQUEST;
    stuff.f1 = 1;
    stuff.response = 0;
    stuff.method = RequestMethodStr[req->method];
    stuff.uri = storeUrl(e);
    stuff.version = vbuf;
    stuff.req_hdrs = req->headers;
    pkt = htcpBuildPacket(&stuff, &pktlen);
    if (pkt == NULL) {
	debug(31, 0) ("htcpQuery: htcpBuildPacket() failed\n");
	return;
    }
    htcpSend(pkt, (int) pktlen, p);
    xfree(pkt);
}

void
htcpInit(void)
{
    wordlist *s;
    enter_suid();
    htcpInSocket = comm_open(SOCK_DGRAM,
	0,
	Config.Addrs.udp_incoming,
	Config.Port.htcp,
	COMM_NONBLOCKING,
	"HTCP Socket");
    leave_suid();
    if (htcpInSocket < 0)
	fatal("Cannot open HTCP Socket");
    commSetSelect(htcpInSocket, COMM_SELECT_READ, htcpRecv, NULL, 0);
    for (s = Config.mcast_group_list; s; s = s->next)
	ipcache_nbgethostbyname(s->key, mcastJoinGroups, NULL);
    debug(12, 1) ("Accepting HTCP messages on port %d, FD %d.\n",
	(int) Config.Port.htcp, htcpInSocket);
    if (Config.Addrs.udp_outgoing.s_addr != no_addr.s_addr) {
	enter_suid();
	htcpOutSocket = comm_open(SOCK_DGRAM,
	    0,
	    Config.Addrs.udp_outgoing,
	    Config.Port.htcp,
	    COMM_NONBLOCKING,
	    "Outgoing HTCP Socket");
	leave_suid();
	if (htcpOutSocket < 0)
	    fatal("Cannot open Outgoing HTCP Socket");
	commSetSelect(htcpOutSocket, COMM_SELECT_READ, htcpRecv, NULL, 0);
	debug(12, 1) ("Outgoing HTCP messages on port %d, FD %d.\n",
	    (int) Config.Port.htcp, htcpOutSocket);
	fd_note(htcpInSocket, "Incoming HTCP socket");
    } else {
	htcpOutSocket = htcpInSocket;
    }
}
