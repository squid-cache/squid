
/*
 * DEBUG: section 31    HTCP
 */

#include "squid.h"

typedef struct _Countstr Countstr;
typedef struct _htcpHeader htcpHeader;
typedef struct _htcpDataHeader htcpDataHeader;
typedef struct _htcpAuthHeader htcpAuthHeader;
typedef struct _htcpStuff htcpStuff;
typedef struct _htcpSpecifier htcpSpecifier;

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
#if !WORDS_BIGENDIAN
    u_char opcode:4;
    u_char response:4;
#else
    u_char response:4;
    u_char opcode:4;
#endif
#if !WORDS_BIGENDIAN
    u_char reserved:6;
    u_char F1:1;
    u_char RR:1;
#else
    u_char RR:1;
    u_char F1:1;
    u_char reserved:6;
#endif
    u_num32 msg_id;
};

    /* RR == 0 --> F1 = RESPONSE DESIRED FLAG */
    /* RR == 1 --> F1 = MESSAGE OVERALL FLAG */
    /* RR == 0 --> REQUEST */
    /* RR == 1 --> RESPONSE */

struct _htcpAuthHeader {
    u_short length;
    time_t sig_time;
    time_t sig_expire;
    Countstr key_name;
    Countstr signature;
};

struct _htcpSpecifier {
    char *method;
    char *uri;
    char *version;
    char *req_hdrs;
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
    HTCP_CLR,
    HTCP_END
};

static const char *const htcpOpcodeStr[] = {
	"HTCP_NOP",
	"HTCP_TST",
	"HTCP_MON",
	"HTCP_SET",
	"HTCP_CLR",
	"HTCP_END"
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

/*
 * STUFF FOR SENDING HTCP MESSAGES
 */

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
    hdr.msg_id = htonl(hdr.msg_id);
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
    hdr.length = htons((u_short)off);
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
htcpQuery(StoreEntry * e, request_t * req, peer * p)
{
    char *pkt;
    ssize_t pktlen;
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

/*
 * STUFF FOR RECEIVING HTCP MESSAGES
 */

static void
htcpFreeSpecifier(htcpSpecifier * s)
{
    safe_free(s->method);
    safe_free(s->uri);
    safe_free(s->version);
    safe_free(s->req_hdrs);
    xfree(s);
}

int
htcpUnpackCountstr(char *buf, int sz, char **str)
{
	u_short l;
	debug(31,1)("htcpUnpackCountstr: sz = %d\n", sz);
	if (sz < 2) {
	    debug(31,1)("htcpUnpackCountstr: sz < 2\n");
	    return -1;
	}
	xmemcpy(&l, buf, 2);
	l = ntohl(l);
	buf += 2;
	sz -= 2;
	debug(31,1)("htcpUnpackCountstr: LENGTH = %d\n", (int) l);
	if (sz < l) {
	    debug(31,1)("htcpUnpackCountstr: sz(%d) < l(%d)\n", sz, l);
	    return -1;
	}
	if (str) {
		*str = xmalloc(l+1);
		xstrncpy(*str, buf, l+1);
		debug(31,1)("htcpUnpackCountstr: TEXT = %s\n", *str);
	}
	return (int)l+2;
}


htcpSpecifier *
htcpUnpackSpecifier(char *buf, int sz)
{
	htcpSpecifier *s = xcalloc(1, sizeof(htcpSpecifier));
	int o;

	o = htcpUnpackCountstr(buf, sz, &s->method);
	if (o < 0) {
		debug(31,1)("htcpUnpackSpecifier: failed to unpack METHOD\n");
		htcpFreeSpecifier(s);
		return NULL;
	}
	buf += o;
	sz -= o;

	o = htcpUnpackCountstr(buf, sz, &s->uri);
	if (o < 0) {
		debug(31,1)("htcpUnpackSpecifier: failed to unpack URI\n");
		htcpFreeSpecifier(s);
		return NULL;
	}
	buf += o;
	sz -= o;

	o = htcpUnpackCountstr(buf, sz, &s->version);
	if (o < 0) {
		debug(31,1)("htcpUnpackSpecifier: failed to unpack VERSION\n");
		htcpFreeSpecifier(s);
		return NULL;
	}
	buf += o;
	sz -= o;

	o = htcpUnpackCountstr(buf, sz, &s->req_hdrs);
	if (o < 0) {
		debug(31,1)("htcpUnpackSpecifier: failed to unpack REQ-HDRS\n");
		htcpFreeSpecifier(s);
		return NULL;
	}
	buf += o;
	sz -= o;

	return s;
}

static void
htcpHandleNop(char *buf, int sz, struct sockaddr_in *from)
{
	debug(31,1)("htcpHandleNop: Unimplemented\n");
}

static void
htcpHandleTst(char *buf, int sz, struct sockaddr_in *from)
{
	/* buf should be a SPECIFIER */
	htcpSpecifier *s = htcpUnpackSpecifier(buf, sz);
	if (NULL == s) {
		debug(31,1)("htcpHandleTst: htcpUnpackSpecifier failed\n");
		return;
	}
	debug(31,1)("htcpHandleTst: %s %s %s\n",
		s->method,
		s->uri,
		s->version);
	debug(31,1)("htcpHandleTst: %s\n", s->req_hdrs);
}

static void
htcpHandleMon(char *buf, int sz, struct sockaddr_in *from)
{
	debug(31,1)("htcpHandleMon: Unimplemented\n");
}

static void
htcpHandleSet(char *buf, int sz, struct sockaddr_in *from)
{
	debug(31,1)("htcpHandleSet: Unimplemented\n");
}

static void
htcpHandleData(char *buf, int sz, struct sockaddr_in *from)
{
    htcpDataHeader hdr;
    if (sz < sizeof(htcpDataHeader)) {
	debug(31,0)("htcpHandleData: msg size less than htcpDataHeader size\n");
	return;
    }
    xmemcpy(&hdr, buf, sizeof(htcpDataHeader));
    hdr.length = ntohs(hdr.length);
    hdr.msg_id = ntohs(hdr.msg_id);
    debug(31,1)("htcpHandleData: length = %d\n", (int) hdr.length);
    if (hdr.opcode < HTCP_NOP || hdr.opcode > HTCP_END) {
	debug(31,0)("htcpHandleData: opcode %d out of range\n",
	    (int) hdr.opcode);
	return;
    }
    debug(31,1)("htcpHandleData: opcode = %d %s\n",
	(int) hdr.opcode, htcpOpcodeStr[hdr.opcode]);
    debug(31,1)("htcpHandleData: response = %d\n", (int) hdr.response);
    debug(31,1)("htcpHandleData: F1 = %d\n", (int) hdr.F1);
    debug(31,1)("htcpHandleData: RR = %d\n", (int) hdr.RR);
    debug(31,1)("htcpHandleData: msg_id = %#x\n", (int) hdr.msg_id);
    if (sz < hdr.length) {
	debug(31,0)("htcpHandle: sz < hdr.length\n");
	return;
    }
    buf += sizeof(htcpDataHeader);
    sz -= sizeof(htcpDataHeader);
    switch(hdr.opcode) {
    case HTCP_NOP:
	htcpHandleNop(buf, sz, from);
	break;
    case HTCP_TST:
	htcpHandleTst(buf, sz, from);
	break;
    case HTCP_MON:
	htcpHandleMon(buf, sz, from);
	break;
    case HTCP_SET:
	htcpHandleSet(buf, sz, from);
	break;
    default:
	assert(0);
	break;
    }
}

static void
htcpHandle(char *buf, int sz, struct sockaddr_in *from)
{
    htcpHeader htcpHdr;
    if (sz < sizeof(htcpHeader)) {
	debug(31,0)("htcpHandle: msg size less than htcpHeader size\n");
	return;
    }
    xmemcpy(&htcpHdr, buf, sizeof(htcpHeader));
    htcpHdr.length = ntohs(htcpHdr.length);
    debug(31,1)("htcpHandle: htcpHdr.length = %d\n", (int) htcpHdr.length);
    debug(31,1)("htcpHandle: htcpHdr.major = %d\n", (int) htcpHdr.major);
    debug(31,1)("htcpHandle: htcpHdr.minor = %d\n", (int) htcpHdr.minor);
    if (sz != htcpHdr.length) {
	debug(31,0)("htcpHandle: sz != htcpHdr.length\n");
	return;
    }
    buf += sizeof(htcpHeader);
    sz -= sizeof(htcpHeader);
    htcpHandleData(buf, sz, from);
}

void
htcpRecv(int fd, void *data)
{
    static char buf[8192];
    int len;
    static struct sockaddr_in from;
    int flen = sizeof(struct sockaddr_in);
    memset(&from, '\0', flen);
    len = recvfrom(fd, buf, 8192, 0, (struct sockaddr *) &from, &flen);
    debug(31, 0) ("htcpRecv: FD %d, %d bytes from %s:%d\n",
	fd, len, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
    htcpHandle(buf, len, &from);
    commSetSelect(fd, COMM_SELECT_READ, htcpRecv, NULL, 0);
}

void
htcpInit(void)
{
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
    debug(31, 1) ("Accepting HTCP messages on port %d, FD %d.\n",
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
	debug(31, 1) ("Outgoing HTCP messages on port %d, FD %d.\n",
	    (int) Config.Port.htcp, htcpOutSocket);
	fd_note(htcpInSocket, "Incoming HTCP socket");
    } else {
	htcpOutSocket = htcpInSocket;
    }
}
