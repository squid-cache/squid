
/*
 * $Id: htcp.cc,v 1.40 2002/04/30 07:59:49 hno Exp $
 *
 * DEBUG: section 31    Hypertext Caching Protocol
 * AUTHOR: Duane Wesssels
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

typedef struct _Countstr Countstr;
typedef struct _htcpHeader htcpHeader;
typedef struct _htcpDataHeader htcpDataHeader;
typedef struct _htcpAuthHeader htcpAuthHeader;
typedef struct _htcpStuff htcpStuff;
typedef struct _htcpSpecifier htcpSpecifier;
typedef struct _htcpDetail htcpDetail;

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
    unsigned int opcode:4;
    unsigned int response:4;
#else
    unsigned int response:4;
    unsigned int opcode:4;
#endif
#if !WORDS_BIGENDIAN
    unsigned int reserved:6;
    unsigned int F1:1;
    unsigned int RR:1;
#else
    unsigned int RR:1;
    unsigned int F1:1;
    unsigned int reserved:6;
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

struct _htcpDetail {
    char *resp_hdrs;
    char *entity_hdrs;
    char *cache_hdrs;
};

struct _htcpStuff {
    int op;
    int rr;
    int f1;
    int response;
    u_num32 msg_id;
    htcpSpecifier S;
    htcpDetail D;
};

enum {
    HTCP_NOP,
    HTCP_TST,
    HTCP_MON,
    HTCP_SET,
    HTCP_CLR,
    HTCP_END
};

static const char *const htcpOpcodeStr[] =
{
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
#define N_QUERIED_KEYS 256
static cache_key queried_keys[N_QUERIED_KEYS][MD5_DIGEST_CHARS];
static MemPool *htcpSpecifierPool = NULL;
static MemPool *htcpDetailPool = NULL;


static char *htcpBuildPacket(htcpStuff * stuff, ssize_t * len);
static htcpSpecifier *htcpUnpackSpecifier(char *buf, int sz);
static htcpDetail *htcpUnpackDetail(char *buf, int sz);
static int htcpUnpackCountstr(char *buf, int sz, char **str);
static ssize_t htcpBuildAuth(char *buf, size_t buflen);
static ssize_t htcpBuildCountstr(char *buf, size_t buflen, const char *s);
static ssize_t htcpBuildData(char *buf, size_t buflen, htcpStuff * stuff);
static ssize_t htcpBuildDetail(char *buf, size_t buflen, htcpStuff * stuff);
static ssize_t htcpBuildOpData(char *buf, size_t buflen, htcpStuff * stuff);
static ssize_t htcpBuildSpecifier(char *buf, size_t buflen, htcpStuff * stuff);
static ssize_t htcpBuildTstOpData(char *buf, size_t buflen, htcpStuff * stuff);
static void htcpFreeSpecifier(htcpSpecifier * s);
static void htcpFreeDetail(htcpDetail * s);
static void htcpHandle(char *buf, int sz, struct sockaddr_in *from);
static void htcpHandleData(char *buf, int sz, struct sockaddr_in *from);
static void htcpHandleMon(htcpDataHeader *, char *buf, int sz, struct sockaddr_in *from);
static void htcpHandleNop(htcpDataHeader *, char *buf, int sz, struct sockaddr_in *from);
static void htcpHandleSet(htcpDataHeader *, char *buf, int sz, struct sockaddr_in *from);
static void htcpHandleTst(htcpDataHeader *, char *buf, int sz, struct sockaddr_in *from);
static void htcpRecv(int fd, void *data);
static void htcpSend(const char *buf, int len, struct sockaddr_in *to);
static void htcpTstReply(htcpDataHeader *, StoreEntry *, htcpSpecifier *, struct sockaddr_in *);
static void htcpHandleTstRequest(htcpDataHeader *, char *buf, int sz, struct sockaddr_in *from);
static void htcpHandleTstResponse(htcpDataHeader *, char *, int, struct sockaddr_in *);
static StoreEntry *htcpCheckHit(const htcpSpecifier *);

static void
htcpHexdump(const char *tag, const char *s, int sz)
{
#if USE_HEXDUMP
    int i;
    int k;
    char hex[80];
    debug(31, 3) ("htcpHexdump %s\n", tag);
    memset(hex, '\0', 80);
    for (i = 0; i < sz; i++) {
	k = i % 16;
	snprintf(&hex[k * 3], 4, " %02x", (int) *(s + i));
	if (k < 15 && i < (sz - 1))
	    continue;
	debug(31, 3) ("\t%s\n", hex);
	memset(hex, '\0', 80);
    }
#endif
}

/*
 * STUFF FOR SENDING HTCP MESSAGES
 */

static ssize_t
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

static ssize_t
htcpBuildCountstr(char *buf, size_t buflen, const char *s)
{
    u_short length;
    size_t len;
    off_t off = 0;
    if (buflen - off < 2)
	return -1;
    if (s)
	len = strlen(s);
    else
	len = 0;
    debug(31, 3) ("htcpBuildCountstr: LENGTH = %d\n", len);
    debug(31, 3) ("htcpBuildCountstr: TEXT = {%s}\n", s ? s : "<NULL>");
    length = htons((u_short) len);
    xmemcpy(buf + off, &length, 2);
    off += 2;
    if (buflen - off < len)
	return -1;
    if (len)
	xmemcpy(buf + off, s, len);
    off += len;
    return off;
}

static ssize_t
htcpBuildSpecifier(char *buf, size_t buflen, htcpStuff * stuff)
{
    ssize_t off = 0;
    ssize_t s;
    s = htcpBuildCountstr(buf + off, buflen - off, stuff->S.method);
    if (s < 0)
	return s;
    off += s;
    s = htcpBuildCountstr(buf + off, buflen - off, stuff->S.uri);
    if (s < 0)
	return s;
    off += s;
    s = htcpBuildCountstr(buf + off, buflen - off, stuff->S.version);
    if (s < 0)
	return s;
    off += s;
    s = htcpBuildCountstr(buf + off, buflen - off, stuff->S.req_hdrs);
    if (s < 0)
	return s;
    off += s;
    debug(31, 3) ("htcpBuildSpecifier: size %d\n", (int) off);
    return off;
}

static ssize_t
htcpBuildDetail(char *buf, size_t buflen, htcpStuff * stuff)
{
    ssize_t off = 0;
    ssize_t s;
    s = htcpBuildCountstr(buf + off, buflen - off, stuff->D.resp_hdrs);
    if (s < 0)
	return s;
    off += s;
    s = htcpBuildCountstr(buf + off, buflen - off, stuff->D.entity_hdrs);
    if (s < 0)
	return s;
    off += s;
    s = htcpBuildCountstr(buf + off, buflen - off, stuff->D.cache_hdrs);
    if (s < 0)
	return s;
    off += s;
    return off;
}

static ssize_t
htcpBuildTstOpData(char *buf, size_t buflen, htcpStuff * stuff)
{
    switch (stuff->rr) {
    case RR_REQUEST:
	debug(31, 3) ("htcpBuildTstOpData: RR_REQUEST\n");
	return htcpBuildSpecifier(buf, buflen, stuff);
    case RR_RESPONSE:
	debug(31, 3) ("htcpBuildTstOpData: RR_RESPONSE\n");
	debug(31, 3) ("htcpBuildTstOpData: F1 = %d\n", stuff->f1);
	if (stuff->f1)		/* cache miss */
	    return 0;
	else			/* cache hit */
	    return htcpBuildDetail(buf, buflen, stuff);
    default:
	fatal_dump("htcpBuildTstOpData: bad RR value");
    }
    return 0;
}

static ssize_t
htcpBuildOpData(char *buf, size_t buflen, htcpStuff * stuff)
{
    ssize_t off = 0;
    debug(31, 3) ("htcpBuildOpData: opcode %s\n",
	htcpOpcodeStr[stuff->op]);
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

static ssize_t
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
    debug(31, 3) ("htcpBuildData: hdr.length = %d\n", (int) off);
    hdr.length = (u_short) off;
    hdr.opcode = stuff->op;
    hdr.response = stuff->response;
    hdr.RR = stuff->rr;
    hdr.F1 = stuff->f1;
    hdr.msg_id = stuff->msg_id;
    /* convert multi-byte fields */
    hdr.length = htons(hdr.length);
    hdr.msg_id = htonl(hdr.msg_id);
    xmemcpy(buf, &hdr, hdr_sz);
    debug(31, 3) ("htcpBuildData: size %d\n", (int) off);
    return off;
}

static char *
htcpBuildPacket(htcpStuff * stuff, ssize_t * len)
{
    size_t buflen = 8192;
    size_t s;
    ssize_t off = 0;
    size_t hdr_sz = sizeof(htcpHeader);
    htcpHeader hdr;
    char *buf = xcalloc(buflen, 1);
    /* skip the header -- we don't know the overall length */
    if (buflen < hdr_sz) {
	xfree(buf);
	return NULL;
    }
    off += hdr_sz;
    s = htcpBuildData(buf + off, buflen - off, stuff);
    if (s < 0) {
	xfree(buf);
	return NULL;
    }
    off += s;
    s = htcpBuildAuth(buf + off, buflen - off);
    if (s < 0) {
	xfree(buf);
	return NULL;
    }
    off += s;
    hdr.length = htons((u_short) off);
    hdr.major = 0;
    hdr.minor = 0;
    xmemcpy(buf, &hdr, hdr_sz);
    *len = off;
    debug(31, 3) ("htcpBuildPacket: size %d\n", (int) off);
    return buf;
}

static void
htcpSend(const char *buf, int len, struct sockaddr_in *to)
{
    int x;
    debug(31, 3) ("htcpSend: %s/%d\n",
	inet_ntoa(to->sin_addr), (int) ntohs(to->sin_port));
    htcpHexdump("htcpSend", buf, len);
    x = comm_udp_sendto(htcpOutSocket,
	to,
	sizeof(struct sockaddr_in),
	buf,
	len);
    if (x < 0)
	debug(31, 0) ("htcpSend: FD %d sendto: %s\n", htcpOutSocket, xstrerror());
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
    memPoolFree(htcpSpecifierPool, s);
}

static void
htcpFreeDetail(htcpDetail * d)
{
    safe_free(d->resp_hdrs);
    safe_free(d->entity_hdrs);
    safe_free(d->cache_hdrs);
    memPoolFree(htcpDetailPool, d);
}

static int
htcpUnpackCountstr(char *buf, int sz, char **str)
{
    u_short l;
    debug(31, 3) ("htcpUnpackCountstr: sz = %d\n", sz);
    if (sz < 2) {
	debug(31, 3) ("htcpUnpackCountstr: sz < 2\n");
	return -1;
    }
    htcpHexdump("htcpUnpackCountstr", buf, sz);
    xmemcpy(&l, buf, 2);
    l = ntohs(l);
    buf += 2;
    sz -= 2;
    debug(31, 3) ("htcpUnpackCountstr: LENGTH = %d\n", (int) l);
    if (sz < l) {
	debug(31, 3) ("htcpUnpackCountstr: sz(%d) < l(%d)\n", sz, l);
	return -1;
    }
    if (str) {
	*str = xmalloc(l + 1);
	xstrncpy(*str, buf, l + 1);
	debug(31, 3) ("htcpUnpackCountstr: TEXT = {%s}\n", *str);
    }
    return (int) l + 2;
}

static htcpSpecifier *
htcpUnpackSpecifier(char *buf, int sz)
{
    htcpSpecifier *s = memPoolAlloc(htcpSpecifierPool);
    int o;
    debug(31, 3) ("htcpUnpackSpecifier: %d bytes\n", (int) sz);
    o = htcpUnpackCountstr(buf, sz, &s->method);
    if (o < 0) {
	debug(31, 1) ("htcpUnpackSpecifier: failed to unpack METHOD\n");
	htcpFreeSpecifier(s);
	return NULL;
    }
    buf += o;
    sz -= o;
    o = htcpUnpackCountstr(buf, sz, &s->uri);
    if (o < 0) {
	debug(31, 1) ("htcpUnpackSpecifier: failed to unpack URI\n");
	htcpFreeSpecifier(s);
	return NULL;
    }
    buf += o;
    sz -= o;
    o = htcpUnpackCountstr(buf, sz, &s->version);
    if (o < 0) {
	debug(31, 1) ("htcpUnpackSpecifier: failed to unpack VERSION\n");
	htcpFreeSpecifier(s);
	return NULL;
    }
    buf += o;
    sz -= o;
    o = htcpUnpackCountstr(buf, sz, &s->req_hdrs);
    if (o < 0) {
	debug(31, 1) ("htcpUnpackSpecifier: failed to unpack REQ-HDRS\n");
	htcpFreeSpecifier(s);
	return NULL;
    }
    buf += o;
    sz -= o;
    debug(31, 3) ("htcpUnpackSpecifier: %d bytes left\n", sz);
    return s;
}

static htcpDetail *
htcpUnpackDetail(char *buf, int sz)
{
    htcpDetail *d = memPoolAlloc(htcpDetailPool);
    int o;
    debug(31, 3) ("htcpUnpackDetail: %d bytes\n", (int) sz);
    o = htcpUnpackCountstr(buf, sz, &d->resp_hdrs);
    if (o < 0) {
	debug(31, 1) ("htcpUnpackDetail: failed to unpack RESP_HDRS\n");
	htcpFreeDetail(d);
	return NULL;
    }
    buf += o;
    sz -= o;
    o = htcpUnpackCountstr(buf, sz, &d->entity_hdrs);
    if (o < 0) {
	debug(31, 1) ("htcpUnpackDetail: failed to unpack ENTITY_HDRS\n");
	htcpFreeDetail(d);
	return NULL;
    }
    buf += o;
    sz -= o;
    o = htcpUnpackCountstr(buf, sz, &d->cache_hdrs);
    if (o < 0) {
	debug(31, 1) ("htcpUnpackDetail: failed to unpack CACHE_HDRS\n");
	htcpFreeDetail(d);
	return NULL;
    }
    buf += o;
    sz -= o;
    debug(31, 3) ("htcpUnpackDetail: %d bytes left\n", sz);
    return d;
}

static void
htcpTstReply(htcpDataHeader * dhdr, StoreEntry * e, htcpSpecifier * spec, struct sockaddr_in *from)
{
    htcpStuff stuff;
    char *pkt;
    HttpHeader hdr;
    MemBuf mb;
    Packer p;
    ssize_t pktlen;
    char *host;
    int rtt = 0;
    int hops = 0;
    int samp = 0;
    char cto_buf[128];
    memset(&stuff, '\0', sizeof(stuff));
    stuff.op = HTCP_TST;
    stuff.rr = RR_RESPONSE;
    stuff.f1 = 0;
    stuff.response = e ? 0 : 1;
    debug(31, 3) ("htcpTstReply: response = %d\n", stuff.response);
    stuff.msg_id = dhdr->msg_id;
    if (spec) {
	memBufDefInit(&mb);
	packerToMemInit(&p, &mb);
	httpHeaderInit(&hdr, hoHtcpReply);
	stuff.S.method = spec->method;
	stuff.S.uri = spec->uri;
	stuff.S.version = spec->version;
	stuff.S.req_hdrs = spec->req_hdrs;
	httpHeaderPutInt(&hdr, HDR_AGE,
	    e->timestamp <= squid_curtime ?
	    squid_curtime - e->timestamp : 0);
	httpHeaderPackInto(&hdr, &p);
	stuff.D.resp_hdrs = xstrdup(mb.buf);
	debug(31, 3) ("htcpTstReply: resp_hdrs = {%s}\n", stuff.D.resp_hdrs);
	memBufReset(&mb);
	httpHeaderReset(&hdr);
	if (e->expires > -1)
	    httpHeaderPutTime(&hdr, HDR_EXPIRES, e->expires);
	if (e->lastmod > -1)
	    httpHeaderPutTime(&hdr, HDR_LAST_MODIFIED, e->lastmod);
	httpHeaderPackInto(&hdr, &p);
	stuff.D.entity_hdrs = xstrdup(mb.buf);
	debug(31, 3) ("htcpTstReply: entity_hdrs = {%s}\n", stuff.D.entity_hdrs);
	memBufReset(&mb);
	httpHeaderReset(&hdr);
	if ((host = urlHostname(spec->uri))) {
	    netdbHostData(host, &samp, &rtt, &hops);
	    if (rtt || hops) {
		snprintf(cto_buf, 128, "%s %d %f %d",
		    host, samp, 0.001 * rtt, hops);
		httpHeaderPutExt(&hdr, "Cache-to-Origin", cto_buf);
	    }
	}
	httpHeaderPackInto(&hdr, &p);
	stuff.D.cache_hdrs = xstrdup(mb.buf);
	debug(31, 3) ("htcpTstReply: cache_hdrs = {%s}\n", stuff.D.cache_hdrs);
	memBufClean(&mb);
	httpHeaderClean(&hdr);
	packerClean(&p);
    }
    pkt = htcpBuildPacket(&stuff, &pktlen);
    if (pkt == NULL) {
	debug(31, 0) ("htcpTstReply: htcpBuildPacket() failed\n");
	return;
    }
    htcpSend(pkt, (int) pktlen, from);
    xfree(pkt);
}

static void
htcpHandleNop(htcpDataHeader * hdr, char *buf, int sz, struct sockaddr_in *from)
{
    debug(31, 3) ("htcpHandleNop: Unimplemented\n");
}

static StoreEntry *
htcpCheckHit(const htcpSpecifier * s)
{
    request_t *request;
    method_t m = urlParseMethod(s->method);
    StoreEntry *e = NULL, *hit = NULL;
    char *blk_end;
    request = urlParse(m, s->uri);
    if (NULL == request) {
	debug(31, 3) ("htcpCheckHit: NO; failed to parse URL\n");
	return NULL;
    }
    blk_end = s->req_hdrs + strlen(s->req_hdrs);
    if (!httpHeaderParse(&request->header, s->req_hdrs, blk_end)) {
	debug(31, 3) ("htcpCheckHit: NO; failed to parse request headers\n");
	goto miss;
    }
    e = storeGetPublicByRequest(request);
    if (NULL == e) {
	debug(31, 3) ("htcpCheckHit: NO; public object not found\n");
	goto miss;
    }
    if (!storeEntryValidToSend(e)) {
	debug(31, 3) ("htcpCheckHit: NO; entry not valid to send\n");
	goto miss;
    }
    if (refreshCheckHTCP(e, request)) {
	debug(31, 3) ("htcpCheckHit: NO; cached response is stale\n");
	goto miss;
    }
    debug(31, 3) ("htcpCheckHit: YES!?\n");
    hit = e;
  miss:
    requestDestroy(request);
    return hit;
}

static void
htcpHandleTst(htcpDataHeader * hdr, char *buf, int sz, struct sockaddr_in *from)
{
    debug(31, 3) ("htcpHandleTst: sz = %d\n", (int) sz);
    if (hdr->RR == RR_REQUEST)
	htcpHandleTstRequest(hdr, buf, sz, from);
    else
	htcpHandleTstResponse(hdr, buf, sz, from);
}

static void
htcpHandleTstResponse(htcpDataHeader * hdr, char *buf, int sz, struct sockaddr_in *from)
{
    htcpReplyData htcpReply;
    cache_key *key = NULL;
    htcpDetail *d = NULL;
    char *t;
    if (hdr->F1 == 1) {
	debug(31, 1) ("htcpHandleTstResponse: error condition, F1/MO == 1\n");
	return;
    }
    memset(&htcpReply, '\0', sizeof(htcpReply));
    httpHeaderInit(&htcpReply.hdr, hoHtcpReply);
    htcpReply.msg_id = hdr->msg_id;
    debug(31, 3) ("htcpHandleTstResponse: msg_id = %d\n", (int) htcpReply.msg_id);
    htcpReply.hit = hdr->response ? 0 : 1;
    if (hdr->F1) {
	debug(31, 3) ("htcpHandleTstResponse: MISS\n");
    } else {
	debug(31, 3) ("htcpHandleTstResponse: HIT\n");
	d = htcpUnpackDetail(buf, sz);
	if (d == NULL) {
	    debug(31, 1) ("htcpHandleTstResponse: bad DETAIL\n");
	    return;
	}
	if ((t = d->resp_hdrs))
	    httpHeaderParse(&htcpReply.hdr, t, t + strlen(t));
	if ((t = d->entity_hdrs))
	    httpHeaderParse(&htcpReply.hdr, t, t + strlen(t));
	if ((t = d->cache_hdrs))
	    httpHeaderParse(&htcpReply.hdr, t, t + strlen(t));
    }
    key = queried_keys[htcpReply.msg_id % N_QUERIED_KEYS];
    debug(31, 3) ("htcpHandleTstResponse: key (%p) %s\n", key, storeKeyText(key));
    neighborsHtcpReply(key, &htcpReply, from);
    httpHeaderClean(&htcpReply.hdr);
    if (d)
	htcpFreeDetail(d);
}

static void
htcpHandleTstRequest(htcpDataHeader * dhdr, char *buf, int sz, struct sockaddr_in *from)
{
    /* buf should be a SPECIFIER */
    htcpSpecifier *s;
    StoreEntry *e;
    if (sz == 0) {
	debug(31, 3) ("htcpHandleTst: nothing to do\n");
	return;
    }
    if (dhdr->F1 == 0)
	return;
    s = htcpUnpackSpecifier(buf, sz);
    if (NULL == s) {
	debug(31, 3) ("htcpHandleTstRequest: htcpUnpackSpecifier failed\n");
	return;
    }
    debug(31, 3) ("htcpHandleTstRequest: %s %s %s\n",
	s->method,
	s->uri,
	s->version);
    debug(31, 3) ("htcpHandleTstRequest: %s\n", s->req_hdrs);
    if ((e = htcpCheckHit(s)))
	htcpTstReply(dhdr, e, s, from);		/* hit */
    else
	htcpTstReply(dhdr, NULL, NULL, from);	/* cache miss */
    htcpFreeSpecifier(s);
}

static void
htcpHandleMon(htcpDataHeader * hdr, char *buf, int sz, struct sockaddr_in *from)
{
    debug(31, 3) ("htcpHandleMon: Unimplemented\n");
}

static void
htcpHandleSet(htcpDataHeader * hdr, char *buf, int sz, struct sockaddr_in *from)
{
    debug(31, 3) ("htcpHandleSet: Unimplemented\n");
}

static void
htcpHandleData(char *buf, int sz, struct sockaddr_in *from)
{
    htcpDataHeader hdr;
    if (sz < sizeof(htcpDataHeader)) {
	debug(31, 0) ("htcpHandleData: msg size less than htcpDataHeader size\n");
	return;
    }
    xmemcpy(&hdr, buf, sizeof(htcpDataHeader));
    hdr.length = ntohs(hdr.length);
    hdr.msg_id = ntohl(hdr.msg_id);
    debug(31, 3) ("htcpHandleData: sz = %d\n", sz);
    debug(31, 3) ("htcpHandleData: length = %d\n", (int) hdr.length);
    if (hdr.opcode >= HTCP_END) {
	debug(31, 0) ("htcpHandleData: client %s, opcode %d out of range\n",
	    inet_ntoa(from->sin_addr),
	    (int) hdr.opcode);
	return;
    }
    debug(31, 3) ("htcpHandleData: opcode = %d %s\n",
	(int) hdr.opcode, htcpOpcodeStr[hdr.opcode]);
    debug(31, 3) ("htcpHandleData: response = %d\n", (int) hdr.response);
    debug(31, 3) ("htcpHandleData: F1 = %d\n", (int) hdr.F1);
    debug(31, 3) ("htcpHandleData: RR = %d\n", (int) hdr.RR);
    debug(31, 3) ("htcpHandleData: msg_id = %d\n", (int) hdr.msg_id);
    if (sz < hdr.length) {
	debug(31, 0) ("htcpHandle: sz < hdr.length\n");
	return;
    }
    /*
     * set sz = hdr.length so we ignore any AUTH fields following
     * the DATA.
     */
    sz = (int) hdr.length;
    buf += sizeof(htcpDataHeader);
    sz -= sizeof(htcpDataHeader);
    debug(31, 3) ("htcpHandleData: sz = %d\n", sz);
    htcpHexdump("htcpHandleData", buf, sz);
    switch (hdr.opcode) {
    case HTCP_NOP:
	htcpHandleNop(&hdr, buf, sz, from);
	break;
    case HTCP_TST:
	htcpHandleTst(&hdr, buf, sz, from);
	break;
    case HTCP_MON:
	htcpHandleMon(&hdr, buf, sz, from);
	break;
    case HTCP_SET:
	htcpHandleSet(&hdr, buf, sz, from);
	break;
    case HTCP_CLR:
	debug(31, 1) ("htcpHandleData: client %s, CLR not supported\n",
	    inet_ntoa(from->sin_addr));
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
	debug(31, 0) ("htcpHandle: msg size less than htcpHeader size\n");
	return;
    }
    htcpHexdump("htcpHandle", buf, sz);
    xmemcpy(&htcpHdr, buf, sizeof(htcpHeader));
    htcpHdr.length = ntohs(htcpHdr.length);
    debug(31, 3) ("htcpHandle: htcpHdr.length = %d\n", (int) htcpHdr.length);
    debug(31, 3) ("htcpHandle: htcpHdr.major = %d\n", (int) htcpHdr.major);
    debug(31, 3) ("htcpHandle: htcpHdr.minor = %d\n", (int) htcpHdr.minor);
    if (sz != htcpHdr.length) {
	debug(31, 1) ("htcpHandle: sz != htcpHdr.length\n");
	return;
    }
    buf += sizeof(htcpHeader);
    sz -= sizeof(htcpHeader);
    htcpHandleData(buf, sz, from);
}

static void
htcpRecv(int fd, void *data)
{
    static char buf[8192];
    int len;
    static struct sockaddr_in from;
    int flen = sizeof(struct sockaddr_in);
    memset(&from, '\0', flen);
    statCounter.syscalls.sock.recvfroms++;
    len = recvfrom(fd, buf, 8192, 0, (struct sockaddr *) &from, &flen);
    debug(31, 3) ("htcpRecv: FD %d, %d bytes from %s:%d\n",
	fd, len, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
    htcpHandle(buf, len, &from);
    commSetSelect(fd, COMM_SELECT_READ, htcpRecv, NULL, 0);
}

/*
 * ======================================================================
 * PUBLIC FUNCTIONS
 * ======================================================================
 */

void
htcpInit(void)
{
    if (Config.Port.htcp <= 0) {
	debug(31, 1) ("HTCP Disabled.\n");
	return;
    }
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
    if (!htcpSpecifierPool) {
	htcpSpecifierPool = memPoolCreate("htcpSpecifier", sizeof(htcpSpecifier));
	htcpDetailPool = memPoolCreate("htcpDetail", sizeof(htcpDetail));
    }
}

void
htcpQuery(StoreEntry * e, request_t * req, peer * p)
{
    cache_key *save_key;
    char *pkt;
    ssize_t pktlen;
    char vbuf[32];
    htcpStuff stuff;
    HttpHeader hdr;
    Packer pa;
    MemBuf mb;
    http_state_flags flags;

    if (htcpInSocket < 0)
	return;

    memset(&flags, '\0', sizeof(flags));
    snprintf(vbuf, sizeof(vbuf), "%d/%d",
	req->http_ver.major, req->http_ver.minor);
    stuff.op = HTCP_TST;
    stuff.rr = RR_REQUEST;
    stuff.f1 = 1;
    stuff.response = 0;
    stuff.msg_id = ++msg_id_counter;
    stuff.S.method = (char *) RequestMethodStr[req->method];
    stuff.S.uri = (char *) storeUrl(e);
    stuff.S.version = vbuf;
    httpBuildRequestHeader(req, req, e, &hdr, -1, flags);
    memBufDefInit(&mb);
    packerToMemInit(&pa, &mb);
    httpHeaderPackInto(&hdr, &pa);
    httpHeaderClean(&hdr);
    packerClean(&pa);
    stuff.S.req_hdrs = mb.buf;
    pkt = htcpBuildPacket(&stuff, &pktlen);
    memBufClean(&mb);
    if (pkt == NULL) {
	debug(31, 0) ("htcpQuery: htcpBuildPacket() failed\n");
	return;
    }
    htcpSend(pkt, (int) pktlen, &p->in_addr);
    save_key = queried_keys[stuff.msg_id % N_QUERIED_KEYS];
    storeKeyCopy(save_key, e->hash.key);
    debug(31, 3) ("htcpQuery: key (%p) %s\n", save_key, storeKeyText(save_key));
    xfree(pkt);
}

/*  
 * htcpSocketShutdown only closes the 'in' socket if it is
 * different than the 'out' socket.
 */
void
htcpSocketShutdown(void)
{
    if (htcpInSocket < 0)
	return;
    if (htcpInSocket != htcpOutSocket) {
	debug(12, 1) ("FD %d Closing HTCP socket\n", htcpInSocket);
	comm_close(htcpInSocket);
    }
    /*      
     * Here we set 'htcpInSocket' to -1 even though the HTCP 'in'
     * and 'out' sockets might be just one FD.  This prevents this
     * function from executing repeatedly.  When we are really ready to
     * exit or restart, main will comm_close the 'out' descriptor.
     */
    htcpInSocket = -1;
    /*      
     * Normally we only write to the outgoing HTCP socket, but
     * we also have a read handler there to catch messages sent
     * to that specific interface.  During shutdown, we must
     * disable reading on the outgoing socket.
     */
    /* XXX Don't we need this handler to read replies while shutting down?
     * I think there should be a separate hander for reading replies..
     */
    assert(htcpOutSocket > -1);
    commSetSelect(htcpOutSocket, COMM_SELECT_READ, NULL, NULL, 0);
}

void
htcpSocketClose(void)
{
    htcpSocketShutdown();
    if (htcpOutSocket > -1) {
	debug(12, 1) ("FD %d Closing HTCP socket\n", htcpOutSocket);
	comm_close(htcpOutSocket);
	htcpOutSocket = -1;
    }
}
