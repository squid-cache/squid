
/*
 * $Id: htcp.cc,v 1.71 2006/11/04 14:15:22 hno Exp $
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
#include "htcp.h"
#include "ACLChecklist.h"
#include "ACL.h"
#include "SquidTime.h"
#include "Store.h"
#include "StoreClient.h"
#include "HttpRequest.h"
#include "comm.h"
#include "MemBuf.h"
#include "http.h"

typedef struct _Countstr Countstr;

typedef struct _htcpHeader htcpHeader;

typedef struct _htcpDataHeader htcpDataHeader;

typedef struct _htcpDataHeaderSquid htcpDataHeaderSquid;

typedef struct _htcpAuthHeader htcpAuthHeader;

typedef struct _htcpStuff htcpStuff;

typedef struct _htcpDetail htcpDetail;

struct _Countstr
{
    u_int16_t length;
    char *text;
};

struct _htcpHeader
{
    u_int16_t length;
    u_char major;
    u_char minor;
};

struct _htcpDataHeaderSquid
{
    u_int16_t length;
#if !WORDS_BIGENDIAN

unsigned int opcode:
    4;

unsigned int response:
    4;
#else

unsigned int response:
    4;

unsigned int opcode:
    4;
#endif
#if !WORDS_BIGENDIAN

unsigned int reserved:
    6;

unsigned int F1:
    1;

unsigned int RR:
    1;
#else

unsigned int RR:
    1;

unsigned int F1:
    1;

unsigned int reserved:
    6;
#endif

    u_int32_t msg_id;
};

struct _htcpDataHeader
{
    u_int16_t length;
#if WORDS_BIGENDIAN

u_int8_t opcode:
    4;

u_int8_t response:
    4;
#else

u_int8_t response:
    4;

u_int8_t opcode:
    4;
#endif
#if WORDS_BIGENDIAN

u_int8_t reserved:
    6;

u_int8_t F1:
    1;

u_int8_t RR:
    1;
#else

u_int8_t RR:
    1;

u_int8_t F1:
    1;

u_int8_t reserved:
    6;
#endif

    u_int32_t msg_id;
};

/* RR == 0 --> F1 = RESPONSE DESIRED FLAG */
/* RR == 1 --> F1 = MESSAGE OVERALL FLAG */
/* RR == 0 --> REQUEST */
/* RR == 1 --> RESPONSE */

struct _htcpAuthHeader
{
    u_int16_t length;
    time_t sig_time;
    time_t sig_expire;
    Countstr key_name;
    Countstr signature;
};

class htcpSpecifier : public StoreClient
{

public:
    MEMPROXY_CLASS(htcpSpecifier);

    void created (StoreEntry *newEntry);
    void checkHit();
    void checkedHit(StoreEntry *e);

    void setFrom (struct sockaddr_in *from);
    void setDataHeader (htcpDataHeader *);
    char *method;
    char *uri;
    char *version;
    char *req_hdrs;
    HttpRequest *request;

private:
    HttpRequest *checkHitRequest;

    struct sockaddr_in *from;
    htcpDataHeader *dhdr;
};

MEMPROXY_CLASS_INLINE(htcpSpecifier)

struct _htcpDetail
{
    char *resp_hdrs;
    char *entity_hdrs;
    char *cache_hdrs;
};

struct _htcpStuff
{
    int op;
    int rr;
    int f1;
    int response;
    u_int32_t msg_id;
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

static u_int32_t msg_id_counter = 0;
static int htcpInSocket = -1;
static int htcpOutSocket = -1;
#define N_QUERIED_KEYS 8192
static u_int32_t queried_id[N_QUERIED_KEYS];
static cache_key queried_keys[N_QUERIED_KEYS][MD5_DIGEST_CHARS];

static struct sockaddr_in queried_addr[N_QUERIED_KEYS];
static MemAllocator *htcpDetailPool = NULL;

static int old_squid_format = 0;


static ssize_t htcpBuildPacket(char *buf, size_t buflen, htcpStuff * stuff);
static htcpSpecifier *htcpUnpackSpecifier(char *buf, int sz);
static htcpDetail *htcpUnpackDetail(char *buf, int sz);
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
    assert(2 == sizeof(u_int16_t));
    auth.length = htons(2);
    copy_sz += 2;
    if (buflen < copy_sz)
	return -1;
    xmemcpy(buf, &auth, copy_sz);
    return copy_sz;
}

static ssize_t
htcpBuildCountstr(char *buf, size_t buflen, const char *s)
{
    u_int16_t length;
    size_t len;
    int off = 0;

    if (buflen - off < 2)
        return -1;

    if (s)
        len = strlen(s);
    else
        len = 0;

    debugs(31, 3, "htcpBuildCountstr: LENGTH = " << len);

    debug(31, 3) ("htcpBuildCountstr: TEXT = {%s}\n", s ? s : "<NULL>");

    length = htons((u_int16_t) len);

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

    case HTCP_CLR:
        /* nothing to be done */
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

    hdr.length = (u_int16_t) off;

    hdr.opcode = stuff->op;

    hdr.response = stuff->response;

    hdr.RR = stuff->rr;

    hdr.F1 = stuff->f1;

    hdr.msg_id = stuff->msg_id;

    /* convert multi-byte fields */
    hdr.length = htons(hdr.length);

    hdr.msg_id = htonl(hdr.msg_id);

    if (!old_squid_format) {
        xmemcpy(buf, &hdr, hdr_sz);
    } else {
        htcpDataHeaderSquid hdrSquid;
        memset(&hdrSquid, 0, sizeof(hdrSquid));
        hdrSquid.length = hdr.length;
        hdrSquid.opcode = hdr.opcode;
        hdrSquid.response = hdr.response;
        hdrSquid.F1 = hdr.F1;
        hdrSquid.RR = hdr.RR;
        xmemcpy(buf, &hdrSquid, hdr_sz);
    }

    debug(31, 3) ("htcpBuildData: size %d\n", (int) off);

    return off;
}

/*
 * Build an HTCP packet into buf, maximum length buflen.
 * Returns the packet length, or zero on failure.
 */
static ssize_t
htcpBuildPacket(char *buf, size_t buflen, htcpStuff * stuff)
{
    ssize_t s;
    ssize_t off = 0;
    size_t hdr_sz = sizeof(htcpHeader);
    htcpHeader hdr;
    /* skip the header -- we don't know the overall length */

    if (buflen < hdr_sz) {
        return 0;
    }

    off += hdr_sz;
    s = htcpBuildData(buf + off, buflen - off, stuff);

    if (s < 0) {
        return 0;
    }

    off += s;
    s = htcpBuildAuth(buf + off, buflen - off);

    if (s < 0) {
        return 0;
    }

    off += s;
    hdr.length = htons((u_int16_t) off);
    hdr.major = 0;

    if (old_squid_format)
        hdr.minor = 0;
    else
        hdr.minor = 1;

    xmemcpy(buf, &hdr, hdr_sz);

    debug(31, 3) ("htcpBuildPacket: size %d\n", (int) off);

    return off;
}

static void

htcpSend(const char *buf, int len, struct sockaddr_in *to)
{
    int x;
    debugs(31, 3, "htcpSend: " << inet_ntoa(to->sin_addr) << "/" << ntohs(to->sin_port));
    htcpHexdump("htcpSend", buf, len);
    x = comm_udp_sendto(htcpOutSocket,
                        to,

                        sizeof(struct sockaddr_in),
                        buf,
                        len);

    if (x < 0)
        debug(31, 1) ("htcpSend: FD %d sendto: %s\n", htcpOutSocket, xstrerror());
    else
        statCounter.htcp.pkts_sent++;
}

/*
 * STUFF FOR RECEIVING HTCP MESSAGES
 */

void

htcpSpecifier::setFrom (struct sockaddr_in *aSocket)
{
    from = aSocket;
}

void
htcpSpecifier::setDataHeader (htcpDataHeader *aDataHeader)
{
    dhdr = aDataHeader;
}

static void
htcpFreeSpecifier(htcpSpecifier * s)
{
    HTTPMSGUNLOCK(s->request);

    delete s;
}

static void
htcpFreeDetail(htcpDetail * d)
{
    htcpDetailPool->free(d);
}

/*
 * Unpack an HTCP SPECIFIER in place
 * This will overwrite any following AUTH block
 */
static htcpSpecifier *
htcpUnpackSpecifier(char *buf, int sz)
{
    htcpSpecifier *s = new htcpSpecifier;
    method_t method;

    /* Find length of METHOD */
    u_int16_t l = ntohs(*(u_int16_t *) buf);
    sz -= 2;
    buf += 2;

    if (l > sz) {
        debug(31, 1) ("htcpUnpackSpecifier: failed to unpack METHOD\n");
        htcpFreeSpecifier(s);
        return NULL;
    }

    /* Set METHOD */
    s->method = buf;

    buf += l;

    sz -= l;

    /* Find length of URI */
    l = ntohs(*(u_int16_t *) buf);

    sz -= 2;

    if (l > sz) {
        debug(31, 1) ("htcpUnpackSpecifier: failed to unpack URI\n");
        htcpFreeSpecifier(s);
        return NULL;
    }

    /* Add terminating null to METHOD */
    *buf = '\0';

    /* Set URI */
    buf += 2;

    s->uri = buf;

    buf += l;

    sz -= l;

    /* Find length of VERSION */
    l = ntohs(*(u_int16_t *) buf);

    sz -= 2;

    if (l > sz) {
        debug(31, 1) ("htcpUnpackSpecifier: failed to unpack VERSION\n");
        htcpFreeSpecifier(s);
        return NULL;
    }

    /* Add terminating null to URI */
    *buf = '\0';

    /* Set VERSION */
    buf += 2;

    s->version = buf;

    buf += l;

    sz -= l;

    /* Find length of REQ-HDRS */
    l = ntohs(*(u_int16_t *) buf);

    sz -= 2;

    if (l > sz) {
        debug(31, 1) ("htcpUnpackSpecifier: failed to unpack REQ-HDRS\n");
        htcpFreeSpecifier(s);
        return NULL;
    }

    /* Add terminating null to URI */
    *buf = '\0';

    /* Set REQ-HDRS */
    buf += 2;

    s->req_hdrs = buf;

    buf += l;

    sz -= l;

    debug(31, 3) ("htcpUnpackSpecifier: %d bytes left\n", sz);

    /*
     * Add terminating null to REQ-HDRS. This is possible because we allocated 
     * an extra byte when we received the packet. This will overwrite any following
     * AUTH block.
     */
    *buf = '\0';

    /*
     * Parse the request
     */
    method = HttpRequestMethod(s->method);

    s->request = HttpRequest::CreateFromUrlAndMethod(s->uri, method == METHOD_NONE ? METHOD_GET : method);

    return s;
}

/*
 * Unpack an HTCP DETAIL in place
 * This will overwrite any following AUTH block
 */
static htcpDetail *
htcpUnpackDetail(char *buf, int sz)
{
    htcpDetail *d = static_cast<htcpDetail *>(htcpDetailPool->alloc());

    /* Find length of RESP-HDRS */
    u_int16_t l = ntohs(*(u_int16_t *) buf);
    sz -= 2;
    buf += 2;

    if (l > sz) {
        debug(31, 1) ("htcpUnpackDetail: failed to unpack RESP_HDRS\n");
        htcpFreeDetail(d);
        return NULL;
    }

    /* Set RESP-HDRS */
    d->resp_hdrs = buf;

    buf += l;

    sz -= l;

    /* Find length of ENTITY-HDRS */
    l = ntohs(*(u_int16_t *) buf);

    sz -= 2;

    if (l > sz) {
        debug(31, 1) ("htcpUnpackDetail: failed to unpack ENTITY_HDRS\n");
        htcpFreeDetail(d);
        return NULL;
    }

    /* Add terminating null to RESP-HDRS */
    *buf = '\0';

    /* Set ENTITY-HDRS */
    buf += 2;

    d->entity_hdrs = buf;

    buf += l;

    sz -= l;

    /* Find length of CACHE-HDRS */
    l = ntohs(*(u_int16_t *) buf);

    sz -= 2;

    if (l > sz) {
        debug(31, 1) ("htcpUnpackDetail: failed to unpack CACHE_HDRS\n");
        htcpFreeDetail(d);
        return NULL;
    }

    /* Add terminating null to ENTITY-HDRS */
    *buf = '\0';

    /* Set CACHE-HDRS */
    buf += 2;

    d->cache_hdrs = buf;

    buf += l;

    sz -= l;

    debug(31, 3) ("htcpUnpackDetail: %d bytes left\n", sz);

    /*
     * Add terminating null to CACHE-HDRS. This is possible because we allocated 
     * an extra byte when we received the packet. This will overwrite any following
     * AUTH block.
     */
    *buf = '\0';

    return d;
}

static int

htcpAccessCheck(acl_access * acl, htcpSpecifier * s, struct sockaddr_in *from)
{
    ACLChecklist checklist;
    checklist.src_addr = from->sin_addr;
    checklist.my_addr = no_addr;
    checklist.request = s->request;
    checklist.accessList = cbdataReference(acl);
    /* cbdataReferenceDone() happens in either fastCheck() or ~ACLCheckList */
    int result = checklist.fastCheck();
    return result;
}

static void

htcpTstReply(htcpDataHeader * dhdr, StoreEntry * e, htcpSpecifier * spec, struct sockaddr_in *from)
{
    htcpStuff stuff;
    static char pkt[8192];
    HttpHeader hdr(hoHtcpReply);
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

    if (spec)
    {
        mb.init();
        packerToMemInit(&p, &mb);
        stuff.S.method = spec->method;
        stuff.S.uri = spec->uri;
        stuff.S.version = spec->version;
        stuff.S.req_hdrs = spec->req_hdrs;
        hdr.putInt(HDR_AGE,
                   e->timestamp <= squid_curtime ?
                   squid_curtime - e->timestamp : 0);
        hdr.packInto(&p);
        stuff.D.resp_hdrs = xstrdup(mb.buf);
        debug(31, 3) ("htcpTstReply: resp_hdrs = {%s}\n", stuff.D.resp_hdrs);
        mb.reset();
        hdr.reset();

        if (e->expires > -1)
            hdr.putTime(HDR_EXPIRES, e->expires);

        if (e->lastmod > -1)
            hdr.putTime(HDR_LAST_MODIFIED, e->lastmod);

        hdr.packInto(&p);

        stuff.D.entity_hdrs = xstrdup(mb.buf);

        debug(31, 3) ("htcpTstReply: entity_hdrs = {%s}\n", stuff.D.entity_hdrs);

        mb.reset();

        hdr.reset();

        if ((host = urlHostname(spec->uri))) {
            netdbHostData(host, &samp, &rtt, &hops);

            if (rtt || hops) {
                snprintf(cto_buf, 128, "%s %d %f %d",
                         host, samp, 0.001 * rtt, hops);
                hdr.putExt("Cache-to-Origin", cto_buf);
            }
        }

        hdr.packInto(&p);
        stuff.D.cache_hdrs = xstrdup(mb.buf);
        debug(31, 3) ("htcpTstReply: cache_hdrs = {%s}\n", stuff.D.cache_hdrs);
        mb.clean();
        hdr.clean();
        packerClean(&p);
    }

    pktlen = htcpBuildPacket(pkt, sizeof(pkt), &stuff);

    safe_free(stuff.D.resp_hdrs);
    safe_free(stuff.D.entity_hdrs);
    safe_free(stuff.D.cache_hdrs);

    if (!pktlen)
    {
        debug(31, 1) ("htcpTstReply: htcpBuildPacket() failed\n");
        return;
    }

    htcpSend(pkt, (int) pktlen, from);
}

static void

htcpClrReply(htcpDataHeader * dhdr, int purgeSucceeded, struct sockaddr_in *from)
{
    htcpStuff stuff;
    static char pkt[8192];
    ssize_t pktlen;

    /* If dhdr->F1 == 0, no response desired */

    if (dhdr->F1 == 0)
        return;

    memset(&stuff, '\0', sizeof(stuff));

    stuff.op = HTCP_CLR;

    stuff.rr = RR_RESPONSE;

    stuff.f1 = 0;

    stuff.response = purgeSucceeded ? 0 : 2;

    debug(31, 3) ("htcpClrReply: response = %d\n", stuff.response);

    stuff.msg_id = dhdr->msg_id;

    pktlen = htcpBuildPacket(pkt, sizeof(pkt), &stuff);

    if (pktlen == 0)
    {
        debug(31, 1) ("htcpClrReply: htcpBuildPacket() failed\n");
        return;
    }

    htcpSend(pkt, (int) pktlen, from);
}

static void

htcpHandleNop(htcpDataHeader * hdr, char *buf, int sz, struct sockaddr_in *from)
{
    debug(31, 3) ("htcpHandleNop: Unimplemented\n");
}

void
htcpSpecifier::checkHit()
{
    char *blk_end;
    checkHitRequest = request;

    if (NULL == checkHitRequest) {
        debug(31, 3) ("htcpCheckHit: NO; failed to parse URL\n");
        checkedHit(NullStoreEntry::getInstance());
        return;
    }

    blk_end = req_hdrs + strlen(req_hdrs);

    if (!checkHitRequest->header.parse(req_hdrs, blk_end)) {
        debug(31, 3) ("htcpCheckHit: NO; failed to parse request headers\n");
        delete checkHitRequest;
        checkHitRequest = NULL;
        checkedHit(NullStoreEntry::getInstance());
        return;
    }

    StoreEntry::getPublicByRequest(this, checkHitRequest);
}

void
htcpSpecifier::created (StoreEntry *e)
{
    StoreEntry *hit=NULL;
    assert (e);

    if (e->isNull()) {
        debug(31, 3) ("htcpCheckHit: NO; public object not found\n");
        goto miss;
    }

    if (!storeEntryValidToSend(e)) {
        debug(31, 3) ("htcpCheckHit: NO; entry not valid to send\n");
        goto miss;
    }

    if (refreshCheckHTCP(e, checkHitRequest)) {
        debug(31, 3) ("htcpCheckHit: NO; cached response is stale\n");
        goto miss;
    }

    debug(31, 3) ("htcpCheckHit: YES!?\n");
    hit = e;

miss:
    checkedHit (hit);
}

static void
htcpClrStoreEntry(StoreEntry * e)
{
    debug(31, 4) ("htcpClrStoreEntry: Clearing store for entry: %s\n", storeUrl(e));
    storeReleaseRequest(e);
}

static int
htcpClrStore(const htcpSpecifier * s)
{
    HttpRequest *request = s->request;
    char *blk_end;
    StoreEntry *e = NULL;
    int released = 0;

    if (request == NULL) {
        debug(31, 3) ("htcpClrStore: failed to parse URL\n");
        return -1;
    }

    /* Parse request headers */
    blk_end = s->req_hdrs + strlen(s->req_hdrs);

    if (!request->header.parse(s->req_hdrs, blk_end)) {
        debug(31, 2) ("htcpClrStore: failed to parse request headers\n");
        return -1;
    }

    /* Lookup matching entries. This matches both GET and HEAD */
    while ((e = storeGetPublicByRequest(request)) != NULL) {
        if (e != NULL) {
            htcpClrStoreEntry(e);
            released++;
        }
    }

    if (released) {
        debug(31, 4) ("htcpClrStore: Cleared %d matching entries\n", released);
        return 1;
    } else {
        debug(31, 4) ("htcpClrStore: No matching entry found\n");
        return 0;
    }
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

HtcpReplyData::HtcpReplyData() : hdr(hoHtcpReply)
{}

static void

htcpHandleTstResponse(htcpDataHeader * hdr, char *buf, int sz, struct sockaddr_in *from)
{
    htcpReplyData htcpReply;
    cache_key *key = NULL;

    struct sockaddr_in *peer;
    htcpDetail *d = NULL;
    char *t;


    if (queried_id[hdr->msg_id % N_QUERIED_KEYS] != hdr->msg_id)
    {
        debug(31, 2) ("htcpHandleTstResponse: No matching query id '%d' (expected %d) from '%s'\n", hdr->msg_id, queried_id[hdr->msg_id % N_QUERIED_KEYS], inet_ntoa(from->sin_addr));
        return;
    }

    key = queried_keys[hdr->msg_id % N_QUERIED_KEYS];

    if (!key)
    {
        debug(31, 1) ("htcpHandleTstResponse: No query key for response id '%d' from '%s'\n", hdr->msg_id, inet_ntoa(from->sin_addr));
        return;
    }

    peer = &queried_addr[hdr->msg_id % N_QUERIED_KEYS];

    if (peer->sin_addr.s_addr != from->sin_addr.s_addr || peer->sin_port != from->sin_port)
    {
        debug(31, 1) ("htcpHandleTstResponse: Unexpected response source %s\n", inet_ntoa(from->sin_addr));
        return;
    }

    if (hdr->F1 == 1)
    {
        debug(31, 2) ("htcpHandleTstResponse: error condition, F1/MO == 1\n");
        return;
    }

    htcpReply.msg_id = hdr->msg_id;
    debug(31, 3) ("htcpHandleTstResponse: msg_id = %d\n", (int) htcpReply.msg_id);
    htcpReply.hit = hdr->response ? 0 : 1;

    if (hdr->F1)
    {
        debug(31, 3) ("htcpHandleTstResponse: MISS\n");
    } else
    {
        debug(31, 3) ("htcpHandleTstResponse: HIT\n");
        d = htcpUnpackDetail(buf, sz);

        if (d == NULL) {
            debug(31, 1) ("htcpHandleTstResponse: bad DETAIL\n");
            return;
        }

        if ((t = d->resp_hdrs))
            htcpReply.hdr.parse(t, t + strlen(t));

        if ((t = d->entity_hdrs))
            htcpReply.hdr.parse(t, t + strlen(t));

        if ((t = d->cache_hdrs))
            htcpReply.hdr.parse(t, t + strlen(t));
    }

    debug(31, 3) ("htcpHandleTstResponse: key (%p) %s\n", key, storeKeyText(key));
    neighborsHtcpReply(key, &htcpReply, from);
    htcpReply.hdr.clean();

    if (d)
        htcpFreeDetail(d);
}

static void

htcpHandleTstRequest(htcpDataHeader * dhdr, char *buf, int sz, struct sockaddr_in *from)
{
    /* buf should be a SPECIFIER */
    htcpSpecifier *s;

    if (sz == 0)
    {
        debug(31, 3) ("htcpHandleTst: nothing to do\n");
        return;
    }

    if (dhdr->F1 == 0)
        return;

    /* s is a new object */
    s = htcpUnpackSpecifier(buf, sz);

    s->setFrom (from);

    s->setDataHeader (dhdr);

    if (NULL == s)
    {
        debug(31, 2) ("htcpHandleTstRequest: htcpUnpackSpecifier failed\n");
        return;
    }

    if (!s->request)
    {
        debug(31, 2) ("htcpHandleTstRequest: failed to parse request\n");
        htcpFreeSpecifier(s);
        return;
    }

    HTTPMSGLOCK(s->request);

    if (!htcpAccessCheck(Config.accessList.htcp, s, from))
    {
        debug(31, 2) ("htcpHandleTstRequest: Access denied\n");
        htcpFreeSpecifier(s);
        return;
    }

    debug(31, 3) ("htcpHandleTstRequest: %s %s %s\n",
                  s->method,
                  s->uri,
                  s->version);
    debug(31, 3) ("htcpHandleTstRequest: %s\n", s->req_hdrs);
    s->checkHit();
}

void
htcpSpecifier::checkedHit(StoreEntry *e)
{
    if (e)
        htcpTstReply(dhdr, e, this, from);		/* hit */
    else
        htcpTstReply(dhdr, NULL, NULL, from);	/* cache miss */

    htcpFreeSpecifier(this);
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

htcpHandleClr(htcpDataHeader * hdr, char *buf, int sz, struct sockaddr_in *from)
{
    htcpSpecifier *s;
    /* buf[0/1] is reserved and reason */
    int reason = buf[1] << 4;
    debug(31, 3) ("htcpHandleClr: reason=%d\n", reason);
    buf += 2;
    sz -= 2;

    /* buf should be a SPECIFIER */

    if (sz == 0)
    {
        debug(31, 4) ("htcpHandleClr: nothing to do\n");
        return;
    }

    s = htcpUnpackSpecifier(buf, sz);

    if (NULL == s)
    {
        debug(31, 3) ("htcpHandleClr: htcpUnpackSpecifier failed\n");
        return;
    }

    if (!htcpAccessCheck(Config.accessList.htcp_clr, s, from))
    {
        debug(31, 2) ("htcpHandleClr: Access denied\n");
        htcpFreeSpecifier(s);
        return;
    }

    debug(31, 5) ("htcpHandleClr: %s %s %s\n",
                  s->method,
                  s->uri,
                  s->version);
    debug(31, 5) ("htcpHandleClr: request headers: %s\n", s->req_hdrs);

    /* Release objects from cache
     * analog to clientPurgeRequest in client_side.c
     */

    switch (htcpClrStore(s))
    {

    case 1:
        htcpClrReply(hdr, 1, from);	/* hit */
        break;

    case 0:
        htcpClrReply(hdr, 0, from);	/* miss */
        break;

    default:
        break;
    }

    htcpFreeSpecifier(s);
}

static void

htcpHandleData(char *buf, int sz, struct sockaddr_in *from)
{
    htcpDataHeader hdr;

    if ((size_t)sz < sizeof(htcpDataHeader))
    {
        debug(31, 1) ("htcpHandleData: msg size less than htcpDataHeader size\n");
        return;
    }

    if (!old_squid_format)
    {
        xmemcpy(&hdr, buf, sizeof(hdr));
    } else
    {
        htcpDataHeaderSquid hdrSquid;
        xmemcpy(&hdrSquid, buf, sizeof(hdrSquid));
        hdr.length = hdrSquid.length;
        hdr.opcode = hdrSquid.opcode;
        hdr.response = hdrSquid.response;
        hdr.F1 = hdrSquid.F1;
        hdr.RR = hdrSquid.RR;
        hdr.reserved = 0;
        hdr.msg_id = hdrSquid.msg_id;
    }

    hdr.length = ntohs(hdr.length);
    hdr.msg_id = ntohl(hdr.msg_id);
    debug(31, 3) ("htcpHandleData: sz = %d\n", sz);
    debug(31, 3) ("htcpHandleData: length = %d\n", (int) hdr.length);

    if (hdr.opcode >= HTCP_END)
    {
        debug(31, 1) ("htcpHandleData: client %s, opcode %d out of range\n",
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

    if (sz < hdr.length)
    {
        debug(31, 1) ("htcpHandleData: sz < hdr.length\n");
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

    switch (hdr.opcode)
    {

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
        htcpHandleClr(&hdr, buf, sz, from);
        break;

    default:
        return;
    }
}

static void

htcpHandle(char *buf, int sz, struct sockaddr_in *from)
{
    htcpHeader htcpHdr;
    assert (sz >= 0);

    if ((size_t)sz < sizeof(htcpHeader))
    {
        debug(31, 1) ("htcpHandle: msg size less than htcpHeader size\n");
        return;
    }

    htcpHexdump("htcpHandle", buf, sz);
    xmemcpy(&htcpHdr, buf, sizeof(htcpHeader));
    htcpHdr.length = ntohs(htcpHdr.length);

    if (htcpHdr.minor == 0)
        old_squid_format = 1;
    else
        old_squid_format = 0;

    debug(31, 3) ("htcpHandle: htcpHdr.length = %d\n", (int) htcpHdr.length);

    debug(31, 3) ("htcpHandle: htcpHdr.major = %d\n", (int) htcpHdr.major);

    debug(31, 3) ("htcpHandle: htcpHdr.minor = %d\n", (int) htcpHdr.minor);

    if (sz != htcpHdr.length)
    {
        debug(31, 1) ("htcpHandle: sz/%d != htcpHdr.length/%d from %s:%d\n",
                      sz, htcpHdr.length,
                      inet_ntoa(from->sin_addr), (int) ntohs(from->sin_port));
        return;
    }

    if (htcpHdr.major != 0)
    {
        debug(31, 1) ("htcpHandle: Unknown major version %d from %s:%d\n",
                      htcpHdr.major,
                      inet_ntoa(from->sin_addr), (int) ntohs(from->sin_port));
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

    socklen_t flen = sizeof(struct sockaddr_in);
    memset(&from, '\0', flen);

    /* Receive up to 8191 bytes, leaving room for a null */

    len = comm_udp_recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *) &from, &flen);
    debug(31, 3) ("htcpRecv: FD %d, %d bytes from %s:%d\n",
                  fd, len, inet_ntoa(from.sin_addr), ntohs(from.sin_port));

    if (len)
        statCounter.htcp.pkts_recv++;

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
                             IPPROTO_UDP,
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
                                  IPPROTO_UDP,
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

    if (!htcpDetailPool) {
        htcpDetailPool = memPoolCreate("htcpDetail", sizeof(htcpDetail));
    }
}

void
htcpQuery(StoreEntry * e, HttpRequest * req, peer * p)
{
    cache_key *save_key;
    static char pkt[8192];
    ssize_t pktlen;
    char vbuf[32];
    htcpStuff stuff;
    HttpHeader hdr(hoRequest);
    Packer pa;
    MemBuf mb;
    http_state_flags flags;

    if (htcpInSocket < 0)
        return;

    old_squid_format = p->options.htcp_oldsquid;

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

    HttpStateData::httpBuildRequestHeader(req, req, e, &hdr, flags);

    mb.init();

    packerToMemInit(&pa, &mb);

    hdr.packInto(&pa);

    hdr.clean();

    packerClean(&pa);

    stuff.S.req_hdrs = mb.buf;

    pktlen = htcpBuildPacket(pkt, sizeof(pkt), &stuff);

    mb.clean();

    if (!pktlen) {
        debug(31, 1) ("htcpQuery: htcpBuildPacket() failed\n");
        return;
    }

    htcpSend(pkt, (int) pktlen, &p->in_addr);
    queried_id[stuff.msg_id % N_QUERIED_KEYS] = stuff.msg_id;
    save_key = queried_keys[stuff.msg_id % N_QUERIED_KEYS];
    storeKeyCopy(save_key, (const cache_key *)e->key);
    queried_addr[stuff.msg_id % N_QUERIED_KEYS] = p->in_addr;
    debug(31, 3) ("htcpQuery: key (%p) %s\n", save_key, storeKeyText(save_key));
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
