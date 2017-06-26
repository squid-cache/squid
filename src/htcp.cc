/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 31    Hypertext Caching Protocol */

#include "squid.h"
#include "AccessLogEntry.h"
#include "acl/Acl.h"
#include "acl/FilledChecklist.h"
#include "CachePeer.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "comm/UdpOpenDialer.h"
#include "compat/xalloc.h"
#include "globals.h"
#include "htcp.h"
#include "http.h"
#include "HttpRequest.h"
#include "icmp/net_db.h"
#include "ip/tools.h"
#include "md5.h"
#include "mem/forward.h"
#include "MemBuf.h"
#include "refresh.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "Store.h"
#include "store_key_md5.h"
#include "StoreClient.h"
#include "tools.h"
#include "URL.h"

typedef struct _Countstr Countstr;

typedef struct _htcpHeader htcpHeader;

typedef struct _htcpDataHeader htcpDataHeader;

typedef struct _htcpDataHeaderSquid htcpDataHeaderSquid;

typedef struct _htcpAuthHeader htcpAuthHeader;

struct _Countstr {
    uint16_t length;
    char *text;
};

struct _htcpHeader {
    uint16_t length;
    u_char major;
    u_char minor;
};

struct _htcpDataHeaderSquid {
    uint16_t length;

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

    uint32_t msg_id;
};

struct _htcpDataHeader {
    uint16_t length;

#if WORDS_BIGENDIAN
    uint8_t opcode:4;
    uint8_t response:4;
#else
    uint8_t response:4;
    uint8_t opcode:4;
#endif

#if WORDS_BIGENDIAN
    uint8_t reserved:6;
    uint8_t F1:1;
    uint8_t RR:1;
#else
    uint8_t RR:1;
    uint8_t F1:1;
    uint8_t reserved:6;
#endif

    uint32_t msg_id;
};

/* RR == 0 --> F1 = RESPONSE DESIRED FLAG */
/* RR == 1 --> F1 = MESSAGE OVERALL FLAG */
/* RR == 0 --> REQUEST */
/* RR == 1 --> RESPONSE */

struct _htcpAuthHeader {
    uint16_t length;
    time_t sig_time;
    time_t sig_expire;
    Countstr key_name;
    Countstr signature;
};

class htcpSpecifier : public RefCountable, public StoreClient
{
    MEMPROXY_CLASS(htcpSpecifier);

public:
    typedef RefCount<htcpSpecifier> Pointer;

    void checkHit();
    void checkedHit(StoreEntry *);

    void setFrom(Ip::Address &anIp) { from = anIp; }
    void setDataHeader(htcpDataHeader *aDataHeader) {
        dhdr = aDataHeader;
    }

    /* StoreClient API */
    void created(StoreEntry *);

public:
    const char *method = nullptr;
    char *uri = nullptr;
    char *version = nullptr;
    char *req_hdrs = nullptr;
    size_t reqHdrsSz = 0; ///< size of the req_hdrs content
    HttpRequest::Pointer request;

private:
    HttpRequest::Pointer checkHitRequest;

    Ip::Address from;
    htcpDataHeader *dhdr = nullptr;
};

class htcpDetail {
    MEMPROXY_CLASS(htcpDetail);
public:
    htcpDetail() : resp_hdrs(nullptr), respHdrsSz(0), entity_hdrs(nullptr), entityHdrsSz(0), cache_hdrs(nullptr), cacheHdrsSz(0) {}
    char *resp_hdrs;
    size_t respHdrsSz;

    char *entity_hdrs;
    size_t entityHdrsSz;

    char *cache_hdrs;
    size_t cacheHdrsSz;
};

class htcpStuff
{
public:
    htcpStuff(uint32_t id, int o, int r, int f) :
        op(o),
        rr(r),
        f1(f),
        response(0),
        reason(0),
        msg_id(id)
    {
        memset(&D, 0, sizeof(D));
    }

    int op;
    int rr;
    int f1;
    int response;
    int reason;
    uint32_t msg_id;
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

static void htcpIncomingConnectionOpened(const Comm::ConnectionPointer &conn, int errNo);
static uint32_t msg_id_counter = 0;

static Comm::ConnectionPointer htcpOutgoingConn = NULL;
static Comm::ConnectionPointer htcpIncomingConn = NULL;
#define N_QUERIED_KEYS 8192
static uint32_t queried_id[N_QUERIED_KEYS];
static cache_key queried_keys[N_QUERIED_KEYS][SQUID_MD5_DIGEST_LENGTH];

static Ip::Address queried_addr[N_QUERIED_KEYS];

static int old_squid_format = 0;

static ssize_t htcpBuildPacket(char *buf, size_t buflen, htcpStuff * stuff);
static htcpDetail *htcpUnpackDetail(char *buf, int sz);
static ssize_t htcpBuildAuth(char *buf, size_t buflen);
static ssize_t htcpBuildCountstr(char *buf, size_t buflen, const char *s, size_t len);
static ssize_t htcpBuildData(char *buf, size_t buflen, htcpStuff * stuff);
static ssize_t htcpBuildDetail(char *buf, size_t buflen, htcpStuff * stuff);
static ssize_t htcpBuildOpData(char *buf, size_t buflen, htcpStuff * stuff);
static ssize_t htcpBuildSpecifier(char *buf, size_t buflen, htcpStuff * stuff);
static ssize_t htcpBuildTstOpData(char *buf, size_t buflen, htcpStuff * stuff);

static void htcpHandleMsg(char *buf, int sz, Ip::Address &from);

static void htcpLogHtcp(Ip::Address &, int, LogTags, const char *);
static void htcpHandleTst(htcpDataHeader *, char *buf, int sz, Ip::Address &from);

static void htcpRecv(int fd, void *data);

static void htcpSend(const char *buf, int len, Ip::Address &to);

static void htcpTstReply(htcpDataHeader *, StoreEntry *, htcpSpecifier *, Ip::Address &);

static void htcpHandleTstRequest(htcpDataHeader *, char *buf, int sz, Ip::Address &from);

static void htcpHandleTstResponse(htcpDataHeader *, char *, int, Ip::Address &);

static void
htcpHexdump(const char *tag, const char *s, int sz)
{
#if USE_HEXDUMP
    char hex[80];
    debugs(31, 3, "htcpHexdump " << tag);
    memset(hex, '\0', sizeof(hex));

    for (int i = 0; i < sz; ++i) {
        int k = i % 16;
        snprintf(&hex[k * 3], 4, " %02x", (int) *(s + i));

        if (k < 15 && i < (sz - 1))
            continue;

        debugs(31, 3, "\t" << hex);

        memset(hex, '\0', sizeof(hex));
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
    assert(2 == sizeof(uint16_t));
    auth.length = htons(2);
    copy_sz += 2;
    if (buflen < copy_sz)
        return -1;
    memcpy(buf, &auth, copy_sz);
    return copy_sz;
}

static ssize_t
htcpBuildCountstr(char *buf, size_t buflen, const char *s, size_t len)
{
    int off = 0;

    if (buflen - off < 2)
        return -1;

    debugs(31, 3, "htcpBuildCountstr: LENGTH = " << len);

    debugs(31, 3, "htcpBuildCountstr: TEXT = {" << (s ? s : "<NULL>") << "}");

    uint16_t length = htons((uint16_t) len);

    memcpy(buf + off, &length, 2);

    off += 2;

    if (buflen - off < len)
        return -1;

    if (len)
        memcpy(buf + off, s, len);

    off += len;

    return off;
}

static ssize_t
htcpBuildSpecifier(char *buf, size_t buflen, htcpStuff * stuff)
{
    ssize_t off = 0;
    ssize_t s;
    s = htcpBuildCountstr(buf + off, buflen - off, stuff->S.method, (stuff->S.method?strlen(stuff->S.method):0));

    if (s < 0)
        return s;

    off += s;

    s = htcpBuildCountstr(buf + off, buflen - off, stuff->S.uri, (stuff->S.uri?strlen(stuff->S.uri):0));

    if (s < 0)
        return s;

    off += s;

    s = htcpBuildCountstr(buf + off, buflen - off, stuff->S.version, (stuff->S.version?strlen(stuff->S.version):0));

    if (s < 0)
        return s;

    off += s;

    s = htcpBuildCountstr(buf + off, buflen - off, stuff->S.req_hdrs, stuff->S.reqHdrsSz);

    if (s < 0)
        return s;

    off += s;

    debugs(31, 3, "htcpBuildSpecifier: size " << off);

    return off;
}

static ssize_t
htcpBuildDetail(char *buf, size_t buflen, htcpStuff * stuff)
{
    ssize_t off = 0;
    ssize_t s;
    s = htcpBuildCountstr(buf + off, buflen - off, stuff->D.resp_hdrs, stuff->D.respHdrsSz);

    if (s < 0)
        return s;

    off += s;

    s = htcpBuildCountstr(buf + off, buflen - off, stuff->D.entity_hdrs, stuff->D.entityHdrsSz);

    if (s < 0)
        return s;

    off += s;

    s = htcpBuildCountstr(buf + off, buflen - off, stuff->D.cache_hdrs, stuff->D.cacheHdrsSz);

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
        debugs(31, 3, "htcpBuildTstOpData: RR_REQUEST");
        return htcpBuildSpecifier(buf, buflen, stuff);

    case RR_RESPONSE:
        debugs(31, 3, "htcpBuildTstOpData: RR_RESPONSE");
        debugs(31, 3, "htcpBuildTstOpData: F1 = " << stuff->f1);

        if (stuff->f1)      /* cache miss */
            return 0;
        else            /* cache hit */
            return htcpBuildDetail(buf, buflen, stuff);

    default:
        fatal_dump("htcpBuildTstOpData: bad RR value");
    }

    return 0;
}

static ssize_t
htcpBuildClrOpData(char *buf, size_t buflen, htcpStuff * stuff)
{
    unsigned short reason;

    switch (stuff->rr) {
    case RR_REQUEST:
        debugs(31, 3, "htcpBuildClrOpData: RR_REQUEST");
        reason = htons((unsigned short)stuff->reason);
        memcpy(buf, &reason, 2);
        return htcpBuildSpecifier(buf + 2, buflen - 2, stuff) + 2;
    case RR_RESPONSE:
        break;
    default:
        fatal_dump("htcpBuildClrOpData: bad RR value");
    }

    return 0;
}

static ssize_t
htcpBuildOpData(char *buf, size_t buflen, htcpStuff * stuff)
{
    ssize_t off = 0;
    debugs(31, 3, "htcpBuildOpData: opcode " << htcpOpcodeStr[stuff->op]);

    switch (stuff->op) {

    case HTCP_TST:
        off = htcpBuildTstOpData(buf + off, buflen, stuff);
        break;

    case HTCP_CLR:
        off = htcpBuildClrOpData(buf + off, buflen, stuff);
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

    if (buflen < hdr_sz)
        return -1;

    off += hdr_sz;      /* skip! */

    op_data_sz = htcpBuildOpData(buf + off, buflen - off, stuff);

    if (op_data_sz < 0)
        return op_data_sz;

    off += op_data_sz;

    debugs(31, 3, "htcpBuildData: hdr.length = " << off);

    if (!old_squid_format) {
        htcpDataHeader hdr;
        memset(&hdr, 0, sizeof(hdr));
        /* convert multi-byte fields */
        hdr.msg_id = htonl(stuff->msg_id);
        hdr.length = htons(static_cast<uint16_t>(off));
        hdr.opcode = stuff->op;
        hdr.response = stuff->response;
        hdr.RR = stuff->rr;
        hdr.F1 = stuff->f1;
        memcpy(buf, &hdr, hdr_sz);
    } else {
        htcpDataHeaderSquid hdrSquid;
        memset(&hdrSquid, 0, sizeof(hdrSquid));
        hdrSquid.length = htons(static_cast<uint16_t>(off));
        hdrSquid.opcode = stuff->op;
        hdrSquid.response = stuff->response;
        hdrSquid.F1 = stuff->f1;
        hdrSquid.RR = stuff->rr;
        memcpy(buf, &hdrSquid, hdr_sz);
    }

    debugs(31, 3, "htcpBuildData: size " << off);

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
    hdr.length = htons((uint16_t) off);
    hdr.major = 0;

    if (old_squid_format)
        hdr.minor = 0;
    else
        hdr.minor = 1;

    memcpy(buf, &hdr, hdr_sz);

    debugs(31, 3, "htcpBuildPacket: size " << off);

    return off;
}

static void
htcpSend(const char *buf, int len, Ip::Address &to)
{
    debugs(31, 3, to);
    htcpHexdump("htcpSend", buf, len);

    if (comm_udp_sendto(htcpOutgoingConn->fd, to, buf, len) < 0) {
        int xerrno = errno;
        debugs(31, 3, htcpOutgoingConn << " sendto: " << xstrerr(xerrno));
    } else
        ++statCounter.htcp.pkts_sent;
}

/*
 * Unpack an HTCP SPECIFIER in place
 * This will overwrite any following AUTH block
 */
// XXX: this needs to be turned into an Htcp1::Parser inheriting from Http1::RequestParser
//   but with different first-line and block unpacking logic.
static htcpSpecifier::Pointer
htcpUnpackSpecifier(char *buf, int sz)
{
    static const htcpSpecifier::Pointer nil;
    htcpSpecifier::Pointer s(new htcpSpecifier);
    HttpRequestMethod method;

    /* Find length of METHOD */
    uint16_t l = ntohs(*(uint16_t *) buf);
    sz -= 2;
    buf += 2;

    if (l > sz) {
        debugs(31, 3, "htcpUnpackSpecifier: failed to unpack METHOD");
        return nil;
    }

    /* Set METHOD */
    s->method = buf;
    buf += l;
    sz -= l;
    debugs(31, 6, "htcpUnpackSpecifier: METHOD (" << l << "/" << sz << ") '" << s->method << "'");

    /* Find length of URI */
    l = ntohs(*(uint16_t *) buf);
    sz -= 2;

    if (l > sz) {
        debugs(31, 3, "htcpUnpackSpecifier: failed to unpack URI");
        return nil;
    }

    /* Add terminating null to METHOD */
    *buf = '\0';
    buf += 2;

    /* Set URI */
    s->uri = buf;
    buf += l;
    sz -= l;
    debugs(31, 6, "htcpUnpackSpecifier: URI (" << l << "/" << sz << ") '" << s->uri << "'");

    /* Find length of VERSION */
    l = ntohs(*(uint16_t *) buf);
    sz -= 2;

    if (l > sz) {
        debugs(31, 3, "htcpUnpackSpecifier: failed to unpack VERSION");
        return nil;
    }

    /* Add terminating null to URI */
    *buf = '\0';
    buf += 2;

    /* Set VERSION */
    s->version = buf;
    buf += l;
    sz -= l;
    debugs(31, 6, "htcpUnpackSpecifier: VERSION (" << l << "/" << sz << ") '" << s->version << "'");

    /* Find length of REQ-HDRS */
    l = ntohs(*(uint16_t *) buf);
    sz -= 2;

    if (l > sz) {
        debugs(31, 3, "htcpUnpackSpecifier: failed to unpack REQ-HDRS");
        return nil;
    }

    /* Add terminating null to URI */
    *buf = '\0';
    buf += 2;

    /* Set REQ-HDRS */
    s->req_hdrs = buf;
    buf += l;
    sz -= l;
    s->reqHdrsSz = l;
    debugs(31, 6, "htcpUnpackSpecifier: REQ-HDRS (" << l << "/" << sz << ") '" << s->req_hdrs << "'");

    debugs(31, 3, "htcpUnpackSpecifier: " << sz << " bytes left");

    /*
     * Add terminating null to REQ-HDRS. This is possible because we allocated
     * an extra byte when we received the packet. This will overwrite any following
     * AUTH block.
     */
    *buf = '\0';

    // Parse the request
    method.HttpRequestMethodXXX(s->method);

    const MasterXaction::Pointer mx = new MasterXaction(XactionInitiator::initHtcp);
    s->request = HttpRequest::FromUrl(s->uri, mx, method == Http::METHOD_NONE ? HttpRequestMethod(Http::METHOD_GET) : method);
    return s;
}

/*
 * Unpack an HTCP DETAIL in place
 * This will overwrite any following AUTH block
 */
static htcpDetail *
htcpUnpackDetail(char *buf, int sz)
{
    htcpDetail *d = new htcpDetail;

    /* Find length of RESP-HDRS */
    uint16_t l = ntohs(*(uint16_t *) buf);
    sz -= 2;
    buf += 2;

    if (l > sz) {
        debugs(31, 3, "htcpUnpackDetail: failed to unpack RESP_HDRS");
        delete d;
        return NULL;
    }

    /* Set RESP-HDRS */
    d->resp_hdrs = buf;
    buf += l;
    d->respHdrsSz = l;
    sz -= l;

    /* Find length of ENTITY-HDRS */
    l = ntohs(*(uint16_t *) buf);

    sz -= 2;

    if (l > sz) {
        debugs(31, 3, "htcpUnpackDetail: failed to unpack ENTITY_HDRS");
        delete d;
        return NULL;
    }

    /* Add terminating null to RESP-HDRS */
    *buf = '\0';

    /* Set ENTITY-HDRS */
    buf += 2;

    d->entity_hdrs = buf;
    buf += l;
    d->entityHdrsSz = l;
    sz -= l;

    /* Find length of CACHE-HDRS */
    l = ntohs(*(uint16_t *) buf);

    sz -= 2;

    if (l > sz) {
        debugs(31, 3, "htcpUnpackDetail: failed to unpack CACHE_HDRS");
        delete d;
        return NULL;
    }

    /* Add terminating null to ENTITY-HDRS */
    *buf = '\0';

    /* Set CACHE-HDRS */
    buf += 2;

    d->cache_hdrs = buf;
    buf += l;
    d->cacheHdrsSz = l;
    sz -= l;

    debugs(31, 3, "htcpUnpackDetail: " << sz << " bytes left");

    /*
     * Add terminating null to CACHE-HDRS. This is possible because we allocated
     * an extra byte when we received the packet. This will overwrite any following
     * AUTH block.
     */
    *buf = '\0';

    return d;
}

static bool
htcpAccessAllowed(acl_access * acl, const htcpSpecifier::Pointer &s, Ip::Address &from)
{
    /* default deny if no access list present */
    if (!acl)
        return false;

    ACLFilledChecklist checklist(acl, s->request.getRaw(), nullptr);
    checklist.src_addr = from;
    checklist.my_addr.setNoAddr();
    return checklist.fastCheck().allowed();
}

static void
htcpTstReply(htcpDataHeader * dhdr, StoreEntry * e, htcpSpecifier * spec, Ip::Address &from)
{
    static char pkt[8192];
    HttpHeader hdr(hoHtcpReply);
    ssize_t pktlen;

    htcpStuff stuff(dhdr->msg_id, HTCP_TST, RR_RESPONSE, 0);
    stuff.response = e ? 0 : 1;
    debugs(31, 3, "htcpTstReply: response = " << stuff.response);

    if (spec) {
        stuff.S.method = spec->method;
        stuff.S.uri = spec->uri;
        stuff.S.version = spec->version;
        stuff.S.req_hdrs = spec->req_hdrs;
        stuff.S.reqHdrsSz = spec->reqHdrsSz;
        if (e)
            hdr.putInt(Http::HdrType::AGE, (e->timestamp <= squid_curtime ? (squid_curtime - e->timestamp) : 0) );
        else
            hdr.putInt(Http::HdrType::AGE, 0);
        MemBuf mb;
        mb.init();
        hdr.packInto(&mb);
        stuff.D.resp_hdrs = xstrdup(mb.buf);
        stuff.D.respHdrsSz = mb.contentSize();
        debugs(31, 3, "htcpTstReply: resp_hdrs = {" << stuff.D.resp_hdrs << "}");
        mb.reset();
        hdr.clean();

        if (e && e->expires > -1)
            hdr.putTime(Http::HdrType::EXPIRES, e->expires);

        if (e && e->lastModified() > -1)
            hdr.putTime(Http::HdrType::LAST_MODIFIED, e->lastModified());

        hdr.packInto(&mb);

        stuff.D.entity_hdrs = xstrdup(mb.buf);
        stuff.D.entityHdrsSz = mb.contentSize();

        debugs(31, 3, "htcpTstReply: entity_hdrs = {" << stuff.D.entity_hdrs << "}");

        mb.reset();
        hdr.clean();

#if USE_ICMP
        if (char *host = urlHostname(spec->uri)) {
            int rtt = 0;
            int hops = 0;
            int samp = 0;
            netdbHostData(host, &samp, &rtt, &hops);

            if (rtt || hops) {
                char cto_buf[128];
                snprintf(cto_buf, 128, "%s %d %f %d",
                         host, samp, 0.001 * rtt, hops);
                hdr.putExt("Cache-to-Origin", cto_buf);
            }
        }
#endif /* USE_ICMP */

        hdr.packInto(&mb);
        stuff.D.cache_hdrs = xstrdup(mb.buf);
        stuff.D.cacheHdrsSz = mb.contentSize();
        debugs(31, 3, "htcpTstReply: cache_hdrs = {" << stuff.D.cache_hdrs << "}");
        mb.clean();
        hdr.clean();
    }

    pktlen = htcpBuildPacket(pkt, sizeof(pkt), &stuff);

    safe_free(stuff.D.resp_hdrs);
    stuff.D.respHdrsSz = 0;
    safe_free(stuff.D.entity_hdrs);
    stuff.D.entityHdrsSz = 0;
    safe_free(stuff.D.cache_hdrs);
    stuff.D.cacheHdrsSz = 0;

    if (!pktlen) {
        debugs(31, 3, "htcpTstReply: htcpBuildPacket() failed");
        return;
    }

    htcpSend(pkt, (int) pktlen, from);
}

static void

htcpClrReply(htcpDataHeader * dhdr, int purgeSucceeded, Ip::Address &from)
{
    static char pkt[8192];
    ssize_t pktlen;

    /* If dhdr->F1 == 0, no response desired */

    if (dhdr->F1 == 0)
        return;

    htcpStuff stuff(dhdr->msg_id, HTCP_CLR, RR_RESPONSE, 0);

    stuff.response = purgeSucceeded ? 0 : 2;

    debugs(31, 3, "htcpClrReply: response = " << stuff.response);

    pktlen = htcpBuildPacket(pkt, sizeof(pkt), &stuff);

    if (pktlen == 0) {
        debugs(31, 3, "htcpClrReply: htcpBuildPacket() failed");
        return;
    }

    htcpSend(pkt, (int) pktlen, from);
}

void
htcpSpecifier::checkHit()
{
    checkHitRequest = request;

    if (!checkHitRequest) {
        debugs(31, 3, "htcpCheckHit: NO; failed to parse URL");
        checkedHit(NullStoreEntry::getInstance());
        return;
    }

    if (!checkHitRequest->header.parse(req_hdrs, reqHdrsSz)) {
        debugs(31, 3, "htcpCheckHit: NO; failed to parse request headers");
        checkHitRequest = nullptr;
        checkedHit(NullStoreEntry::getInstance());
        return;
    }

    StoreEntry::getPublicByRequest(this, checkHitRequest.getRaw());
}

void
htcpSpecifier::created(StoreEntry *e)
{
    StoreEntry *hit = nullptr;

    if (!e || e->isNull()) {
        debugs(31, 3, "htcpCheckHit: NO; public object not found");
    } else if (!e->validToSend()) {
        debugs(31, 3, "htcpCheckHit: NO; entry not valid to send" );
    } else if (refreshCheckHTCP(e, checkHitRequest.getRaw())) {
        debugs(31, 3, "htcpCheckHit: NO; cached response is stale");
    } else {
        debugs(31, 3, "htcpCheckHit: YES!?");
        hit = e;
    }

    checkedHit(hit);
}

static void
htcpClrStoreEntry(StoreEntry * e)
{
    debugs(31, 4, "htcpClrStoreEntry: Clearing store for entry: " << e->url()  );
    e->releaseRequest();
}

static int
htcpClrStore(const htcpSpecifier::Pointer &s)
{
    HttpRequestPointer request(s->request);
    if (!request) {
        debugs(31, 3, "htcpClrStore: failed to parse URL");
        return -1;
    }

    /* Parse request headers */
    if (!request->header.parse(s->req_hdrs, s->reqHdrsSz)) {
        debugs(31, 2, "htcpClrStore: failed to parse request headers");
        return -1;
    }

    StoreEntry *e = nullptr;
    int released = 0;
    /* Lookup matching entries. This matches both GET and HEAD */
    while ((e = storeGetPublicByRequest(request.getRaw()))) {
        htcpClrStoreEntry(e);
        ++released;
    }

    if (released) {
        debugs(31, 4, "htcpClrStore: Cleared " << released << " matching entries");
        return 1;
    } else {
        debugs(31, 4, "htcpClrStore: No matching entry found");
        return 0;
    }
}

static void

htcpHandleTst(htcpDataHeader * hdr, char *buf, int sz, Ip::Address &from)
{
    debugs(31, 3, "htcpHandleTst: sz = " << sz);

    if (hdr->RR == RR_REQUEST)
        htcpHandleTstRequest(hdr, buf, sz, from);
    else
        htcpHandleTstResponse(hdr, buf, sz, from);
}

HtcpReplyData::HtcpReplyData() :
    hit(0), hdr(hoHtcpReply), msg_id(0), version(0.0)
{
    memset(&cto, 0, sizeof(cto));
}

static void

htcpHandleTstResponse(htcpDataHeader * hdr, char *buf, int sz, Ip::Address &from)
{
    HtcpReplyData htcpReply;
    cache_key *key = NULL;

    Ip::Address *peer;
    htcpDetail *d = NULL;
    char *t;

    if (queried_id[hdr->msg_id % N_QUERIED_KEYS] != hdr->msg_id) {
        debugs(31, 2, "htcpHandleTstResponse: No matching query id '" <<
               hdr->msg_id << "' (expected " <<
               queried_id[hdr->msg_id % N_QUERIED_KEYS] << ") from '" <<
               from << "'");

        return;
    }

    key = queried_keys[hdr->msg_id % N_QUERIED_KEYS];

    if (!key) {
        debugs(31, 3, "htcpHandleTstResponse: No query key for response id '" << hdr->msg_id << "' from '" << from << "'");
        return;
    }

    peer = &queried_addr[hdr->msg_id % N_QUERIED_KEYS];

    if ( *peer != from || peer->port() != from.port() ) {
        debugs(31, 3, "htcpHandleTstResponse: Unexpected response source " << from );
        return;
    }

    if (hdr->F1 == 1) {
        debugs(31, 2, "htcpHandleTstResponse: error condition, F1/MO == 1");
        return;
    }

    htcpReply.msg_id = hdr->msg_id;
    debugs(31, 3, "htcpHandleTstResponse: msg_id = " << htcpReply.msg_id);
    htcpReply.hit = hdr->response ? 0 : 1;

    if (hdr->F1) {
        debugs(31, 3, "htcpHandleTstResponse: MISS");
    } else {
        debugs(31, 3, "htcpHandleTstResponse: HIT");
        d = htcpUnpackDetail(buf, sz);

        if (d == NULL) {
            debugs(31, 3, "htcpHandleTstResponse: bad DETAIL");
            return;
        }

        if ((t = d->resp_hdrs))
            htcpReply.hdr.parse(t, d->respHdrsSz);

        if ((t = d->entity_hdrs))
            htcpReply.hdr.parse(t, d->entityHdrsSz);

        if ((t = d->cache_hdrs))
            htcpReply.hdr.parse(t, d->cacheHdrsSz);
    }

    debugs(31, 3, "htcpHandleTstResponse: key (" << key << ") " << storeKeyText(key));
    neighborsHtcpReply(key, &htcpReply, from);
    htcpReply.hdr.clean();

    delete d;
}

static void
htcpHandleTstRequest(htcpDataHeader * dhdr, char *buf, int sz, Ip::Address &from)
{
    if (sz == 0) {
        debugs(31, 3, "htcpHandleTst: nothing to do");
        return;
    }

    if (dhdr->F1 == 0)
        return;

    /* buf should be a SPECIFIER */
    htcpSpecifier::Pointer s(htcpUnpackSpecifier(buf, sz));

    if (!s) {
        debugs(31, 3, "htcpHandleTstRequest: htcpUnpackSpecifier failed");
        htcpLogHtcp(from, dhdr->opcode, LOG_UDP_INVALID, dash_str);
        return;
    } else {
        s->setFrom(from);
        s->setDataHeader(dhdr);
    }

    if (!s->request) {
        debugs(31, 3, "htcpHandleTstRequest: failed to parse request");
        htcpLogHtcp(from, dhdr->opcode, LOG_UDP_INVALID, dash_str);
        return;
    }

    if (!htcpAccessAllowed(Config.accessList.htcp, s, from)) {
        debugs(31, 3, "htcpHandleTstRequest: Access denied");
        htcpLogHtcp(from, dhdr->opcode, LOG_UDP_DENIED, s->uri);
        return;
    }

    debugs(31, 2, "HTCP TST request: " << s->method << " " << s->uri << " " << s->version);
    debugs(31, 2, "HTCP TST headers: " << s->req_hdrs);
    s->checkHit();
}

void
htcpSpecifier::checkedHit(StoreEntry *e)
{
    if (e) {
        htcpTstReply(dhdr, e, this, from);      /* hit */
        htcpLogHtcp(from, dhdr->opcode, LOG_UDP_HIT, uri);
    } else {
        htcpTstReply(dhdr, NULL, NULL, from);   /* cache miss */
        htcpLogHtcp(from, dhdr->opcode, LOG_UDP_MISS, uri);
    }
}

static void
htcpHandleClr(htcpDataHeader * hdr, char *buf, int sz, Ip::Address &from)
{
    /* buf[0/1] is reserved and reason */
    int reason = buf[1] << 4;
    debugs(31, 2, "HTCP CLR reason: " << reason);
    buf += 2;
    sz -= 2;

    /* buf should be a SPECIFIER */

    if (sz == 0) {
        debugs(31, 4, "htcpHandleClr: nothing to do");
        htcpLogHtcp(from, hdr->opcode, LOG_UDP_INVALID, dash_str);
        return;
    }

    htcpSpecifier::Pointer s(htcpUnpackSpecifier(buf, sz));

    if (!s) {
        debugs(31, 3, "htcpHandleClr: htcpUnpackSpecifier failed");
        htcpLogHtcp(from, hdr->opcode, LOG_UDP_INVALID, dash_str);
        return;
    }

    if (!s->request) {
        debugs(31, 3, "htcpHandleTstRequest: failed to parse request");
        htcpLogHtcp(from, hdr->opcode, LOG_UDP_INVALID, dash_str);
        return;
    }

    if (!htcpAccessAllowed(Config.accessList.htcp_clr, s, from)) {
        debugs(31, 3, "htcpHandleClr: Access denied");
        htcpLogHtcp(from, hdr->opcode, LOG_UDP_DENIED, s->uri);
        return;
    }

    debugs(31, 2, "HTCP CLR request: " << s->method << " " << s->uri << " " << s->version);
    debugs(31, 2, "HTCP CLR headers: " << s->req_hdrs);

    /* Release objects from cache
     * analog to clientPurgeRequest in client_side.c
     */

    switch (htcpClrStore(s)) {

    case 1:
        htcpClrReply(hdr, 1, from); /* hit */
        htcpLogHtcp(from, hdr->opcode, LOG_UDP_HIT, s->uri);
        break;

    case 0:
        htcpClrReply(hdr, 0, from); /* miss */
        htcpLogHtcp(from, hdr->opcode, LOG_UDP_MISS, s->uri);
        break;

    default:
        break;
    }
}

/*
 * Forward a CLR request to all peers who have requested that CLRs be
 * forwarded to them.
 */
static void
htcpForwardClr(char *buf, int sz)
{
    CachePeer *p;

    for (p = Config.peers; p; p = p->next) {
        if (!p->options.htcp) {
            continue;
        }
        if (!p->options.htcp_forward_clr) {
            continue;
        }

        htcpSend(buf, sz, p->in_addr);
    }
}

/*
 * Do the first pass of handling an HTCP message.  This used to be two
 * separate functions, htcpHandle and htcpHandleData.  They were merged to
 * allow for forwarding HTCP packets easily to other peers if desired.
 *
 * This function now works out what type of message we have received and then
 * hands it off to other functions to break apart message-specific data.
 */
static void
htcpHandleMsg(char *buf, int sz, Ip::Address &from)
{
    htcpHeader htcpHdr;
    htcpDataHeader hdr;
    char *hbuf;
    int hsz;

    if (sz < 0 || (size_t)sz < sizeof(htcpHeader)) {
        // These are highly likely to be attack packets. Should probably get a bigger warning.
        debugs(31, 2, "htcpHandle: msg size less than htcpHeader size from " << from);
        return;
    }

    htcpHexdump("htcpHandle", buf, sz);
    memcpy(&htcpHdr, buf, sizeof(htcpHeader));
    htcpHdr.length = ntohs(htcpHdr.length);

    if (htcpHdr.minor == 0)
        old_squid_format = 1;
    else
        old_squid_format = 0;

    debugs(31, 3, "htcpHandle: htcpHdr.length = " << htcpHdr.length);
    debugs(31, 3, "htcpHandle: htcpHdr.major = " << htcpHdr.major);
    debugs(31, 3, "htcpHandle: htcpHdr.minor = " << htcpHdr.minor);

    if (sz != htcpHdr.length) {
        debugs(31, 3, "htcpHandle: sz/" << sz << " != htcpHdr.length/" <<
               htcpHdr.length << " from " << from );

        return;
    }

    if (htcpHdr.major != 0) {
        debugs(31, 3, "htcpHandle: Unknown major version " << htcpHdr.major << " from " << from );

        return;
    }

    hbuf = buf + sizeof(htcpHeader);
    hsz = sz - sizeof(htcpHeader);

    if ((size_t)hsz < sizeof(htcpDataHeader)) {
        debugs(31, 3, "htcpHandleData: msg size less than htcpDataHeader size");
        return;
    }

    if (!old_squid_format) {
        memcpy(&hdr, hbuf, sizeof(hdr));
    } else {
        htcpDataHeaderSquid hdrSquid;
        memcpy(&hdrSquid, hbuf, sizeof(hdrSquid));
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
    debugs(31, 3, "htcpHandleData: hsz = " << hsz);
    debugs(31, 3, "htcpHandleData: length = " << hdr.length);

    if (hdr.opcode >= HTCP_END) {
        debugs(31, 3, "htcpHandleData: client " << from << ", opcode " << hdr.opcode << " out of range");
        return;
    }

    debugs(31, 3, "htcpHandleData: opcode = " << hdr.opcode << " " << htcpOpcodeStr[hdr.opcode]);
    debugs(31, 3, "htcpHandleData: response = " << hdr.response);
    debugs(31, 3, "htcpHandleData: F1 = " << hdr.F1);
    debugs(31, 3, "htcpHandleData: RR = " << hdr.RR);
    debugs(31, 3, "htcpHandleData: msg_id = " << hdr.msg_id);

    if (hsz < hdr.length) {
        debugs(31, 3, "htcpHandleData: sz < hdr.length");
        return;
    }

    /*
     * set sz = hdr.length so we ignore any AUTH fields following
     * the DATA.
     */
    hsz = (int) hdr.length;
    hbuf += sizeof(htcpDataHeader);
    hsz -= sizeof(htcpDataHeader);
    debugs(31, 3, "htcpHandleData: hsz = " << hsz);

    htcpHexdump("htcpHandleData", hbuf, hsz);

    switch (hdr.opcode) {
    case HTCP_NOP:
        debugs(31, 3, "HTCP NOP not implemented");
        break;
    case HTCP_TST:
        htcpHandleTst(&hdr, hbuf, hsz, from);
        break;
    case HTCP_MON:
        debugs(31, 3, "HTCP MON not implemented");
        break;
    case HTCP_SET:
        debugs(31, 3, "HTCP SET not implemented");
        break;
    case HTCP_CLR:
        htcpHandleClr(&hdr, hbuf, hsz, from);
        htcpForwardClr(buf, sz);
        break;
    default:
        break;
    }
}

static void
htcpRecv(int fd, void *)
{
    static char buf[8192];
    int len;
    static Ip::Address from;

    /* Receive up to 8191 bytes, leaving room for a null */

    len = comm_udp_recvfrom(fd, buf, sizeof(buf) - 1, 0, from);

    debugs(31, 3, "htcpRecv: FD " << fd << ", " << len << " bytes from " << from );

    if (len)
        ++statCounter.htcp.pkts_recv;

    htcpHandleMsg(buf, len, from);

    Comm::SetSelect(fd, COMM_SELECT_READ, htcpRecv, NULL, 0);
}

/*
 * ======================================================================
 * PUBLIC FUNCTIONS
 * ======================================================================
 */

void
htcpOpenPorts(void)
{
    if (Config.Port.htcp <= 0) {
        debugs(31, DBG_IMPORTANT, "HTCP Disabled.");
        return;
    }

    htcpIncomingConn = new Comm::Connection;
    htcpIncomingConn->local = Config.Addrs.udp_incoming;
    htcpIncomingConn->local.port(Config.Port.htcp);

    if (!Ip::EnableIpv6 && !htcpIncomingConn->local.setIPv4()) {
        debugs(31, DBG_CRITICAL, "ERROR: IPv6 is disabled. " << htcpIncomingConn->local << " is not an IPv4 address.");
        fatal("HTCP port cannot be opened.");
    }
    /* split-stack for now requires default IPv4-only HTCP */
    if (Ip::EnableIpv6&IPV6_SPECIAL_SPLITSTACK && htcpIncomingConn->local.isAnyAddr()) {
        htcpIncomingConn->local.setIPv4();
    }

    AsyncCall::Pointer call = asyncCall(31, 2,
                                        "htcpIncomingConnectionOpened",
                                        Comm::UdpOpenDialer(&htcpIncomingConnectionOpened));

    Ipc::StartListening(SOCK_DGRAM,
                        IPPROTO_UDP,
                        htcpIncomingConn,
                        Ipc::fdnInHtcpSocket, call);

    if (!Config.Addrs.udp_outgoing.isNoAddr()) {
        htcpOutgoingConn = new Comm::Connection;
        htcpOutgoingConn->local = Config.Addrs.udp_outgoing;
        htcpOutgoingConn->local.port(Config.Port.htcp);

        if (!Ip::EnableIpv6 && !htcpOutgoingConn->local.setIPv4()) {
            debugs(31, DBG_CRITICAL, "ERROR: IPv6 is disabled. " << htcpOutgoingConn->local << " is not an IPv4 address.");
            fatal("HTCP port cannot be opened.");
        }
        /* split-stack for now requires default IPv4-only HTCP */
        if (Ip::EnableIpv6&IPV6_SPECIAL_SPLITSTACK && htcpOutgoingConn->local.isAnyAddr()) {
            htcpOutgoingConn->local.setIPv4();
        }

        enter_suid();
        comm_open_listener(SOCK_DGRAM, IPPROTO_UDP, htcpOutgoingConn, "Outgoing HTCP Socket");
        leave_suid();

        if (!Comm::IsConnOpen(htcpOutgoingConn))
            fatal("Cannot open Outgoing HTCP Socket");

        Comm::SetSelect(htcpOutgoingConn->fd, COMM_SELECT_READ, htcpRecv, NULL, 0);

        debugs(31, DBG_IMPORTANT, "Sending HTCP messages from " << htcpOutgoingConn->local);
    }

}

static void
htcpIncomingConnectionOpened(const Comm::ConnectionPointer &conn, int)
{
    if (!Comm::IsConnOpen(conn))
        fatal("Cannot open HTCP Socket");

    Comm::SetSelect(conn->fd, COMM_SELECT_READ, htcpRecv, NULL, 0);

    debugs(31, DBG_CRITICAL, "Accepting HTCP messages on " << conn->local);

    if (Config.Addrs.udp_outgoing.isNoAddr()) {
        htcpOutgoingConn = conn;
        debugs(31, DBG_IMPORTANT, "Sending HTCP messages from " << htcpOutgoingConn->local);
    }
}

int
htcpQuery(StoreEntry * e, HttpRequest * req, CachePeer * p)
{
    cache_key *save_key;
    static char pkt[8192];
    ssize_t pktlen;
    char vbuf[32];
    HttpHeader hdr(hoRequest);
    Http::StateFlags flags;

    if (!Comm::IsConnOpen(htcpIncomingConn))
        return 0;

    old_squid_format = p->options.htcp_oldsquid;
    memset(&flags, '\0', sizeof(flags));
    snprintf(vbuf, sizeof(vbuf), "%d/%d",
             req->http_ver.major, req->http_ver.minor);

    htcpStuff stuff(++msg_id_counter, HTCP_TST, RR_REQUEST, 1);
    SBuf sb = req->method.image();
    stuff.S.method = sb.c_str();
    stuff.S.uri = (char *) e->url();
    stuff.S.version = vbuf;
    HttpStateData::httpBuildRequestHeader(req, e, NULL, &hdr, flags);
    MemBuf mb;
    mb.init();
    hdr.packInto(&mb);
    hdr.clean();
    stuff.S.req_hdrs = mb.buf;
    pktlen = htcpBuildPacket(pkt, sizeof(pkt), &stuff);
    mb.clean();
    if (!pktlen) {
        debugs(31, 3, "htcpQuery: htcpBuildPacket() failed");
        return -1;
    }

    htcpSend(pkt, (int) pktlen, p->in_addr);

    queried_id[stuff.msg_id % N_QUERIED_KEYS] = stuff.msg_id;
    save_key = queried_keys[stuff.msg_id % N_QUERIED_KEYS];
    storeKeyCopy(save_key, (const cache_key *)e->key);
    queried_addr[stuff.msg_id % N_QUERIED_KEYS] = p->in_addr;
    debugs(31, 3, "htcpQuery: key (" << save_key << ") " << storeKeyText(save_key));

    return 1;
}

/*
 * Send an HTCP CLR message for a specified item to a given CachePeer.
 */
void
htcpClear(StoreEntry * e, const char *uri, HttpRequest * req, const HttpRequestMethod &, CachePeer * p, htcp_clr_reason reason)
{
    static char pkt[8192];
    ssize_t pktlen;
    char vbuf[32];
    HttpHeader hdr(hoRequest);
    MemBuf mb;
    Http::StateFlags flags;

    if (!Comm::IsConnOpen(htcpIncomingConn))
        return;

    old_squid_format = p->options.htcp_oldsquid;
    memset(&flags, '\0', sizeof(flags));
    snprintf(vbuf, sizeof(vbuf), "%d/%d",
             req->http_ver.major, req->http_ver.minor);

    htcpStuff stuff(++msg_id_counter, HTCP_CLR, RR_REQUEST, 0);
    if (reason == HTCP_CLR_INVALIDATION)
        stuff.reason = 1;

    SBuf sb = req->method.image();
    stuff.S.method = sb.c_str();
    if (e == NULL || e->mem_obj == NULL) {
        if (uri == NULL) {
            return;
        }
        stuff.S.uri = xstrdup(uri);
    } else {
        stuff.S.uri = (char *) e->url();
    }
    stuff.S.version = vbuf;
    if (reason != HTCP_CLR_INVALIDATION) {
        HttpStateData::httpBuildRequestHeader(req, e, NULL, &hdr, flags);
        mb.init();
        hdr.packInto(&mb);
        hdr.clean();
        stuff.S.req_hdrs = mb.buf;
    } else {
        stuff.S.req_hdrs = NULL;
    }
    pktlen = htcpBuildPacket(pkt, sizeof(pkt), &stuff);
    if (reason != HTCP_CLR_INVALIDATION) {
        mb.clean();
    }
    if (e == NULL) {
        xfree(stuff.S.uri);
    }
    if (!pktlen) {
        debugs(31, 3, "htcpClear: htcpBuildPacket() failed");
        return;
    }

    htcpSend(pkt, (int) pktlen, p->in_addr);
}

/*
 * htcpSocketShutdown only closes the 'in' socket if it is
 * different than the 'out' socket.
 */
void
htcpSocketShutdown(void)
{
    if (!Comm::IsConnOpen(htcpIncomingConn))
        return;

    debugs(12, DBG_IMPORTANT, "Stop accepting HTCP on " << htcpIncomingConn->local);
    /*
     * Here we just unlink htcpIncomingConn because the HTCP 'in'
     * and 'out' sockets might be just one FD.  This prevents this
     * function from executing repeatedly.  When we are really ready to
     * exit or restart, main will comm_close the 'out' descriptor.
     */
    htcpIncomingConn = NULL;

    /*
     * Normally we only write to the outgoing HTCP socket, but
     * we also have a read handler there to catch messages sent
     * to that specific interface.  During shutdown, we must
     * disable reading on the outgoing socket.
     */
    /* XXX Don't we need this handler to read replies while shutting down?
     * I think there should be a separate hander for reading replies..
     */
    assert(Comm::IsConnOpen(htcpOutgoingConn));

    Comm::SetSelect(htcpOutgoingConn->fd, COMM_SELECT_READ, NULL, NULL, 0);
}

void
htcpClosePorts(void)
{
    htcpSocketShutdown();

    if (htcpOutgoingConn != NULL) {
        debugs(12, DBG_IMPORTANT, "Stop sending HTCP from " << htcpOutgoingConn->local);
        htcpOutgoingConn = NULL;
    }
}

static void
htcpLogHtcp(Ip::Address &caddr, int opcode, LogTags logcode, const char *url)
{
    AccessLogEntry::Pointer al = new AccessLogEntry;
    if (LOG_TAG_NONE == logcode.oldType)
        return;
    if (!Config.onoff.log_udp)
        return;
    al->htcp.opcode = htcpOpcodeStr[opcode];
    al->url = url;
    al->cache.caddr = caddr;
    al->cache.code = logcode;
    al->cache.trTime.tv_sec = 0;
    al->cache.trTime.tv_usec = 0;
    accessLogLog(al, NULL);
}

