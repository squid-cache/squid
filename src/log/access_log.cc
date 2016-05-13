/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log */

#include "squid.h"
#include "AccessLogEntry.h"
#include "acl/Checklist.h"
#if USE_ADAPTATION
#include "adaptation/Config.h"
#endif
#include "CachePeer.h"
#include "err_detail_type.h"
#include "errorpage.h"
#include "format/Token.h"
#include "globals.h"
#include "hier_code.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "log/access_log.h"
#include "log/Config.h"
#include "log/CustomLog.h"
#include "log/File.h"
#include "log/Formats.h"
#include "MemBuf.h"
#include "mgr/Registration.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"

#if USE_SQUID_EUI
#include "eui/Eui48.h"
#include "eui/Eui64.h"
#endif

#if HEADERS_LOG
static Logfile *headerslog = NULL;
#endif

#if MULTICAST_MISS_STREAM
static int mcast_miss_fd = -1;

static struct sockaddr_in mcast_miss_to;
static void mcast_encode(unsigned int *, size_t, const unsigned int *);
#endif

#if USE_FORW_VIA_DB

typedef struct {
    hash_link hash;
    int n;
} fvdb_entry;
static hash_table *via_table = NULL;
static hash_table *forw_table = NULL;
static void fvdbInit();
static void fvdbDumpTable(StoreEntry * e, hash_table * hash);
static void fvdbCount(hash_table * hash, const char *key);
static OBJH fvdbDumpVia;
static OBJH fvdbDumpForw;
static FREE fvdbFreeEntry;
static void fvdbClear(void);
static void fvdbRegisterWithCacheManager();
#endif

int LogfileStatus = LOG_DISABLE;

void
accessLogLogTo(CustomLog* log, AccessLogEntry::Pointer &al, ACLChecklist * checklist)
{

    if (al->url.isEmpty())
        al->url = Format::Dash;

    if (!al->http.content_type || *al->http.content_type == '\0')
        al->http.content_type = dash_str;

    if (al->hier.host[0] == '\0')
        xstrncpy(al->hier.host, dash_str, SQUIDHOSTNAMELEN);

    for (; log; log = log->next) {
        if (log->aclList && checklist && checklist->fastCheck(log->aclList) != ACCESS_ALLOWED)
            continue;

        // The special-case "none" type has no logfile object set
        if (log->type == Log::Format::CLF_NONE)
            return;

        if (log->logfile) {
            logfileLineStart(log->logfile);

            switch (log->type) {

            case Log::Format::CLF_SQUID:
                Log::Format::SquidNative(al, log->logfile);
                break;

            case Log::Format::CLF_COMBINED:
                Log::Format::HttpdCombined(al, log->logfile);
                break;

            case Log::Format::CLF_COMMON:
                Log::Format::HttpdCommon(al, log->logfile);
                break;

            case Log::Format::CLF_REFERER:
                Log::Format::SquidReferer(al, log->logfile);
                break;

            case Log::Format::CLF_USERAGENT:
                Log::Format::SquidUserAgent(al, log->logfile);
                break;

            case Log::Format::CLF_CUSTOM:
                Log::Format::SquidCustom(al, log);
                break;

#if ICAP_CLIENT
            case Log::Format::CLF_ICAP_SQUID:
                Log::Format::SquidIcap(al, log->logfile);
                break;
#endif

            default:
                fatalf("Unknown log format %d\n", log->type);
                break;
            }

            logfileLineEnd(log->logfile);
        }

        // NP:  WTF?  if _any_ log line has no checklist ignore the following ones?
        if (!checklist)
            break;
    }
}

void
accessLogLog(AccessLogEntry::Pointer &al, ACLChecklist * checklist)
{
    if (LogfileStatus != LOG_ENABLE)
        return;

    accessLogLogTo(Config.Log.accesslogs, al, checklist);
#if MULTICAST_MISS_STREAM

    if (al->cache.code != LOG_TCP_MISS)
        (void) 0;
    else if (al->http.method != METHOD_GET)
        (void) 0;
    else if (mcast_miss_fd < 0)
        (void) 0;
    else {
        unsigned int ibuf[365];
        size_t isize;
        xstrncpy((char *) ibuf, al->url.c_str(), 364 * sizeof(int));
        isize = ((al->url.length() + 8) / 8) * 2;

        if (isize > 364)
            isize = 364;

        mcast_encode((unsigned int *) ibuf, isize,
                     (const unsigned int *) Config.mcast_miss.encode_key);

        comm_udp_sendto(mcast_miss_fd,
                        &mcast_miss_to, sizeof(mcast_miss_to),
                        ibuf, isize * sizeof(int));
    }

#endif
}

void
accessLogRotate(void)
{
    CustomLog *log;
#if USE_FORW_VIA_DB

    fvdbClear();
#endif

    for (log = Config.Log.accesslogs; log; log = log->next) {
        if (log->logfile) {
            int16_t rc = (log->rotateCount >= 0 ? log->rotateCount : Config.Log.rotateNumber);
            logfileRotate(log->logfile, rc);
        }
    }

#if HEADERS_LOG

    logfileRotate(headerslog, Config.Log.rotateNumber);

#endif
}

void
accessLogClose(void)
{
    CustomLog *log;

    for (log = Config.Log.accesslogs; log; log = log->next) {
        if (log->logfile) {
            logfileClose(log->logfile);
            log->logfile = NULL;
        }
    }

#if HEADERS_LOG

    logfileClose(headerslog);

    headerslog = NULL;

#endif
}

HierarchyLogEntry::HierarchyLogEntry() :
    code(HIER_NONE),
    cd_lookup(LOOKUP_NONE),
    n_choices(0),
    n_ichoices(0),
    peer_reply_status(Http::scNone),
    tcpServer(NULL),
    bodyBytesRead(-1)
{
    memset(host, '\0', SQUIDHOSTNAMELEN);
    memset(cd_host, '\0', SQUIDHOSTNAMELEN);

    peer_select_start.tv_sec =0;
    peer_select_start.tv_usec =0;

    store_complete_stop.tv_sec =0;
    store_complete_stop.tv_usec =0;

    peer_http_request_sent.tv_sec = 0;
    peer_http_request_sent.tv_usec = 0;

    peer_response_time.tv_sec = -1;
    peer_response_time.tv_usec = 0;

    totalResponseTime_.tv_sec = -1;
    totalResponseTime_.tv_usec = 0;

    firstConnStart_.tv_sec = 0;
    firstConnStart_.tv_usec = 0;
}

void
HierarchyLogEntry::note(const Comm::ConnectionPointer &server, const char *requestedHost)
{
    tcpServer = server;
    if (tcpServer == NULL) {
        code = HIER_NONE;
        xstrncpy(host, requestedHost, sizeof(host));
    } else {
        code = tcpServer->peerType;

        if (tcpServer->getPeer()) {
            // went to peer, log peer host name
            xstrncpy(host, tcpServer->getPeer()->name, sizeof(host));
        } else {
            xstrncpy(host, requestedHost, sizeof(host));
        }
    }
}

void
HierarchyLogEntry::startPeerClock()
{
    if (!firstConnStart_.tv_sec)
        firstConnStart_ = current_time;
}

void
HierarchyLogEntry::stopPeerClock(const bool force)
{
    debugs(46, 5, "First connection started: " << firstConnStart_.tv_sec << "." <<
           std::setfill('0') << std::setw(6) << firstConnStart_.tv_usec <<
           ", current total response time value: " << (totalResponseTime_.tv_sec * 1000 +  totalResponseTime_.tv_usec/1000) <<
           (force ? ", force fixing" : ""));
    if (!force && totalResponseTime_.tv_sec != -1)
        return;

    if (firstConnStart_.tv_sec)
        tvSub(totalResponseTime_, firstConnStart_, current_time);
}

void
HierarchyLogEntry::totalResponseTime(struct timeval &responseTime)
{
    // This should not really happen, but there may be rare code
    // paths that lead to FwdState discarded (or transaction logged)
    // without (or before) a stopPeerClock() call.
    if (firstConnStart_.tv_sec && totalResponseTime_.tv_sec == -1)
        stopPeerClock(false);

    responseTime = totalResponseTime_;
}

static void
accessLogRegisterWithCacheManager(void)
{
#if USE_FORW_VIA_DB
    fvdbRegisterWithCacheManager();
#endif
}

void
accessLogInit(void)
{
    CustomLog *log;

    accessLogRegisterWithCacheManager();

#if USE_ADAPTATION
    Log::TheConfig.hasAdaptToken = false;
#endif
#if ICAP_CLIENT
    Log::TheConfig.hasIcapToken = false;
#endif

    for (log = Config.Log.accesslogs; log; log = log->next) {
        if (log->type == Log::Format::CLF_NONE)
            continue;

        log->logfile = logfileOpen(log->filename, log->bufferSize, log->fatal);

        LogfileStatus = LOG_ENABLE;

#if USE_ADAPTATION
        for (Format::Token * curr_token = (log->logFormat?log->logFormat->format:NULL); curr_token; curr_token = curr_token->next) {
            if (curr_token->type == Format::LFT_ADAPTATION_SUM_XACT_TIMES ||
                    curr_token->type == Format::LFT_ADAPTATION_ALL_XACT_TIMES ||
                    curr_token->type == Format::LFT_ADAPTATION_LAST_HEADER ||
                    curr_token->type == Format::LFT_ADAPTATION_LAST_HEADER_ELEM ||
                    curr_token->type == Format::LFT_ADAPTATION_LAST_ALL_HEADERS||
                    (curr_token->type == Format::LFT_NOTE && !Adaptation::Config::metaHeaders.empty())) {
                Log::TheConfig.hasAdaptToken = true;
            }
#if ICAP_CLIENT
            if (curr_token->type == Format::LFT_ICAP_TOTAL_TIME) {
                Log::TheConfig.hasIcapToken = true;
            }
#endif
        }
#endif
    }

#if HEADERS_LOG

    headerslog = logfileOpen("/usr/local/squid/logs/headers.log", 512);

    assert(NULL != headerslog);

#endif
#if MULTICAST_MISS_STREAM

    if (Config.mcast_miss.addr.s_addr != no_addr.s_addr) {
        memset(&mcast_miss_to, '\0', sizeof(mcast_miss_to));
        mcast_miss_to.sin_family = AF_INET;
        mcast_miss_to.sin_port = htons(Config.mcast_miss.port);
        mcast_miss_to.sin_addr.s_addr = Config.mcast_miss.addr.s_addr;
        mcast_miss_fd = comm_open(SOCK_DGRAM,
                                  IPPROTO_UDP,
                                  Config.Addrs.udp_incoming,
                                  Config.mcast_miss.port,
                                  COMM_NONBLOCKING,
                                  "Multicast Miss Stream");

        if (mcast_miss_fd < 0)
            fatal("Cannot open Multicast Miss Stream Socket");

        debugs(46, DBG_IMPORTANT, "Multicast Miss Stream Socket opened on FD " << mcast_miss_fd);

        mcastSetTtl(mcast_miss_fd, Config.mcast_miss.ttl);

        if (strlen(Config.mcast_miss.encode_key) < 16)
            fatal("mcast_encode_key is too short, must be 16 characters");
    }

#endif
#if USE_FORW_VIA_DB

    fvdbInit();

#endif
}

#if USE_FORW_VIA_DB

static void
fvdbInit(void)
{
    via_table = hash_create((HASHCMP *) strcmp, 977, hash4);
    forw_table = hash_create((HASHCMP *) strcmp, 977, hash4);
}

static void
fvdbRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("via_headers", "Via Request Headers", fvdbDumpVia, 0, 1);
    Mgr::RegisterAction("forw_headers", "X-Forwarded-For Request Headers",
                        fvdbDumpForw, 0, 1);
}

static void
fvdbCount(hash_table * hash, const char *key)
{
    fvdb_entry *fv;

    if (NULL == hash)
        return;

    fv = (fvdb_entry *)hash_lookup(hash, key);

    if (NULL == fv) {
        fv = static_cast <fvdb_entry *>(xcalloc(1, sizeof(fvdb_entry)));
        fv->hash.key = xstrdup(key);
        hash_join(hash, &fv->hash);
    }

    ++ fv->n;
}

void
fvdbCountVia(const char *key)
{
    fvdbCount(via_table, key);
}

void
fvdbCountForw(const char *key)
{
    fvdbCount(forw_table, key);
}

static void
fvdbDumpTable(StoreEntry * e, hash_table * hash)
{
    hash_link *h;
    fvdb_entry *fv;

    if (hash == NULL)
        return;

    hash_first(hash);

    while ((h = hash_next(hash))) {
        fv = (fvdb_entry *) h;
        storeAppendPrintf(e, "%9d %s\n", fv->n, hashKeyStr(&fv->hash));
    }
}

static void
fvdbDumpVia(StoreEntry * e)
{
    fvdbDumpTable(e, via_table);
}

static void
fvdbDumpForw(StoreEntry * e)
{
    fvdbDumpTable(e, forw_table);
}

static
void
fvdbFreeEntry(void *data)
{
    fvdb_entry *fv = static_cast <fvdb_entry *>(data);
    xfree(fv->hash.key);
    xfree(fv);
}

static void
fvdbClear(void)
{
    hashFreeItems(via_table, fvdbFreeEntry);
    hashFreeMemory(via_table);
    via_table = hash_create((HASHCMP *) strcmp, 977, hash4);
    hashFreeItems(forw_table, fvdbFreeEntry);
    hashFreeMemory(forw_table);
    forw_table = hash_create((HASHCMP *) strcmp, 977, hash4);
}

#endif

#if MULTICAST_MISS_STREAM
/*
 * From http://www.io.com/~paulhart/game/algorithms/tea.html
 *
 * size of 'ibuf' must be a multiple of 2.
 * size of 'key' must be 4.
 * 'ibuf' is modified in place, encrypted data is written in
 * network byte order.
 */
static void
mcast_encode(unsigned int *ibuf, size_t isize, const unsigned int *key)
{
    unsigned int y;
    unsigned int z;
    unsigned int sum;
    const unsigned int delta = 0x9e3779b9;
    unsigned int n = 32;
    const unsigned int k0 = htonl(key[0]);
    const unsigned int k1 = htonl(key[1]);
    const unsigned int k2 = htonl(key[2]);
    const unsigned int k3 = htonl(key[3]);
    int i;

    for (i = 0; i < isize; i += 2) {
        y = htonl(ibuf[i]);
        z = htonl(ibuf[i + 1]);
        sum = 0;

        for (n = 32; n; --n) {
            sum += delta;
            y += (z << 4) + (k0 ^ z) + (sum ^ (z >> 5)) + k1;
            z += (y << 4) + (k2 ^ y) + (sum ^ (y >> 5)) + k3;
        }

        ibuf[i] = htonl(y);
        ibuf[i + 1] = htonl(z);
    }
}

#endif

#if HEADERS_LOG
void
headersLog(int cs, int pq, const HttpRequestMethod& method, void *data)
{
    HttpReply *rep;
    HttpRequest *req;
    unsigned short magic = 0;
    unsigned char M = (unsigned char) m;
    char *hmask;
    int ccmask = 0;

    if (0 == pq) {
        /* reply */
        rep = data;
        req = NULL;
        magic = 0x0050;
        hmask = rep->header.mask;

        if (rep->cache_control)
            ccmask = rep->cache_control->mask;
    } else {
        /* request */
        req = data;
        rep = NULL;
        magic = 0x0051;
        hmask = req->header.mask;

        if (req->cache_control)
            ccmask = req->cache_control->mask;
    }

    if (0 == cs) {
        /* client */
        magic |= 0x4300;
    } else {
        /* server */
        magic |= 0x5300;
    }

    magic = htons(magic);
    ccmask = htonl(ccmask);

    unsigned short S = 0;
    if (0 == pq)
        S = static_cast<unsigned short>(rep->sline.status());

    logfileWrite(headerslog, &magic, sizeof(magic));
    logfileWrite(headerslog, &M, sizeof(M));
    logfileWrite(headerslog, &S, sizeof(S));
    logfileWrite(headerslog, hmask, sizeof(HttpHeaderMask));
    logfileWrite(headerslog, &ccmask, sizeof(int));
}

#endif

