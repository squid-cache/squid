/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 76    Internal Squid Object handling */

#include "squid.h"
#include "CacheManager.h"
#include "comm/Connection.h"
#include "errorpage.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "icmp/net_db.h"
#include "MemBuf.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"
#include "tools.h"
#include "URL.h"
#include "wordlist.h"

/* called when we "miss" on an internal object;
 * generate known dynamic objects,
 * return Http::scNotFound for others
 */
void
internalStart(const Comm::ConnectionPointer &clientConn, HttpRequest * request, StoreEntry * entry)
{
    ErrorState *err;
    const char *upath = request->urlpath.termedBuf();
    debugs(76, 3, HERE << clientConn << " requesting '" << upath << "'");

    if (0 == strcmp(upath, "/squid-internal-dynamic/netdb")) {
        netdbBinaryExchange(entry);
    } else if (0 == strcmp(upath, "/squid-internal-periodic/store_digest")) {
#if USE_CACHE_DIGESTS
        const char *msgbuf = "This cache is currently building its digest.\n";
#else

        const char *msgbuf = "This cache does not support Cache Digests.\n";
#endif

        HttpReply *reply = new HttpReply;
        reply->setHeaders(Http::scNotFound, "Not Found", "text/plain", strlen(msgbuf), squid_curtime, -2);
        entry->replaceHttpReply(reply);
        entry->append(msgbuf, strlen(msgbuf));
        entry->complete();
    } else if (0 == strncmp(upath, "/squid-internal-mgr/", 20)) {
        debugs(17, 2, "calling CacheManager due to URL-path /squid-internal-mgr/");
        CacheManager::GetInstance()->Start(clientConn, request, entry);
    } else {
        debugObj(76, 1, "internalStart: unknown request:\n",
                 request, (ObjPackMethod) & httpRequestPack);
        err = new ErrorState(ERR_INVALID_REQ, Http::scNotFound, request);
        errorAppendEntry(entry, err);
    }
}

int
internalCheck(const char *urlpath)
{
    return (0 == strncmp(urlpath, "/squid-internal-", 16));
}

int
internalStaticCheck(const char *urlpath)
{
    return (0 == strncmp(urlpath, "/squid-internal-static", 22));
}

/*
 * makes internal url with a given host and port (remote internal url)
 */
char *
internalRemoteUri(const char *host, unsigned short port, const char *dir, const char *name)
{
    static char lc_host[SQUIDHOSTNAMELEN];
    assert(host && name);
    /* convert host name to lower case */
    xstrncpy(lc_host, host, SQUIDHOSTNAMELEN);
    Tolower(lc_host);

    /* check for an IP address and format appropriately if found */
    Ip::Address test = lc_host;
    if ( !test.isAnyAddr() ) {
        test.toHostStr(lc_host,SQUIDHOSTNAMELEN);
    }

    /*
     * append the domain in order to mirror the requests with appended
     * domains
     */

    /* For IPv6 addresses also check for a colon */
    if (Config.appendDomain && !strchr(lc_host, '.') && !strchr(lc_host, ':'))
        strncat(lc_host, Config.appendDomain, SQUIDHOSTNAMELEN -
                strlen(lc_host) - 1);

    /* build uri in mb */
    static MemBuf mb;

    mb.reset();

    mb.Printf("http://%s", lc_host);

    /* append port if not default */
    if (port && port != urlDefaultPort(AnyP::PROTO_HTTP))
        mb.Printf(":%d", port);

    if (dir)
        mb.Printf("%s", dir);

    mb.Printf("%s", name);

    /* return a pointer to a local static buffer */
    return mb.buf;
}

/*
 * makes internal url with local host and port
 */
char *
internalLocalUri(const char *dir, const char *name)
{
    return internalRemoteUri(getMyHostname(),
                             getMyPort(), dir, name);
}

const char *
internalHostname(void)
{
    LOCAL_ARRAY(char, host, SQUIDHOSTNAMELEN + 1);
    xstrncpy(host, getMyHostname(), SQUIDHOSTNAMELEN);

    /* For IPv6 addresses also check for a colon */
    if (Config.appendDomain && !strchr(host, '.') && !strchr(host, ':'))
        strncat(host, Config.appendDomain, SQUIDHOSTNAMELEN -
                strlen(host) - 1);

    Tolower(host);

    return host;
}

int
internalHostnameIs(const char *arg)
{
    wordlist *w;

    if (0 == strcmp(arg, internalHostname()))
        return 1;

    for (w = Config.hostnameAliases; w; w = w->next)
        if (0 == strcmp(arg, w->key))
            return 1;

    return 0;
}

