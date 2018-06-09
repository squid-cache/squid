/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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
#include "util.h"
#include "wordlist.h"

/* called when we "miss" on an internal object;
 * generate known dynamic objects,
 * return Http::scNotFound for others
 */
void
internalStart(const Comm::ConnectionPointer &clientConn, HttpRequest * request, StoreEntry * entry)
{
    ErrorState *err;
    const SBuf upath = request->url.path();
    debugs(76, 3, clientConn << " requesting '" << upath << "'");

    static const SBuf netdbUri("/squid-internal-dynamic/netdb");
    static const SBuf storeDigestUri("/squid-internal-periodic/store_digest");
    static const SBuf mgrPfx("/squid-internal-mgr/");

    if (upath == netdbUri) {
        netdbBinaryExchange(entry);
    } else if (upath == storeDigestUri) {
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
    } else if (upath.startsWith(mgrPfx)) {
        debugs(17, 2, "calling CacheManager due to URL-path " << mgrPfx);
        CacheManager::GetInstance()->Start(clientConn, request, entry);
    } else {
        debugObj(76, 1, "internalStart: unknown request:\n",
                 request, (ObjPackMethod) & httpRequestPack);
        err = new ErrorState(ERR_INVALID_REQ, Http::scNotFound, request);
        errorAppendEntry(entry, err);
    }
}

bool
internalCheck(const SBuf &urlPath)
{
    static const SBuf InternalPfx("/squid-internal-");
    return urlPath.startsWith(InternalPfx);
}

bool
internalStaticCheck(const SBuf &urlPath)
{
    static const SBuf InternalStaticPfx("/squid-internal-static");
    return urlPath.startsWith(InternalStaticPfx);
}

/*
 * makes internal url with a given host and port (remote internal url)
 */
char *
internalRemoteUri(const char *host, unsigned short port, const char *dir, const SBuf &name)
{
    static char lc_host[SQUIDHOSTNAMELEN];
    assert(host && !name.isEmpty());
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

    /* build URI */
    AnyP::Uri tmp(AnyP::PROTO_HTTP);
    tmp.host(lc_host);
    if (port)
        tmp.port(port);

    static MemBuf mb;

    mb.reset();
    mb.appendf("http://" SQUIDSBUFPH, SQUIDSBUFPRINT(tmp.authority()));

    if (dir)
        mb.append(dir, strlen(dir));

    mb.append(name.rawContent(), name.length());

    /* return a pointer to a local static buffer */
    return mb.buf;
}

/*
 * makes internal url with local host and port
 */
char *
internalLocalUri(const char *dir, const SBuf &name)
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

