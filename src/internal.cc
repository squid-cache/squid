
#include "squid.h"

/* called when we "miss" on an internal object;
 * generate known dynamic objects, 
 * return HTTP_NOT_FOUND for others
 */
void
internalStart(request_t * request, StoreEntry * entry)
{
    ErrorState *err;
    const char *upath = strBuf(request->urlpath);
    debug(0, 1) ("internalStart: %s requesting '%s'\n",
	inet_ntoa(request->client_addr), upath);
    if (0 == strcmp(upath, "/squid-internal-dynamic/netdb"))
	netdbBinaryExchange(entry);
    else {
	debug(0, 0) ("internalStart: unknown request '%s'\n", upath);
	debugObj(0,0, "internalStart: unknown request:\n", request, (ObjPackMethod)&httpRequestPack);
	err = errorCon(ERR_INVALID_REQ, HTTP_NOT_FOUND);
	err->request = requestLink(request);
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
internalRemoteUri(const char *host, u_short port, const char *dir, const char *name)
{
    static MemBuf mb = MemBufNULL;
    static char lc_host[SQUIDHOSTNAMELEN];
    assert(host && port && name);
    /* convert host name to lower case */
    xstrncpy(lc_host, host, sizeof(lc_host));
    Tolower(lc_host);
    /* build uri in mb */
    memBufReset(&mb);
    memBufPrintf(&mb, "http://%s", lc_host);
    /* append port if not default */
    if (port != urlDefaultPort(PROTO_HTTP))
	memBufPrintf(&mb, ":%d", port);
    if (dir)
	memBufPrintf(&mb, "%s", dir);
    memBufPrintf(&mb, "%s", name);
    /* return a pointer to a local static buffer */
    return mb.buf;
}

/*
 * makes internal url with local host and port
 */
char *
internalLocalUri(const char *dir, const char *name)
{
    return internalRemoteUri(getMyHostname(), Config.Port.http->i, dir, name);
}
