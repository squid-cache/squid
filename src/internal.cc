
#include "squid.h"

void
internalStart(request_t * request, StoreEntry * entry)
{
    const char *upath = strBuf(request->urlpath);
    debug(0, 1) ("internalStart: %s requesting '%s'\n",
	inet_ntoa(request->client_addr), upath);
    if (0 == strcmp(upath, "/squid-internal-dynamic/netdb"))
	netdbBinaryExchange(entry);
    else
	debug(0, 0) ("internalStart: unknown request '%s'\n", upath);
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
    LOCAL_ARRAY(char, buf, MAX_URL);
    int k = 0;
    static char lc_host[SQUIDHOSTNAMELEN];
    assert(host && port && name);
    xstrncpy(lc_host, host, SQUIDHOSTNAMELEN);
    Tolower(lc_host);
    k += snprintf(buf + k, MAX_URL - k, "http://%s", lc_host);
    if (port != urlDefaultPort(PROTO_HTTP))
	k += snprintf(buf + k, MAX_URL - k, ":%d", port);
    if (dir)
	k += snprintf(buf + k, MAX_URL - k, "%s", dir);
    k += snprintf(buf + k, MAX_URL - k, "%s", name);
    return buf;
}

/*
 * makes internal url with local host and port
 */
char *
internalLocalUri(const char *dir, const char *name)
{
    return internalRemoteUri(getMyHostname(), Config.Port.http->i, dir, name);
}
