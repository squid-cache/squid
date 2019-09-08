/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 23    URL Parsing */

#include "squid.h"
#include "globals.h"
#include "HttpRequest.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "URL.h"

static HttpRequest *urlParseFinish(const HttpRequestMethod& method,
                                   const AnyP::ProtocolType protocol,
                                   const char *const urlpath,
                                   const char *const host,
                                   const char *const login,
                                   const int port,
                                   HttpRequest *request);
static HttpRequest *urnParse(const HttpRequestMethod& method, char *urn, HttpRequest *request);
static const char valid_hostname_chars_u[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-._"
    "[:]"
    ;
static const char valid_hostname_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-."
    "[:]"
    ;

void
urlInitialize(void)
{
    debugs(23, 5, "urlInitialize: Initializing...");
    /* this ensures that the number of protocol strings is the same as
     * the enum slots allocated because the last enum is always 'MAX'.
     */
    assert(strcmp(AnyP::ProtocolType_str[AnyP::PROTO_MAX], "MAX") == 0);
    /*
     * These test that our matchDomainName() function works the
     * way we expect it to.
     */
    assert(0 == matchDomainName("foo.com", "foo.com"));
    assert(0 == matchDomainName(".foo.com", "foo.com"));
    assert(0 == matchDomainName("foo.com", ".foo.com"));
    assert(0 == matchDomainName(".foo.com", ".foo.com"));
    assert(0 == matchDomainName("x.foo.com", ".foo.com"));
    assert(0 == matchDomainName("y.x.foo.com", ".foo.com"));
    assert(0 != matchDomainName("x.foo.com", "foo.com"));
    assert(0 != matchDomainName("foo.com", "x.foo.com"));
    assert(0 != matchDomainName("bar.com", "foo.com"));
    assert(0 != matchDomainName(".bar.com", "foo.com"));
    assert(0 != matchDomainName(".bar.com", ".foo.com"));
    assert(0 != matchDomainName("bar.com", ".foo.com"));
    assert(0 < matchDomainName("zzz.com", "foo.com"));
    assert(0 > matchDomainName("aaa.com", "foo.com"));
    assert(0 == matchDomainName("FOO.com", "foo.COM"));
    assert(0 < matchDomainName("bfoo.com", "afoo.com"));
    assert(0 > matchDomainName("afoo.com", "bfoo.com"));
    assert(0 < matchDomainName("x-foo.com", ".foo.com"));

    assert(0 == matchDomainName(".foo.com", ".foo.com", mdnRejectSubsubDomains));
    assert(0 == matchDomainName("x.foo.com", ".foo.com", mdnRejectSubsubDomains));
    assert(0 != matchDomainName("y.x.foo.com", ".foo.com", mdnRejectSubsubDomains));
    assert(0 != matchDomainName(".x.foo.com", ".foo.com", mdnRejectSubsubDomains));

    assert(0 == matchDomainName("*.foo.com", "x.foo.com", mdnHonorWildcards));
    assert(0 == matchDomainName("*.foo.com", ".x.foo.com", mdnHonorWildcards));
    assert(0 == matchDomainName("*.foo.com", ".foo.com", mdnHonorWildcards));
    assert(0 != matchDomainName("*.foo.com", "foo.com", mdnHonorWildcards));

    /* more cases? */
}

/**
 * urlParseProtocol() takes begin (b) and end (e) pointers, but for
 * backwards compatibility, e defaults to NULL, in which case we
 * assume b is NULL-terminated.
 */
AnyP::ProtocolType
urlParseProtocol(const char *b, const char *e)
{
    /*
     * if e is NULL, b must be NULL terminated and we
     * make e point to the first whitespace character
     * after b.
     */

    if (NULL == e)
        e = b + strcspn(b, ":");

    int len = e - b;

    /* test common stuff first */

    if (strncasecmp(b, "http", len) == 0)
        return AnyP::PROTO_HTTP;

    if (strncasecmp(b, "ftp", len) == 0)
        return AnyP::PROTO_FTP;

    if (strncasecmp(b, "https", len) == 0)
        return AnyP::PROTO_HTTPS;

    if (strncasecmp(b, "file", len) == 0)
        return AnyP::PROTO_FTP;

    if (strncasecmp(b, "coap", len) == 0)
        return AnyP::PROTO_COAP;

    if (strncasecmp(b, "coaps", len) == 0)
        return AnyP::PROTO_COAPS;

    if (strncasecmp(b, "gopher", len) == 0)
        return AnyP::PROTO_GOPHER;

    if (strncasecmp(b, "wais", len) == 0)
        return AnyP::PROTO_WAIS;

    if (strncasecmp(b, "cache_object", len) == 0)
        return AnyP::PROTO_CACHE_OBJECT;

    if (strncasecmp(b, "urn", len) == 0)
        return AnyP::PROTO_URN;

    if (strncasecmp(b, "whois", len) == 0)
        return AnyP::PROTO_WHOIS;

    return AnyP::PROTO_NONE;
}

int
urlDefaultPort(AnyP::ProtocolType p)
{
    switch (p) {

    case AnyP::PROTO_HTTP:
        return 80;

    case AnyP::PROTO_HTTPS:
        return 443;

    case AnyP::PROTO_FTP:
        return 21;

    case AnyP::PROTO_COAP:
    case AnyP::PROTO_COAPS:
        // coaps:// default is TBA as of draft-ietf-core-coap-08.
        // Assuming IANA policy of allocating same port for base and TLS protocol versions will occur.
        return 5683;

    case AnyP::PROTO_GOPHER:
        return 70;

    case AnyP::PROTO_WAIS:
        return 210;

    case AnyP::PROTO_CACHE_OBJECT:
        return CACHE_HTTP_PORT;

    case AnyP::PROTO_WHOIS:
        return 43;

    default:
        return 0;
    }
}

/**
 * Appends configured append_domain to hostname, assuming
 * the given buffer is at least SQUIDHOSTNAMELEN bytes long,
 * and that the host FQDN is not a 'dotless' TLD.
 *
 * \returns false if and only if there is not enough space to append
 */
bool
urlAppendDomain(char *host)
{
    /* For IPv4 addresses check for a dot */
    /* For IPv6 addresses also check for a colon */
    if (Config.appendDomain && !strchr(host, '.') && !strchr(host, ':')) {
        const uint64_t dlen = strlen(host);
        const uint64_t want = dlen + Config.appendDomainLen;
        if (want > SQUIDHOSTNAMELEN - 1) {
            debugs(23, 2, "URL domain too large (" << dlen << " bytes)");
            return false;
        }
        strncat(host, Config.appendDomain, SQUIDHOSTNAMELEN - dlen - 1);
    }
    return true;
}

/*
 * Parse a URI/URL.
 *
 * If the 'request' arg is non-NULL, put parsed values there instead
 * of allocating a new HttpRequest.
 *
 * This abuses HttpRequest as a way of representing the parsed url
 * and its components.
 * method is used to switch parsers and to init the HttpRequest.
 * If method is Http::METHOD_CONNECT, then rather than a URL a hostname:port is
 * looked for.
 * The url is non const so that if its too long we can NULL-terminate it in place.
 */

/*
 * This routine parses a URL. Its assumed that the URL is complete -
 * ie, the end of the string is the end of the URL. Don't pass a partial
 * URL here as this routine doesn't have any way of knowing whether
 * its partial or not (ie, it handles the case of no trailing slash as
 * being "end of host with implied path of /".
 */
HttpRequest *
urlParse(const HttpRequestMethod& method, char *url, HttpRequest *request)
{
    LOCAL_ARRAY(char, proto, MAX_URL);
    LOCAL_ARRAY(char, login, MAX_URL);
    LOCAL_ARRAY(char, host, MAX_URL);
    LOCAL_ARRAY(char, urlpath, MAX_URL);
    char *t = NULL;
    char *q = NULL;
    int port;
    AnyP::ProtocolType protocol = AnyP::PROTO_NONE;
    int l;
    int i;
    const char *src;
    char *dst;
    proto[0] = host[0] = urlpath[0] = login[0] = '\0';

    if ((l = strlen(url)) + Config.appendDomainLen > (MAX_URL - 1)) {
        /* terminate so it doesn't overflow other buffers */
        *(url + (MAX_URL >> 1)) = '\0';
        debugs(23, DBG_IMPORTANT, "urlParse: URL too large (" << l << " bytes)");
        return NULL;
    }
    if (method == Http::METHOD_CONNECT) {
        port = CONNECT_PORT;

        if (sscanf(url, "[%[^]]]:%d", host, &port) < 1)
            if (sscanf(url, "%[^:]:%d", host, &port) < 1)
                return NULL;

    } else if ((method == Http::METHOD_OPTIONS || method == Http::METHOD_TRACE) &&
               strcmp(url, "*") == 0) {
        protocol = AnyP::PROTO_HTTP;
        port = urlDefaultPort(protocol);
        return urlParseFinish(method, protocol, url, host, login, port, request);
    } else if (!strncmp(url, "urn:", 4)) {
        return urnParse(method, url, request);
    } else {
        /* Parse the URL: */
        src = url;
        i = 0;
        /* Find first : - everything before is protocol */
        for (i = 0, dst = proto; i < l && *src != ':'; ++i, ++src, ++dst) {
            *dst = *src;
        }
        if (i >= l)
            return NULL;
        *dst = '\0';

        /* Then its :// */
        if ((i+3) > l || *src != ':' || *(src + 1) != '/' || *(src + 2) != '/')
            return NULL;
        i += 3;
        src += 3;

        /* Then everything until first /; thats host (and port; which we'll look for here later) */
        // bug 1881: If we don't get a "/" then we imply it was there
        // bug 3074: We could just be given a "?" or "#". These also imply "/"
        // bug 3233: whitespace is also a hostname delimiter.
        for (dst = host; i < l && *src != '/' && *src != '?' && *src != '#' && *src != '\0' && !xisspace(*src); ++i, ++src, ++dst) {
            *dst = *src;
        }

        /*
         * We can't check for "i >= l" here because we could be at the end of the line
         * and have a perfectly valid URL w/ no trailing '/'. In this case we assume we've
         * been -given- a valid URL and the path is just '/'.
         */
        if (i > l)
            return NULL;
        *dst = '\0';

        // bug 3074: received 'path' starting with '?', '#', or '\0' implies '/'
        if (*src == '?' || *src == '#' || *src == '\0') {
            urlpath[0] = '/';
            dst = &urlpath[1];
        } else {
            dst = urlpath;
        }
        /* Then everything from / (inclusive) until \r\n or \0 - thats urlpath */
        for (; i < l && *src != '\r' && *src != '\n' && *src != '\0'; ++i, ++src, ++dst) {
            *dst = *src;
        }

        /* We -could- be at the end of the buffer here */
        if (i > l)
            return NULL;
        /* If the URL path is empty we set it to be "/" */
        if (dst == urlpath) {
            *dst = '/';
            ++dst;
        }
        *dst = '\0';

        protocol = urlParseProtocol(proto);
        port = urlDefaultPort(protocol);

        /* Is there any login information? (we should eventually parse it above) */
        t = strrchr(host, '@');
        if (t != NULL) {
            strncpy((char *) login, (char *) host, sizeof(login)-1);
            login[sizeof(login)-1] = '\0';
            t = strrchr(login, '@');
            *t = 0;
            strncpy((char *) host, t + 1, sizeof(host)-1);
            host[sizeof(host)-1] = '\0';
            // Bug 4498: URL-unescape the login info after extraction
            rfc1738_unescape(login);
        }

        /* Is there any host information? (we should eventually parse it above) */
        if (*host == '[') {
            /* strip any IPA brackets. valid under IPv6. */
            dst = host;
            /* only for IPv6 sadly, pre-IPv6/URL code can't handle the clean result properly anyway. */
            src = host;
            ++src;
            l = strlen(host);
            i = 1;
            for (; i < l && *src != ']' && *src != '\0'; ++i, ++src, ++dst) {
                *dst = *src;
            }

            /* we moved in-place, so truncate the actual hostname found */
            *dst = '\0';
            ++dst;

            /* skip ahead to either start of port, or original EOS */
            while (*dst != '\0' && *dst != ':')
                ++dst;
            t = dst;
        } else {
            t = strrchr(host, ':');

            if (t != strchr(host,':') ) {
                /* RFC 2732 states IPv6 "SHOULD" be bracketed. allowing for times when its not. */
                /* RFC 3986 'update' simply modifies this to an "is" with no emphasis at all! */
                /* therefore we MUST accept the case where they are not bracketed at all. */
                t = NULL;
            }
        }

        // Bug 3183 sanity check: If scheme is present, host must be too.
        if (protocol != AnyP::PROTO_NONE && host[0] == '\0') {
            debugs(23, DBG_IMPORTANT, "SECURITY ALERT: Missing hostname in URL '" << url << "'. see access.log for details.");
            return NULL;
        }

        if (t && *t == ':') {
            *t = '\0';
            ++t;
            port = atoi(t);
        }
    }

    for (t = host; *t; ++t)
        *t = xtolower(*t);

    if (stringHasWhitespace(host)) {
        if (URI_WHITESPACE_STRIP == Config.uri_whitespace) {
            t = q = host;
            while (*t) {
                if (!xisspace(*t)) {
                    *q = *t;
                    ++q;
                }
                ++t;
            }
            *q = '\0';
        }
    }

    debugs(23, 3, "urlParse: Split URL '" << url << "' into proto='" << proto << "', host='" << host << "', port='" << port << "', path='" << urlpath << "'");

    if (Config.onoff.check_hostnames && strspn(host, Config.onoff.allow_underscore ? valid_hostname_chars_u : valid_hostname_chars) != strlen(host)) {
        debugs(23, DBG_IMPORTANT, "urlParse: Illegal character in hostname '" << host << "'");
        return NULL;
    }

    if (!urlAppendDomain(host))
        return NULL;

    /* remove trailing dots from hostnames */
    while ((l = strlen(host)) > 0 && host[--l] == '.')
        host[l] = '\0';

    /* reject duplicate or leading dots */
    if (strstr(host, "..") || *host == '.') {
        debugs(23, DBG_IMPORTANT, "urlParse: Illegal hostname '" << host << "'");
        return NULL;
    }

    if (port < 1 || port > 65535) {
        debugs(23, 3, "urlParse: Invalid port '" << port << "'");
        return NULL;
    }

#if HARDCODE_DENY_PORTS
    /* These ports are filtered in the default squid.conf, but
     * maybe someone wants them hardcoded... */
    if (port == 7 || port == 9 || port == 19) {
        debugs(23, DBG_CRITICAL, "urlParse: Deny access to port " << port);
        return NULL;
    }
#endif

    if (stringHasWhitespace(urlpath)) {
        debugs(23, 2, "urlParse: URI has whitespace: {" << url << "}");

        switch (Config.uri_whitespace) {

        case URI_WHITESPACE_DENY:
            return NULL;

        case URI_WHITESPACE_ALLOW:
            break;

        case URI_WHITESPACE_ENCODE:
            t = rfc1738_escape_unescaped(urlpath);
            xstrncpy(urlpath, t, MAX_URL);
            break;

        case URI_WHITESPACE_CHOP:
            *(urlpath + strcspn(urlpath, w_space)) = '\0';
            break;

        case URI_WHITESPACE_STRIP:
        default:
            t = q = urlpath;
            while (*t) {
                if (!xisspace(*t)) {
                    *q = *t;
                    ++q;
                }
                ++t;
            }
            *q = '\0';
        }
    }

    return urlParseFinish(method, protocol, urlpath, host, login, port, request);
}

/**
 * Update request with parsed URI data.  If the request arg is
 * non-NULL, put parsed values there instead of allocating a new
 * HttpRequest.
 */
static HttpRequest *
urlParseFinish(const HttpRequestMethod& method,
               const AnyP::ProtocolType protocol,
               const char *const urlpath,
               const char *const host,
               const char *const login,
               const int port,
               HttpRequest *request)
{
    if (NULL == request)
        request = new HttpRequest(method, protocol, urlpath);
    else {
        request->initHTTP(method, protocol, urlpath);
        safe_free(request->canonical);
    }

    request->SetHost(host);
    xstrncpy(request->login, login, MAX_LOGIN_SZ);
    request->port = (unsigned short) port;
    return request;
}

static HttpRequest *
urnParse(const HttpRequestMethod& method, char *urn, HttpRequest *request)
{
    debugs(50, 5, "urnParse: " << urn);
    if (request) {
        request->initHTTP(method, AnyP::PROTO_URN, urn + 4);
        safe_free(request->canonical);
        return request;
    }

    return new HttpRequest(method, AnyP::PROTO_URN, urn + 4);
}

const char *
urlCanonical(HttpRequest * request)
{
    LOCAL_ARRAY(char, portbuf, 32);
    LOCAL_ARRAY(char, urlbuf, MAX_URL);

    if (request->canonical)
        return request->canonical;

    if (request->url.getScheme() == AnyP::PROTO_URN) {
        snprintf(urlbuf, MAX_URL, "urn:" SQUIDSTRINGPH,
                 SQUIDSTRINGPRINT(request->urlpath));
    } else {
        switch (request->method.id()) {

        case Http::METHOD_CONNECT:
            snprintf(urlbuf, MAX_URL, "%s:%d", request->GetHost(), request->port);
            break;

        default: {
            portbuf[0] = '\0';

            if (request->port != urlDefaultPort(request->url.getScheme()))
                snprintf(portbuf, 32, ":%d", request->port);

            snprintf(urlbuf, MAX_URL, "%s://%s%s%s%s" SQUIDSTRINGPH,
                     request->url.getScheme().c_str(),
                     request->login,
                     *request->login ? "@" : null_string,
                     request->GetHost(),
                     portbuf,
                     SQUIDSTRINGPRINT(request->urlpath));
        }
        }
    }

    return (request->canonical = xstrdup(urlbuf));
}

/** \todo AYJ: Performance: This is an *almost* duplicate of urlCanonical. But elides the query-string.
 *        After copying it on in the first place! Would be less code to merge the two with a flag parameter.
 *        and never copy the query-string part in the first place
 */
char *
urlCanonicalClean(const HttpRequest * request)
{
    LOCAL_ARRAY(char, buf, MAX_URL);
    LOCAL_ARRAY(char, portbuf, 32);
    LOCAL_ARRAY(char, loginbuf, MAX_LOGIN_SZ + 1);
    char *t;

    if (request->url.getScheme() == AnyP::PROTO_URN) {
        snprintf(buf, MAX_URL, "urn:" SQUIDSTRINGPH,
                 SQUIDSTRINGPRINT(request->urlpath));
    } else {
        switch (request->method.id()) {

        case Http::METHOD_CONNECT:
            snprintf(buf, MAX_URL, "%s:%d", request->GetHost(), request->port);
            break;

        default: {
            portbuf[0] = '\0';

            if (request->port != urlDefaultPort(request->url.getScheme()))
                snprintf(portbuf, 32, ":%d", request->port);

            loginbuf[0] = '\0';

            if ((int) strlen(request->login) > 0) {
                strcpy(loginbuf, request->login);

                if ((t = strchr(loginbuf, ':')))
                    *t = '\0';

                strcat(loginbuf, "@");
            }

            snprintf(buf, MAX_URL, "%s://%s%s%s" SQUIDSTRINGPH,
                     request->url.getScheme().c_str(),
                     loginbuf,
                     request->GetHost(),
                     portbuf,
                     SQUIDSTRINGPRINT(request->urlpath));

            // strip arguments AFTER a question-mark
            if (Config.onoff.strip_query_terms)
                if ((t = strchr(buf, '?')))
                    *(++t) = '\0';
        }
        }
    }

    if (stringHasCntl(buf))
        xstrncpy(buf, rfc1738_escape_unescaped(buf), MAX_URL);

    return buf;
}

/**
 * Yet another alternative to urlCanonical.
 * This one adds the https:// parts to Http::METHOD_CONNECT URL
 * for use in error page outputs.
 * Luckily we can leverage the others instead of duplicating.
 */
const char *
urlCanonicalFakeHttps(const HttpRequest * request)
{
    LOCAL_ARRAY(char, buf, MAX_URL);

    // method CONNECT and port HTTPS
    if (request->method == Http::METHOD_CONNECT && request->port == 443) {
        snprintf(buf, MAX_URL, "https://%s/*", request->GetHost());
        return buf;
    }

    // else do the normal complete canonical thing.
    return urlCanonicalClean(request);
}

/*
 * Test if a URL is relative.
 *
 * RFC 2396, Section 5 (Page 17) implies that in a relative URL, a '/' will
 * appear before a ':'.
 */
bool
urlIsRelative(const char *url)
{
    const char *p;

    if (url == NULL) {
        return (false);
    }
    if (*url == '\0') {
        return (false);
    }

    for (p = url; *p != '\0' && *p != ':' && *p != '/'; ++p);

    if (*p == ':') {
        return (false);
    }
    return (true);
}

/*
 * Convert a relative URL to an absolute URL using the context of a given
 * request.
 *
 * It is assumed that you have already ensured that the URL is relative.
 *
 * If NULL is returned it is an indication that the method in use in the
 * request does not distinguish between relative and absolute and you should
 * use the url unchanged.
 *
 * If non-NULL is returned, it is up to the caller to free the resulting
 * memory using safe_free().
 */
char *
urlMakeAbsolute(const HttpRequest * req, const char *relUrl)
{

    if (req->method.id() == Http::METHOD_CONNECT) {
        return (NULL);
    }

    char *urlbuf = (char *)xmalloc(MAX_URL * sizeof(char));

    if (req->url.getScheme() == AnyP::PROTO_URN) {
        snprintf(urlbuf, MAX_URL, "urn:" SQUIDSTRINGPH,
                 SQUIDSTRINGPRINT(req->urlpath));
        return (urlbuf);
    }

    size_t urllen;

    if (req->port != urlDefaultPort(req->url.getScheme())) {
        urllen = snprintf(urlbuf, MAX_URL, "%s://%s%s%s:%d",
                          req->url.getScheme().c_str(),
                          req->login,
                          *req->login ? "@" : null_string,
                          req->GetHost(),
                          req->port
                         );
    } else {
        urllen = snprintf(urlbuf, MAX_URL, "%s://%s%s%s",
                          req->url.getScheme().c_str(),
                          req->login,
                          *req->login ? "@" : null_string,
                          req->GetHost()
                         );
    }

    if (relUrl[0] == '/') {
        strncpy(&urlbuf[urllen], relUrl, MAX_URL - urllen - 1);
    } else {
        const char *path = req->urlpath.termedBuf();
        const char *last_slash = strrchr(path, '/');

        if (last_slash == NULL) {
            urlbuf[urllen] = '/';
            ++urllen;
            strncpy(&urlbuf[urllen], relUrl, MAX_URL - urllen - 1);
        } else {
            ++last_slash;
            size_t pathlen = last_slash - path;
            if (pathlen > MAX_URL - urllen - 1) {
                pathlen = MAX_URL - urllen - 1;
            }
            strncpy(&urlbuf[urllen], path, pathlen);
            urllen += pathlen;
            if (urllen + 1 < MAX_URL) {
                strncpy(&urlbuf[urllen], relUrl, MAX_URL - urllen - 1);
            }
        }
    }

    return (urlbuf);
}

int
matchDomainName(const char *h, const char *d, uint flags)
{
    int dl;
    int hl;

    const bool hostIncludesSubdomains = (*h == '.');
    while ('.' == *h)
        ++h;

    hl = strlen(h);

    if (hl == 0)
        return -1;

    dl = strlen(d);

    /*
     * Start at the ends of the two strings and work towards the
     * beginning.
     */
    while (xtolower(h[--hl]) == xtolower(d[--dl])) {
        if (hl == 0 && dl == 0) {
            /*
             * We made it all the way to the beginning of both
             * strings without finding any difference.
             */
            return 0;
        }

        if (0 == hl) {
            /*
             * The host string is shorter than the domain string.
             * There is only one case when this can be a match.
             * If the domain is just one character longer, and if
             * that character is a leading '.' then we call it a
             * match.
             */

            if (1 == dl && '.' == d[0])
                return 0;
            else
                return -1;
        }

        if (0 == dl) {
            /*
             * The domain string is shorter than the host string.
             * This is a match only if the first domain character
             * is a leading '.'.
             */

            if ('.' == d[0]) {
                if (flags & mdnRejectSubsubDomains) {
                    // Check for sub-sub domain and reject
                    while(--hl >= 0 && h[hl] != '.');
                    if (hl < 0) {
                        // No sub-sub domain found, but reject if there is a
                        // leading dot in given host string (which is removed
                        // before the check is started).
                        return hostIncludesSubdomains ? 1 : 0;
                    } else
                        return 1; // sub-sub domain, reject
                } else
                    return 0;
            } else
                return 1;
        }
    }

    /*
     * We found different characters in the same position (from the end).
     */

    // If the h has a form of "*.foo.com" and d has a form of "x.foo.com"
    // then the h[hl] points to '*', h[hl+1] to '.' and d[dl] to 'x'
    // The following checks are safe, the "h[hl + 1]" in the worst case is '\0'.
    if ((flags & mdnHonorWildcards) && h[hl] == '*' && h[hl + 1] == '.')
        return 0;

    /*
     * If one of those character is '.' then its special.  In order
     * for splay tree sorting to work properly, "x-foo.com" must
     * be greater than ".foo.com" even though '-' is less than '.'.
     */
    if ('.' == d[dl])
        return 1;

    if ('.' == h[hl])
        return -1;

    return (xtolower(h[hl]) - xtolower(d[dl]));
}

/*
 * return true if we can serve requests for this method.
 */
int
urlCheckRequest(const HttpRequest * r)
{
    int rc = 0;
    /* protocol "independent" methods
     *
     * actually these methods are specific to HTTP:
     * they are methods we recieve on our HTTP port,
     * and if we had a FTP listener would not be relevant
     * there.
     *
     * So, we should delegate them to HTTP. The problem is that we
     * do not have a default protocol from the client side of HTTP.
     */

    if (r->method == Http::METHOD_CONNECT)
        return 1;

    // we support OPTIONS and TRACE directed at us (with a 501 reply, for now)
    // we also support forwarding OPTIONS and TRACE, except for the *-URI ones
    if (r->method == Http::METHOD_OPTIONS || r->method == Http::METHOD_TRACE)
        return (r->header.getInt64(HDR_MAX_FORWARDS) == 0 || r->urlpath != "*");

    if (r->method == Http::METHOD_PURGE)
        return 1;

    /* does method match the protocol? */
    switch (r->url.getScheme()) {

    case AnyP::PROTO_URN:

    case AnyP::PROTO_HTTP:

    case AnyP::PROTO_CACHE_OBJECT:
        rc = 1;
        break;

    case AnyP::PROTO_FTP:

        if (r->method == Http::METHOD_PUT)
            rc = 1;

    case AnyP::PROTO_GOPHER:

    case AnyP::PROTO_WAIS:

    case AnyP::PROTO_WHOIS:
        if (r->method == Http::METHOD_GET)
            rc = 1;
        else if (r->method == Http::METHOD_HEAD)
            rc = 1;

        break;

    case AnyP::PROTO_HTTPS:
#if USE_OPENSSL

        rc = 1;

        break;

#else
        /*
        * Squid can't originate an SSL connection, so it should
        * never receive an "https:" URL.  It should always be
        * CONNECT instead.
        */
        rc = 0;

#endif

    default:
        break;
    }

    return rc;
}

/*
 * Quick-n-dirty host extraction from a URL.  Steps:
 *      Look for a colon
 *      Skip any '/' after the colon
 *      Copy the next SQUID_MAXHOSTNAMELEN bytes to host[]
 *      Look for an ending '/' or ':' and terminate
 *      Look for login info preceeded by '@'
 */

class URLHostName
{

public:
    char * extract(char const *url);

private:
    static char Host [SQUIDHOSTNAMELEN];
    void init(char const *);
    void findHostStart();
    void trimTrailingChars();
    void trimAuth();
    char const *hostStart;
    char const *url;
};

char *
urlHostname(const char *url)
{
    return URLHostName().extract(url);
}

char URLHostName::Host[SQUIDHOSTNAMELEN];

void
URLHostName::init(char const *aUrl)
{
    Host[0] = '\0';
    url = aUrl;
}

void
URLHostName::findHostStart()
{
    if (NULL == (hostStart = strchr(url, ':')))
        return;

    ++hostStart;

    while (*hostStart != '\0' && *hostStart == '/')
        ++hostStart;

    if (*hostStart == ']')
        ++hostStart;
}

void
URLHostName::trimTrailingChars()
{
    char *t;

    if ((t = strchr(Host, '/')))
        *t = '\0';

    if ((t = strrchr(Host, ':')))
        *t = '\0';

    if ((t = strchr(Host, ']')))
        *t = '\0';
}

void
URLHostName::trimAuth()
{
    char *t;

    if ((t = strrchr(Host, '@'))) {
        ++t;
        memmove(Host, t, strlen(t) + 1);
    }
}

char *
URLHostName::extract(char const *aUrl)
{
    init(aUrl);
    findHostStart();

    if (hostStart == NULL)
        return NULL;

    xstrncpy(Host, hostStart, SQUIDHOSTNAMELEN);

    trimTrailingChars();

    trimAuth();

    return Host;
}

