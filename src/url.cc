
/*
 * $Id: url.cc,v 1.144 2003/03/09 12:29:41 robertc Exp $
 *
 * DEBUG: section 23    URL Parsing
 * AUTHOR: Duane Wessels
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
#include "HttpRequest.h"

const char *RequestMethodStr[] =
    {
        "NONE",
        "GET",
        "POST",
        "PUT",
        "HEAD",
        "CONNECT",
        "TRACE",
        "PURGE",
        "OPTIONS",
        "DELETE",
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
        "BMOVE",
        "BDELETE",
        "BPROPFIND",
        "BPROPPATCH",
        "BCOPY",
        "SEARCH",
        "SUBSCRIBE",
        "UNSUBSCRIBE",
        "POLL",
        "%EXT00",
        "%EXT01",
        "%EXT02",
        "%EXT03",
        "%EXT04",
        "%EXT05",
        "%EXT06",
        "%EXT07",
        "%EXT08",
        "%EXT09",
        "%EXT10",
        "%EXT11",
        "%EXT12",
        "%EXT13",
        "%EXT14",
        "%EXT15",
        "%EXT16",
        "%EXT17",
        "%EXT18",
        "%EXT19",
        "ERROR"
    };

const char *ProtocolStr[] =
    {
        "NONE",
        "http",
        "ftp",
        "gopher",
        "wais",
        "cache_object",
        "icp",
#if USE_HTCP
        "htcp",
#endif
        "urn",
        "whois",
        "internal",
        "https",
        "TOTAL"
    };

static request_t *urnParse(method_t method, char *urn);
#if CHECK_HOSTNAMES
static const char *const valid_hostname_chars =
#if ALLOW_HOSTNAME_UNDERSCORES
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-._";
#else
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-."
    ;
#endif
#endif /* CHECK_HOSTNAMES */

/* convert %xx in url string to a character
 * Allocate a new string and return a pointer to converted string */

char *
url_convert_hex(char *org_url, int allocate)
{
    static char code[] = "00";
    char *url = NULL;
    char *s = NULL;
    char *t = NULL;
    url = allocate ? (char *) xstrdup(org_url) : org_url;

    if ((int) strlen(url) < 3 || !strchr(url, '%'))
        return url;

    for (s = t = url; *s; s++) {
        if (*s == '%' && *(s + 1) && *(s + 2)) {
            code[0] = *(++s);
            code[1] = *(++s);
            *t++ = (char) strtol(code, NULL, 16);
        } else {
            *t++ = *s;
        }
    }

    do {
        *t++ = *s;
    } while (*s++);

    return url;
}

void
urlInitialize(void)
{
    debug(23, 5) ("urlInitialize: Initializing...\n");
    assert(sizeof(ProtocolStr) == (PROTO_MAX + 1) * sizeof(char *));
    /*
     * These test that our matchDomainName() function works the
     * way we expect it to.
     */
    assert(0 == matchDomainName("foo.com", "foo.com"));
    assert(0 == matchDomainName(".foo.com", "foo.com"));
    assert(0 == matchDomainName("foo.com", ".foo.com"));
    assert(0 == matchDomainName(".foo.com", ".foo.com"));
    assert(0 == matchDomainName("x.foo.com", ".foo.com"));
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
    /* more cases? */
}

method_t &operator++ (method_t &aMethod)
{
    int tmp = (int)aMethod;
    aMethod = (method_t)(++tmp);
    return aMethod;
}


method_t
urlParseMethod(const char *s)
{
    method_t method = METHOD_NONE;
    /*
     * This check for '%' makes sure that we don't
     * match one of the extension method placeholders,
     * which have the form %EXT[0-9][0-9]
     */

    if (*s == '%')
        return METHOD_NONE;

    for (++method; method < METHOD_ENUM_END; ++method) {
        if (0 == strcasecmp(s, RequestMethodStr[method]))
            return method;
    }

    return METHOD_NONE;
}


protocol_t
urlParseProtocol(const char *s)
{
    /* test common stuff first */

    if (strcasecmp(s, "http") == 0)
        return PROTO_HTTP;

    if (strcasecmp(s, "ftp") == 0)
        return PROTO_FTP;

    if (strcasecmp(s, "https") == 0)
        return PROTO_HTTPS;

    if (strcasecmp(s, "file") == 0)
        return PROTO_FTP;

    if (strcasecmp(s, "gopher") == 0)
        return PROTO_GOPHER;

    if (strcasecmp(s, "wais") == 0)
        return PROTO_WAIS;

    if (strcasecmp(s, "cache_object") == 0)
        return PROTO_CACHEOBJ;

    if (strcasecmp(s, "urn") == 0)
        return PROTO_URN;

    if (strcasecmp(s, "whois") == 0)
        return PROTO_WHOIS;

    if (strcasecmp(s, "internal") == 0)
        return PROTO_INTERNAL;

    return PROTO_NONE;
}


int
urlDefaultPort(protocol_t p)
{
    switch (p) {

    case PROTO_HTTP:
        return 80;

    case PROTO_HTTPS:
        return 443;

    case PROTO_FTP:
        return 21;

    case PROTO_GOPHER:
        return 70;

    case PROTO_WAIS:
        return 210;

    case PROTO_CACHEOBJ:

    case PROTO_INTERNAL:
        return CACHE_HTTP_PORT;

    case PROTO_WHOIS:
        return 43;

    default:
        return 0;
    }
}

request_t *
urlParse(method_t method, char *url)
{
    LOCAL_ARRAY(char, proto, MAX_URL);
    LOCAL_ARRAY(char, login, MAX_URL);
    LOCAL_ARRAY(char, host, MAX_URL);
    LOCAL_ARRAY(char, urlpath, MAX_URL);
    request_t *request = NULL;
    char *t = NULL;
    char *q = NULL;
    int port;
    protocol_t protocol = PROTO_NONE;
    int l;
    proto[0] = host[0] = urlpath[0] = login[0] = '\0';

    if ((l = strlen(url)) + Config.appendDomainLen > (MAX_URL - 1)) {
        /* terminate so it doesn't overflow other buffers */
        *(url + (MAX_URL >> 1)) = '\0';
        debug(23, 1) ("urlParse: URL too large (%d bytes)\n", l);
        return NULL;
    }

    if (method == METHOD_CONNECT) {
        port = CONNECT_PORT;

        if (sscanf(url, "%[^:]:%d", host, &port) < 1)
            return NULL;
    } else if (!strncmp(url, "urn:", 4)) {
        return urnParse(method, url);
    } else {
        if (sscanf(url, "%[^:]://%[^/]%[^\r\n]", proto, host, urlpath) < 2)
            return NULL;

        protocol = urlParseProtocol(proto);

        port = urlDefaultPort(protocol);

        /* Is there any login informaiton? */
        if ((t = strrchr(host, '@'))) {
            strcpy((char *) login, (char *) host);
            t = strrchr(login, '@');
            *t = 0;
            strcpy((char *) host, t + 1);
        }

        if ((t = strrchr(host, ':'))) {
            *t++ = '\0';

            if (*t != '\0')
                port = atoi(t);
        }
    }

    for (t = host; *t; t++)
        *t = xtolower(*t);

    if (stringHasWhitespace(host)) {
        if (URI_WHITESPACE_STRIP == Config.uri_whitespace) {
            t = q = host;

            while (*t) {
                if (!xisspace(*t))
                    *q++ = *t;

                t++;
            }

            *q = '\0';
        }
    }

#if CHECK_HOSTNAMES
    if (Config.onoff.check_hostnames && strspn(host, valid_hostname_chars) != strlen(host)) {
        debug(23, 1) ("urlParse: Illegal character in hostname '%s'\n", host);
        return NULL;
    }

#endif
#if DONT_DO_THIS_IT_BREAKS_SEMANTIC_TRANSPARENCY
    /* remove trailing dots from hostnames */
    while ((l = strlen(host)) > 0 && host[--l] == '.')
        host[l] = '\0';

    /* remove duplicate dots */
    while ((t = strstr(host, "..")))
        xmemmove(t, t + 1, strlen(t));

#endif

    if (Config.appendDomain && !strchr(host, '.'))
        strncat(host, Config.appendDomain, SQUIDHOSTNAMELEN);

    if (port < 1 || port > 65535) {
        debug(23, 3) ("urlParse: Invalid port '%d'\n", port);
        return NULL;
    }

#ifdef HARDCODE_DENY_PORTS
    /* These ports are filtered in the default squid.conf, but
     * maybe someone wants them hardcoded... */
    if (port == 7 || port == 9 || port == 19) {
        debug(23, 0) ("urlParse: Deny access to port %d\n", port);
        return NULL;
    }

#endif
    if (stringHasWhitespace(urlpath)) {
        debug(23, 2) ("urlParse: URI has whitespace: {%s}\n", url);

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
                if (!xisspace(*t))
                    *q++ = *t;

                t++;
            }

            *q = '\0';
        }
    }

    request = requestCreate(method, protocol, urlpath);
    xstrncpy(request->host, host, SQUIDHOSTNAMELEN);
    xstrncpy(request->login, login, MAX_LOGIN_SZ);
    request->port = (u_short) port;
    return request;
}

static request_t *
urnParse(method_t method, char *urn)
{
    debug(50, 5) ("urnParse: %s\n", urn);
    return requestCreate(method, PROTO_URN, urn + 4);
}

const char *
urlCanonical(request_t * request)
{
    LOCAL_ARRAY(char, portbuf, 32);
    LOCAL_ARRAY(char, urlbuf, MAX_URL);

    if (request->canonical)
        return request->canonical;

    if (request->protocol == PROTO_URN) {
        snprintf(urlbuf, MAX_URL, "urn:%s", request->urlpath.buf());
    } else {
        switch (request->method) {

        case METHOD_CONNECT:
            snprintf(urlbuf, MAX_URL, "%s:%d", request->host, request->port);
            break;

        default:
            portbuf[0] = '\0';

            if (request->port != urlDefaultPort(request->protocol))
                snprintf(portbuf, 32, ":%d", request->port);

            snprintf(urlbuf, MAX_URL, "%s://%s%s%s%s%s",
                     ProtocolStr[request->protocol],
                     request->login,
                     *request->login ? "@" : null_string,
                     request->host,
                     portbuf,
                     request->urlpath.buf());

            break;
        }
    }

    return (request->canonical = xstrdup(urlbuf));
}

char *
urlCanonicalClean(const request_t * request)
{
    LOCAL_ARRAY(char, buf, MAX_URL);
    LOCAL_ARRAY(char, portbuf, 32);
    LOCAL_ARRAY(char, loginbuf, MAX_LOGIN_SZ + 1);
    char *t;

    if (request->protocol == PROTO_URN) {
        snprintf(buf, MAX_URL, "urn:%s", request->urlpath.buf());
    } else {
        switch (request->method) {

        case METHOD_CONNECT:
            snprintf(buf, MAX_URL, "%s:%d", request->host, request->port);
            break;

        default:
            portbuf[0] = '\0';

            if (request->port != urlDefaultPort(request->protocol))
                snprintf(portbuf, 32, ":%d", request->port);

            loginbuf[0] = '\0';

            if ((int) strlen(request->login) > 0) {
                strcpy(loginbuf, request->login);

                if ((t = strchr(loginbuf, ':')))
                    *t = '\0';

                strcat(loginbuf, "@");
            }

            snprintf(buf, MAX_URL, "%s://%s%s%s%s",
                     ProtocolStr[request->protocol],
                     loginbuf,
                     request->host,
                     portbuf,
                     request->urlpath.buf());
            /*
             * strip arguments AFTER a question-mark
             */

            if (Config.onoff.strip_query_terms)
                if ((t = strchr(buf, '?')))
                    *(++t) = '\0';

            break;
        }
    }

    if (stringHasCntl(buf))
        xstrncpy(buf, rfc1738_escape_unescaped(buf), MAX_URL);

    return buf;
}

/*
 * matchDomainName() compares a hostname with a domainname according
 * to the following rules:
 * 
 *    HOST          DOMAIN        MATCH?
 * ------------- -------------    ------
 *    foo.com       foo.com         YES
 *   .foo.com       foo.com         YES
 *  x.foo.com       foo.com          NO
 *    foo.com      .foo.com         YES
 *   .foo.com      .foo.com         YES
 *  x.foo.com      .foo.com         YES
 *
 *  We strip leading dots on hosts (but not domains!) so that
 *  ".foo.com" is is always the same as "foo.com".
 *
 *  Return values:
 *     0 means the host matches the domain
 *     1 means the host is greater than the domain
 *    -1 means the host is less than the domain
 */

int
matchDomainName(const char *h, const char *d)
{
    int dl;
    int hl;

    while ('.' == *h)
        h++;

    hl = strlen(h);

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

            if ('.' == d[0])
                return 0;
            else
                return 1;
        }
    }

    /*
     * We found different characters in the same position (from the end).
     */
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

int
urlCheckRequest(const request_t * r)
{
    int rc = 0;
    /* protocol "independent" methods */

    if (r->method == METHOD_CONNECT)
        return 1;

    if (r->method == METHOD_TRACE)
        return 1;

    if (r->method == METHOD_PURGE)
        return 1;

    /* does method match the protocol? */
    switch (r->protocol) {

    case PROTO_URN:

    case PROTO_HTTP:

    case PROTO_CACHEOBJ:
        rc = 1;
        break;

    case PROTO_FTP:

        if (r->method == METHOD_PUT)
            rc = 1;

    case PROTO_GOPHER:

    case PROTO_WAIS:

    case PROTO_WHOIS:
        if (r->method == METHOD_GET)
            rc = 1;
        else if (r->method == METHOD_HEAD)
            rc = 1;

        break;

    case PROTO_HTTPS:
#ifdef USE_SSL

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
char *
urlHostname(const char *url)
{
    LOCAL_ARRAY(char, host, SQUIDHOSTNAMELEN);
    char *t;
    host[0] = '\0';

    if (NULL == (t = strchr(url, ':')))
        return NULL;

    t++;

    while (*t != '\0' && *t == '/')
        t++;

    xstrncpy(host, t, SQUIDHOSTNAMELEN);

    if ((t = strchr(host, '/')))
        *t = '\0';

    if ((t = strchr(host, ':')))
        *t = '\0';

    if ((t = strrchr(host, '@'))) {
        t++;
        xmemmove(host, t, strlen(t) + 1);
    }

    return host;
}

static void
urlExtMethodAdd(const char *mstr)
{
    method_t method = METHOD_NONE;

    for (++method; method < METHOD_ENUM_END; ++method) {
        if (0 == strcmp(mstr, RequestMethodStr[method])) {
            debug(23, 2) ("Extension method '%s' already exists\n", mstr);
            return;
        }

        if (0 != strncmp("%EXT", RequestMethodStr[method], 4))
            continue;

        /* Don't free statically allocated "%EXTnn" string */
        RequestMethodStr[method] = xstrdup(mstr);

        debug(23, 1) ("Extension method '%s' added, enum=%d\n", mstr, (int) method);

        return;
    }

    debug(23, 1) ("WARNING: Could not add new extension method '%s' due to lack of array space\n", mstr);
}

void
urlExtMethodConfigure(void)
{
    wordlist *w = Config.ext_methods;

    while (w) {
        char *s;

        for (s = w->key; *s; s++)
            *s = xtoupper(*s);

        urlExtMethodAdd(w->key);

        w = w->next;
    }
}
