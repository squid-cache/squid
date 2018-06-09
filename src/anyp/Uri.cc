/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 23    URL Parsing */

#include "squid.h"
#include "anyp/Uri.h"
#include "globals.h"
#include "HttpRequest.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidString.h"

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

const SBuf &
AnyP::Uri::Asterisk()
{
    static SBuf star("*");
    return star;
}

const SBuf &
AnyP::Uri::SlashPath()
{
    static SBuf slash("/");
    return slash;
}

void
AnyP::Uri::host(const char *src)
{
    hostAddr_.setEmpty();
    hostAddr_ = src;
    if (hostAddr_.isAnyAddr()) {
        xstrncpy(host_, src, sizeof(host_));
        hostIsNumeric_ = false;
    } else {
        hostAddr_.toHostStr(host_, sizeof(host_));
        debugs(23, 3, "given IP: " << hostAddr_);
        hostIsNumeric_ = 1;
    }
    touch();
}

const SBuf &
AnyP::Uri::path() const
{
    // RFC 3986 section 3.3 says path can be empty (path-abempty).
    // RFC 7230 sections 2.7.3, 5.3.1, 5.7.2 - says path cannot be empty, default to "/"
    // at least when sending and using. We must still accept path-abempty as input.
    if (path_.isEmpty() && (scheme_ == AnyP::PROTO_HTTP || scheme_ == AnyP::PROTO_HTTPS))
        return SlashPath();

    return path_;
}

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
 * Parse the scheme name from string b, into protocol type.
 * The string must be 0-terminated.
 */
AnyP::ProtocolType
urlParseProtocol(const char *b)
{
    // make e point to the ':' character
    const char *e = b + strcspn(b, ":");
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

    if (len > 0)
        return AnyP::PROTO_UNKNOWN;

    return AnyP::PROTO_NONE;
}

/*
 * Parse a URI/URL.
 *
 * Stores parsed values in the `request` argument.
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
bool
AnyP::Uri::parse(const HttpRequestMethod& method, const char *url)
{
    LOCAL_ARRAY(char, proto, MAX_URL);
    LOCAL_ARRAY(char, login, MAX_URL);
    LOCAL_ARRAY(char, foundHost, MAX_URL);
    LOCAL_ARRAY(char, urlpath, MAX_URL);
    char *t = NULL;
    char *q = NULL;
    int foundPort;
    AnyP::ProtocolType protocol = AnyP::PROTO_NONE;
    int l;
    int i;
    const char *src;
    char *dst;
    proto[0] = foundHost[0] = urlpath[0] = login[0] = '\0';

    if ((l = strlen(url)) + Config.appendDomainLen > (MAX_URL - 1)) {
        debugs(23, DBG_IMPORTANT, MYNAME << "URL too large (" << l << " bytes)");
        return false;
    }
    if (method == Http::METHOD_CONNECT) {
        /*
         * RFC 7230 section 5.3.3:  authority-form = authority
         *  "excluding any userinfo and its "@" delimiter"
         *
         * RFC 3986 section 3.2:    authority = [ userinfo "@" ] host [ ":" port ]
         *
         * As an HTTP(S) proxy we assume HTTPS (443) if no port provided.
         */
        foundPort = 443;

        if (sscanf(url, "[%[^]]]:%d", foundHost, &foundPort) < 1)
            if (sscanf(url, "%[^:]:%d", foundHost, &foundPort) < 1)
                return false;

    } else if ((method == Http::METHOD_OPTIONS || method == Http::METHOD_TRACE) &&
               AnyP::Uri::Asterisk().cmp(url) == 0) {
        parseFinish(AnyP::PROTO_HTTP, nullptr, url, foundHost, SBuf(), 80 /* HTTP default port */);
        return true;
    } else if (strncmp(url, "urn:", 4) == 0) {
        debugs(23, 3, "Split URI '" << url << "' into proto='urn', path='" << (url+4) << "'");
        debugs(50, 5, "urn=" << (url+4));
        setScheme(AnyP::PROTO_URN, nullptr);
        path(url + 4);
        return true;
    } else {
        /* Parse the URL: */
        src = url;
        i = 0;
        /* Find first : - everything before is protocol */
        for (i = 0, dst = proto; i < l && *src != ':'; ++i, ++src, ++dst) {
            *dst = *src;
        }
        if (i >= l)
            return false;
        *dst = '\0';

        /* Then its :// */
        if ((i+3) > l || *src != ':' || *(src + 1) != '/' || *(src + 2) != '/')
            return false;
        i += 3;
        src += 3;

        /* Then everything until first /; thats host (and port; which we'll look for here later) */
        // bug 1881: If we don't get a "/" then we imply it was there
        // bug 3074: We could just be given a "?" or "#". These also imply "/"
        // bug 3233: whitespace is also a hostname delimiter.
        for (dst = foundHost; i < l && *src != '/' && *src != '?' && *src != '#' && *src != '\0' && !xisspace(*src); ++i, ++src, ++dst) {
            *dst = *src;
        }

        /*
         * We can't check for "i >= l" here because we could be at the end of the line
         * and have a perfectly valid URL w/ no trailing '/'. In this case we assume we've
         * been -given- a valid URL and the path is just '/'.
         */
        if (i > l)
            return false;
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
            return false;
        /* If the URL path is empty we set it to be "/" */
        if (dst == urlpath) {
            *dst = '/';
            ++dst;
        }
        *dst = '\0';

        protocol = urlParseProtocol(proto);
        foundPort = AnyP::UriScheme(protocol).defaultPort();

        /* Is there any login information? (we should eventually parse it above) */
        t = strrchr(foundHost, '@');
        if (t != NULL) {
            strncpy((char *) login, (char *) foundHost, sizeof(login)-1);
            login[sizeof(login)-1] = '\0';
            t = strrchr(login, '@');
            *t = 0;
            strncpy((char *) foundHost, t + 1, sizeof(foundHost)-1);
            foundHost[sizeof(foundHost)-1] = '\0';
            // Bug 4498: URL-unescape the login info after extraction
            rfc1738_unescape(login);
        }

        /* Is there any host information? (we should eventually parse it above) */
        if (*foundHost == '[') {
            /* strip any IPA brackets. valid under IPv6. */
            dst = foundHost;
            /* only for IPv6 sadly, pre-IPv6/URL code can't handle the clean result properly anyway. */
            src = foundHost;
            ++src;
            l = strlen(foundHost);
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
            t = strrchr(foundHost, ':');

            if (t != strchr(foundHost,':') ) {
                /* RFC 2732 states IPv6 "SHOULD" be bracketed. allowing for times when its not. */
                /* RFC 3986 'update' simply modifies this to an "is" with no emphasis at all! */
                /* therefore we MUST accept the case where they are not bracketed at all. */
                t = NULL;
            }
        }

        // Bug 3183 sanity check: If scheme is present, host must be too.
        if (protocol != AnyP::PROTO_NONE && foundHost[0] == '\0') {
            debugs(23, DBG_IMPORTANT, "SECURITY ALERT: Missing hostname in URL '" << url << "'. see access.log for details.");
            return false;
        }

        if (t && *t == ':') {
            *t = '\0';
            ++t;
            foundPort = atoi(t);
        }
    }

    for (t = foundHost; *t; ++t)
        *t = xtolower(*t);

    if (stringHasWhitespace(foundHost)) {
        if (URI_WHITESPACE_STRIP == Config.uri_whitespace) {
            t = q = foundHost;
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

    debugs(23, 3, "Split URL '" << url << "' into proto='" << proto << "', host='" << foundHost << "', port='" << foundPort << "', path='" << urlpath << "'");

    if (Config.onoff.check_hostnames &&
            strspn(foundHost, Config.onoff.allow_underscore ? valid_hostname_chars_u : valid_hostname_chars) != strlen(foundHost)) {
        debugs(23, DBG_IMPORTANT, MYNAME << "Illegal character in hostname '" << foundHost << "'");
        return false;
    }

    /* For IPV6 addresses also check for a colon */
    if (Config.appendDomain && !strchr(foundHost, '.') && !strchr(foundHost, ':'))
        strncat(foundHost, Config.appendDomain, SQUIDHOSTNAMELEN - strlen(foundHost) - 1);

    /* remove trailing dots from hostnames */
    while ((l = strlen(foundHost)) > 0 && foundHost[--l] == '.')
        foundHost[l] = '\0';

    /* reject duplicate or leading dots */
    if (strstr(foundHost, "..") || *foundHost == '.') {
        debugs(23, DBG_IMPORTANT, MYNAME << "Illegal hostname '" << foundHost << "'");
        return false;
    }

    if (foundPort < 1 || foundPort > 65535) {
        debugs(23, 3, "Invalid port '" << foundPort << "'");
        return false;
    }

#if HARDCODE_DENY_PORTS
    /* These ports are filtered in the default squid.conf, but
     * maybe someone wants them hardcoded... */
    if (foundPort == 7 || foundPort == 9 || foundPort == 19) {
        debugs(23, DBG_CRITICAL, MYNAME << "Deny access to port " << foundPort);
        return false;
    }
#endif

    if (stringHasWhitespace(urlpath)) {
        debugs(23, 2, "URI has whitespace: {" << url << "}");

        switch (Config.uri_whitespace) {

        case URI_WHITESPACE_DENY:
            return false;

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

    parseFinish(protocol, proto, urlpath, foundHost, SBuf(login), foundPort);
    return true;
}

/// Update the URL object with parsed URI data.
void
AnyP::Uri::parseFinish(const AnyP::ProtocolType protocol,
                 const char *const protoStr, // for unknown protocols
                 const char *const aUrlPath,
                 const char *const aHost,
                 const SBuf &aLogin,
                 const int aPort)
{
    setScheme(protocol, protoStr);
    path(aUrlPath);
    host(aHost);
    userInfo(aLogin);
    port(aPort);
}

void
AnyP::Uri::touch()
{
    absolute_.clear();
    authorityHttp_.clear();
    authorityWithPort_.clear();
}

SBuf &
AnyP::Uri::authority(bool requirePort) const
{
    if (authorityHttp_.isEmpty()) {

        // both formats contain Host/IP
        authorityWithPort_.append(host());
        authorityHttp_ = authorityWithPort_;

        // authorityForm_ only has :port if it is non-default
        authorityWithPort_.appendf(":%u",port());
        if (port() != getScheme().defaultPort())
            authorityHttp_ = authorityWithPort_;
    }

    return requirePort ? authorityWithPort_ : authorityHttp_;
}

SBuf &
AnyP::Uri::absolute() const
{
    if (absolute_.isEmpty()) {
        // TODO: most URL will be much shorter, avoid allocating this much
        absolute_.reserveCapacity(MAX_URL);

        absolute_.append(getScheme().image());
        absolute_.append(":",1);
        if (getScheme() != AnyP::PROTO_URN) {
            absolute_.append("//", 2);
            const bool omitUserInfo = getScheme() == AnyP::PROTO_HTTP ||
                                      getScheme() != AnyP::PROTO_HTTPS ||
                                      userInfo().isEmpty();
            if (!omitUserInfo) {
                absolute_.append(userInfo());
                absolute_.append("@", 1);
            }
            absolute_.append(authority());
        }
        absolute_.append(path());
    }

    return absolute_;
}

/** \todo AYJ: Performance: This is an *almost* duplicate of HttpRequest::effectiveRequestUri(). But elides the query-string.
 *        After copying it on in the first place! Would be less code to merge the two with a flag parameter.
 *        and never copy the query-string part in the first place
 */
char *
urlCanonicalClean(const HttpRequest * request)
{
    LOCAL_ARRAY(char, buf, MAX_URL);

    snprintf(buf, sizeof(buf), SQUIDSBUFPH, SQUIDSBUFPRINT(request->effectiveRequestUri()));
    buf[sizeof(buf)-1] = '\0';

    // URN, CONNECT method, and non-stripped URIs can go straight out
    if (Config.onoff.strip_query_terms && !(request->method == Http::METHOD_CONNECT || request->url.getScheme() == AnyP::PROTO_URN)) {
        // strip anything AFTER a question-mark
        // leaving the '?' in place
        if (auto t = strchr(buf, '?')) {
            *(++t) = '\0';
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
    if (request->method == Http::METHOD_CONNECT && request->url.port() == 443) {
        snprintf(buf, MAX_URL, "https://%s/*", request->url.host());
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
        // XXX: this is what the original code did, but it seems to break the
        // intended behaviour of this function. It returns the stored URN path,
        // not converting the given one into a URN...
        snprintf(urlbuf, MAX_URL, SQUIDSBUFPH, SQUIDSBUFPRINT(req->url.absolute()));
        return (urlbuf);
    }

    SBuf authorityForm = req->url.authority(); // host[:port]
    const SBuf &scheme = req->url.getScheme().image();
    size_t urllen = snprintf(urlbuf, MAX_URL, SQUIDSBUFPH "://" SQUIDSBUFPH "%s" SQUIDSBUFPH,
                             SQUIDSBUFPRINT(scheme),
                             SQUIDSBUFPRINT(req->url.userInfo()),
                             !req->url.userInfo().isEmpty() ? "@" : "",
                             SQUIDSBUFPRINT(authorityForm));

    // if the first char is '/' assume its a relative path
    // XXX: this breaks on scheme-relative URLs,
    // but we should not see those outside ESI, and rarely there.
    // XXX: also breaks on any URL containing a '/' in the query-string portion
    if (relUrl[0] == '/') {
        xstrncpy(&urlbuf[urllen], relUrl, MAX_URL - urllen - 1);
    } else {
        SBuf path = req->url.path();
        SBuf::size_type lastSlashPos = path.rfind('/');

        if (lastSlashPos == SBuf::npos) {
            // replace the whole path with the given bit(s)
            urlbuf[urllen] = '/';
            ++urllen;
            xstrncpy(&urlbuf[urllen], relUrl, MAX_URL - urllen - 1);
        } else {
            // replace only the last (file?) segment with the given bit(s)
            ++lastSlashPos;
            if (lastSlashPos > MAX_URL - urllen - 1) {
                // XXX: crops bits in the middle of the combined URL.
                lastSlashPos = MAX_URL - urllen - 1;
            }
            SBufToCstring(&urlbuf[urllen], path.substr(0,lastSlashPos));
            urllen += lastSlashPos;
            if (urllen + 1 < MAX_URL) {
                xstrncpy(&urlbuf[urllen], relUrl, MAX_URL - urllen - 1);
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
        return (r->header.getInt64(Http::HdrType::MAX_FORWARDS) == 0 || r->url.path() != AnyP::Uri::Asterisk());

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
#elif USE_GNUTLS
        rc = 1;
#else
        /*
        * Squid can't originate an SSL connection, so it should
        * never receive an "https:" URL.  It should always be
        * CONNECT instead.
        */
        rc = 0;
#endif
        break;

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

AnyP::Uri::Uri(AnyP::UriScheme const &aScheme) :
    scheme_(aScheme),
    hostIsNumeric_(false),
    port_(0)
{
    *host_=0;
}

