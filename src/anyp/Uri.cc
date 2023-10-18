/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 23    URL Parsing */

#include "squid.h"
#include "anyp/Uri.h"
#include "base/Raw.h"
#include "globals.h"
#include "HttpRequest.h"
#include "parser/Tokenizer.h"
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

/// Characters which are valid within a URI userinfo section
static const CharacterSet &
UserInfoChars()
{
    /*
     * RFC 3986 section 3.2.1
     *
     *  userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
     *  unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
     *  pct-encoded   = "%" HEXDIG HEXDIG
     *  sub-delims    = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
     */
    static const auto userInfoValid = CharacterSet("userinfo", ":-._~%!$&'()*+,;=") +
                                      CharacterSet::ALPHA +
                                      CharacterSet::DIGIT;
    return userInfoValid;
}

/**
 * Governed by RFC 3986 section 2.1
 */
SBuf
AnyP::Uri::Encode(const SBuf &buf, const CharacterSet &ignore)
{
    if (buf.isEmpty())
        return buf;

    Parser::Tokenizer tk(buf);
    SBuf goodSection;
    // optimization for the arguably common "no encoding necessary" case
    if (tk.prefix(goodSection, ignore) && tk.atEnd())
        return buf;

    SBuf output;
    output.reserveSpace(buf.length() * 3); // worst case: encode all chars
    output.append(goodSection); // may be empty

    while (!tk.atEnd()) {
        // TODO: Add Tokenizer::parseOne(void).
        const auto ch = tk.remaining()[0];
        output.appendf("%%%02X", static_cast<unsigned int>(static_cast<unsigned char>(ch))); // TODO: Optimize using a table
        (void)tk.skip(ch);

        if (tk.prefix(goodSection, ignore))
            output.append(goodSection);
    }

    return output;
}

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
    hostAddr_.fromHost(src);
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

SBuf
AnyP::Uri::hostOrIp() const
{
    if (hostIsNumeric()) {
        static char ip[MAX_IPSTRLEN];
        const auto hostStrLen = hostIP().toHostStr(ip, sizeof(ip));
        return SBuf(ip, hostStrLen);
    } else
        return SBuf(host());
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

    assert(0 != matchDomainName("foo.com", ""));
    assert(0 != matchDomainName("foo.com", "", mdnHonorWildcards));
    assert(0 != matchDomainName("foo.com", "", mdnRejectSubsubDomains));

    /* more cases? */
}

/**
 * Extract the URI scheme and ':' delimiter from the given input buffer.
 *
 * Schemes up to 16 characters are accepted.
 *
 * Governed by RFC 3986 section 3.1
 */
static AnyP::UriScheme
uriParseScheme(Parser::Tokenizer &tok)
{
    /*
     * RFC 3986 section 3.1 paragraph 2:
     *
     * Scheme names consist of a sequence of characters beginning with a
     * letter and followed by any combination of letters, digits, plus
     * ("+"), period ("."), or hyphen ("-").
     *
     * The underscore ("_") required to match "cache_object://" squid
     * special URI scheme.
     */
    static const auto schemeChars =
#if USE_HTTP_VIOLATIONS
        CharacterSet("special", "_") +
#endif
        CharacterSet("scheme", "+.-") + CharacterSet::ALPHA + CharacterSet::DIGIT;

    SBuf str;
    if (tok.prefix(str, schemeChars, 16) && tok.skip(':') && CharacterSet::ALPHA[str.at(0)]) {
        const auto protocol = AnyP::UriScheme::FindProtocolType(str);
        if (protocol == AnyP::PROTO_UNKNOWN)
            return AnyP::UriScheme(protocol, str.c_str());
        return AnyP::UriScheme(protocol, nullptr);
    }

    throw TextException("invalid URI scheme", Here());
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
 * It is assumed that the URL is complete -
 * ie, the end of the string is the end of the URL. Don't pass a partial
 * URL here as this routine doesn't have any way of knowing whether
 * it is partial or not (ie, it handles the case of no trailing slash as
 * being "end of host with implied path of /".
 *
 * method is used to switch parsers. If method is Http::METHOD_CONNECT,
 * then rather than a URL a hostname:port is looked for.
 */
bool
AnyP::Uri::parse(const HttpRequestMethod& method, const SBuf &rawUrl)
{
    try {

        LOCAL_ARRAY(char, login, MAX_URL);
        LOCAL_ARRAY(char, foundHost, MAX_URL);
        LOCAL_ARRAY(char, urlpath, MAX_URL);
        char *t = nullptr;
        char *q = nullptr;
        int foundPort;
        int l;
        int i;
        const char *src;
        char *dst;
        foundHost[0] = urlpath[0] = login[0] = '\0';

        if ((l = rawUrl.length()) + Config.appendDomainLen > (MAX_URL - 1)) {
            debugs(23, DBG_IMPORTANT, MYNAME << "URL too large (" << l << " bytes)");
            return false;
        }

        if ((method == Http::METHOD_OPTIONS || method == Http::METHOD_TRACE) &&
                Asterisk().cmp(rawUrl) == 0) {
            // XXX: these methods might also occur in HTTPS traffic. Handle this better.
            setScheme(AnyP::PROTO_HTTP, nullptr);
            port(getScheme().defaultPort());
            path(Asterisk());
            return true;
        }

        Parser::Tokenizer tok(rawUrl);
        AnyP::UriScheme scheme;

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

            // XXX: use tokenizer
            auto B = tok.buf();
            const char *url = B.c_str();

            if (sscanf(url, "[%[^]]]:%d", foundHost, &foundPort) < 1)
                if (sscanf(url, "%[^:]:%d", foundHost, &foundPort) < 1)
                    return false;

        } else {

            scheme = uriParseScheme(tok);

            if (scheme == AnyP::PROTO_NONE)
                return false; // invalid scheme

            if (scheme == AnyP::PROTO_URN) {
                parseUrn(tok); // throws on any error
                return true;
            }

            // URLs then have "//"
            static const SBuf doubleSlash("//");
            if (!tok.skip(doubleSlash))
                return false;

            auto B = tok.remaining();
            const char *url = B.c_str();

            /* Parse the URL: */
            src = url;
            i = 0;

            /* Then everything until first /; that's host (and port; which we'll look for here later) */
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

            // We are looking at path-abempty.
            if (*src != '/') {
                // path-empty, including the end of the `src` c-string cases
                urlpath[0] = '/';
                dst = &urlpath[1];
            } else {
                dst = urlpath;
            }
            /* Then everything from / (inclusive) until \r\n or \0 - that's urlpath */
            for (; i < l && *src != '\r' && *src != '\n' && *src != '\0'; ++i, ++src, ++dst) {
                *dst = *src;
            }

            /* We -could- be at the end of the buffer here */
            if (i > l)
                return false;
            *dst = '\0';

            foundPort = scheme.defaultPort(); // may be reset later

            /* Is there any login information? (we should eventually parse it above) */
            t = strrchr(foundHost, '@');
            if (t != nullptr) {
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
                    t = nullptr;
                }
            }

            // Bug 3183 sanity check: If scheme is present, host must be too.
            if (scheme != AnyP::PROTO_NONE && foundHost[0] == '\0') {
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

        debugs(23, 3, "Split URL '" << rawUrl << "' into proto='" << scheme.image() << "', host='" << foundHost << "', port='" << foundPort << "', path='" << urlpath << "'");

        if (Config.onoff.check_hostnames &&
                strspn(foundHost, Config.onoff.allow_underscore ? valid_hostname_chars_u : valid_hostname_chars) != strlen(foundHost)) {
            debugs(23, DBG_IMPORTANT, MYNAME << "Illegal character in hostname '" << foundHost << "'");
            return false;
        }

        if (!urlAppendDomain(foundHost))
            return false;

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

        if (stringHasWhitespace(urlpath)) {
            debugs(23, 2, "URI has whitespace: {" << rawUrl << "}");

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

        setScheme(scheme);
        path(urlpath);
        host(foundHost);
        userInfo(SBuf(login));
        port(foundPort);
        return true;

    } catch (...) {
        debugs(23, 2, "error: " << CurrentException << " " << Raw("rawUrl", rawUrl.rawContent(), rawUrl.length()));
        return false;
    }
}

/**
 * Governed by RFC 8141 section 2:
 *
 *  assigned-name = "urn" ":" NID ":" NSS
 *  NID           = (alphanum) 0*30(ldh) (alphanum)
 *  ldh           = alphanum / "-"
 *  NSS           = pchar *(pchar / "/")
 *
 * RFC 3986 Appendix D.2 defines (as deprecated):
 *
 *   alphanum     = ALPHA / DIGIT
 *
 * Notice that NID is exactly 2-32 characters in length.
 */
void
AnyP::Uri::parseUrn(Parser::Tokenizer &tok)
{
    static const auto nidChars = CharacterSet("NID","-") + CharacterSet::ALPHA + CharacterSet::DIGIT;
    static const auto alphanum = (CharacterSet::ALPHA + CharacterSet::DIGIT).rename("alphanum");
    SBuf nid;
    if (!tok.prefix(nid, nidChars, 32))
        throw TextException("NID not found", Here());

    if (!tok.skip(':'))
        throw TextException("NID too long or missing ':' delimiter", Here());

    if (nid.length() < 2)
        throw TextException("NID too short", Here());

    if (!alphanum[*nid.begin()])
        throw TextException("NID prefix is not alphanumeric", Here());

    if (!alphanum[*nid.rbegin()])
        throw TextException("NID suffix is not alphanumeric", Here());

    setScheme(AnyP::PROTO_URN, nullptr);
    host(nid.c_str());
    // TODO validate path characters
    path(tok.remaining());
    debugs(23, 3, "Split URI into proto=urn, nid=" << nid << ", " << Raw("path",path().rawContent(),path().length()));
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
            const bool allowUserInfo = getScheme() == AnyP::PROTO_FTP ||
                                       getScheme() == AnyP::PROTO_UNKNOWN;

            if (allowUserInfo && !userInfo().isEmpty()) {
                static const CharacterSet uiChars = CharacterSet(UserInfoChars())
                                                    .remove('%')
                                                    .rename("userinfo-reserved");
                absolute_.append(Encode(userInfo(), uiChars));
                absolute_.append("@", 1);
            }
            absolute_.append(authority());
        } else {
            absolute_.append(host());
            absolute_.append(":", 1);
        }
        absolute_.append(path()); // TODO: Encode each URI subcomponent in path_ as needed.
    }

    return absolute_;
}

/* XXX: Performance: This is an *almost* duplicate of HttpRequest::effectiveRequestUri(). But elides the query-string.
 *        After copying it on in the first place! Would be less code to merge the two with a flag parameter.
 *        and never copy the query-string part in the first place
 */
char *
urlCanonicalCleanWithoutRequest(const SBuf &url, const HttpRequestMethod &method, const AnyP::UriScheme &scheme)
{
    LOCAL_ARRAY(char, buf, MAX_URL);

    snprintf(buf, sizeof(buf), SQUIDSBUFPH, SQUIDSBUFPRINT(url));
    buf[sizeof(buf)-1] = '\0';

    // URN, CONNECT method, and non-stripped URIs can go straight out
    if (Config.onoff.strip_query_terms && !(method == Http::METHOD_CONNECT || scheme == AnyP::PROTO_URN)) {
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
    return request->canonicalCleanUrl();
}

/**
 * Test if a URL is a relative reference.
 *
 * Governed by RFC 3986 section 4.2
 *
 *  relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
 *
 *  relative-part = "//" authority path-abempty
 *                / path-absolute
 *                / path-noscheme
 *                / path-empty
 */
bool
urlIsRelative(const char *url)
{
    if (!url)
        return false; // no URL

    /*
     * RFC 3986 section 5.2.3
     *
     * path          = path-abempty    ; begins with "/" or is empty
     *               / path-absolute   ; begins with "/" but not "//"
     *               / path-noscheme   ; begins with a non-colon segment
     *               / path-rootless   ; begins with a segment
     *               / path-empty      ; zero characters
     */

    if (*url == '\0')
        return true; // path-empty

    if (*url == '/') {
        // RFC 3986 section 5.2.3
        // path-absolute   ; begins with "/" but not "//"
        if (url[1] == '/')
            return true; // network-path reference, aka. 'scheme-relative URI'
        else
            return true; // path-absolute, aka 'absolute-path reference'
    }

    for (const auto *p = url; *p != '\0' && *p != '/' && *p != '?' && *p != '#'; ++p) {
        if (*p == ':')
            return false; // colon is forbidden in first segment
    }

    return true; // path-noscheme, path-abempty, path-rootless
}

void
AnyP::Uri::addRelativePath(const char *relUrl)
{
    // URN cannot be merged
    if (getScheme() == AnyP::PROTO_URN)
        return;

    // TODO: Handle . and .. segment normalization

    const auto lastSlashPos = path_.rfind('/');
    // TODO: To optimize and simplify, add and use SBuf::replace().
    const auto relUrlLength = strlen(relUrl);
    if (lastSlashPos == SBuf::npos) {
        // start replacing the whole path
        path_.reserveCapacity(1 + relUrlLength);
        path_.assign("/", 1);
    } else {
        // start replacing just the last segment
        path_.reserveCapacity(lastSlashPos + 1 + relUrlLength);
        path_.chop(0, lastSlashPos+1);
    }
    path_.append(relUrl, relUrlLength);
}

int
matchDomainName(const char *h, const char *d, MatchDomainNameFlags flags)
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
    if (dl == 0)
        return 1;

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
bool
urlCheckRequest(const HttpRequest * r)
{
    /* protocol "independent" methods
     *
     * actually these methods are specific to HTTP:
     * they are methods we receive on our HTTP port,
     * and if we had a FTP listener would not be relevant
     * there.
     *
     * So, we should delegate them to HTTP. The problem is that we
     * do not have a default protocol from the client side of HTTP.
     */

    if (r->method == Http::METHOD_CONNECT)
        return true;

    // we support OPTIONS and TRACE directed at us (with a 501 reply, for now)
    // we also support forwarding OPTIONS and TRACE, except for the *-URI ones
    if (r->method == Http::METHOD_OPTIONS || r->method == Http::METHOD_TRACE)
        return (r->header.getInt64(Http::HdrType::MAX_FORWARDS) == 0 || r->url.path() != AnyP::Uri::Asterisk());

    if (r->method == Http::METHOD_PURGE)
        return true;

    /* does method match the protocol? */
    switch (r->url.getScheme()) {

    case AnyP::PROTO_URN:
    case AnyP::PROTO_HTTP:
    case AnyP::PROTO_CACHE_OBJECT:
        return true;

    case AnyP::PROTO_FTP:
        if (r->method == Http::METHOD_PUT ||
                r->method == Http::METHOD_GET ||
                r->method == Http::METHOD_HEAD )
            return true;
        return false;

    case AnyP::PROTO_WAIS:
    case AnyP::PROTO_WHOIS:
        if (r->method == Http::METHOD_GET ||
                r->method == Http::METHOD_HEAD)
            return true;
        return false;

    case AnyP::PROTO_HTTPS:
#if USE_OPENSSL || USE_GNUTLS
        return true;
#else
        /*
         * Squid can't originate an SSL connection, so it should
         * never receive an "https:" URL.  It should always be
         * CONNECT instead.
         */
        return false;
#endif

    default:
        return false;
    }

    /* notreached */
    return false;
}

AnyP::Uri::Uri(AnyP::UriScheme const &aScheme) :
    scheme_(aScheme),
    hostIsNumeric_(false),
    port_(0)
{
    *host_=0;
}

// TODO: fix code duplication with AnyP::Uri::parse()
char *
AnyP::Uri::cleanup(const char *uri)
{
    char *cleanedUri = nullptr;
    switch (Config.uri_whitespace) {
    case URI_WHITESPACE_ALLOW: {
        const auto flags = RFC1738_ESCAPE_NOSPACE | RFC1738_ESCAPE_UNESCAPED;
        cleanedUri = xstrndup(rfc1738_do_escape(uri, flags), MAX_URL);
        break;
    }

    case URI_WHITESPACE_ENCODE:
        cleanedUri = xstrndup(rfc1738_do_escape(uri, RFC1738_ESCAPE_UNESCAPED), MAX_URL);
        break;

    case URI_WHITESPACE_CHOP: {
        const auto pos = strcspn(uri, w_space);
        char *choppedUri = nullptr;
        if (pos < strlen(uri))
            choppedUri = xstrndup(uri, pos + 1);
        cleanedUri = xstrndup(rfc1738_do_escape(choppedUri ? choppedUri : uri,
                                                RFC1738_ESCAPE_UNESCAPED), MAX_URL);
        cleanedUri[pos] = '\0';
        xfree(choppedUri);
        break;
    }

    case URI_WHITESPACE_DENY:
    case URI_WHITESPACE_STRIP:
    default: {
        // TODO: avoid duplication with urlParse()
        const char *t;
        char *tmp_uri = static_cast<char*>(xmalloc(strlen(uri) + 1));
        char *q = tmp_uri;
        t = uri;
        while (*t) {
            if (!xisspace(*t)) {
                *q = *t;
                ++q;
            }
            ++t;
        }
        *q = '\0';
        cleanedUri = xstrndup(rfc1738_escape_unescaped(tmp_uri), MAX_URL);
        xfree(tmp_uri);
        break;
    }
    }

    assert(cleanedUri);
    return cleanedUri;
}

