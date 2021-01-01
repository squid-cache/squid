/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ANYP_URI_H
#define SQUID_SRC_ANYP_URI_H

#include "anyp/UriScheme.h"
#include "ip/Address.h"
#include "parser/Tokenizer.h"
#include "rfc2181.h"
#include "sbuf/SBuf.h"

#include <iosfwd>

class HttpRequestMethod;

namespace AnyP
{

/**
 * Represents a Uniform Resource Identifier.
 * Can store both URL or URN representations.
 *
 * Governed by RFC 3986
 */
class Uri
{
    MEMPROXY_CLASS(Uri);

public:
    Uri() : hostIsNumeric_(false), port_(0) {*host_=0;}
    Uri(AnyP::UriScheme const &aScheme);
    Uri(const Uri &other) {
        this->operator =(other);
    }
    Uri &operator =(const Uri &o) {
        scheme_ = o.scheme_;
        userInfo_ = o.userInfo_;
        memcpy(host_, o.host_, sizeof(host_));
        hostIsNumeric_ = o.hostIsNumeric_;
        hostAddr_ = o.hostAddr_;
        port_ = o.port_;
        path_ = o.path_;
        touch();
        return *this;
    }

    void clear() {
        scheme_=AnyP::PROTO_NONE;
        hostIsNumeric_ = false;
        *host_ = 0;
        hostAddr_.setEmpty();
        port_ = 0;
        touch();
    }
    void touch(); ///< clear the cached URI display forms

    bool parse(const HttpRequestMethod &, const SBuf &url);

    /// \return a new URI that honors uri_whitespace
    static char *cleanup(const char *uri);

    AnyP::UriScheme const & getScheme() const {return scheme_;}

    /// convert the URL scheme to that given
    void setScheme(const AnyP::ProtocolType &p, const char *str) {
        scheme_ = AnyP::UriScheme(p, str);
        touch();
    }
    void setScheme(const AnyP::UriScheme &s) {
        scheme_ = s;
        touch();
    }

    void userInfo(const SBuf &s) {userInfo_=s; touch();}
    /// \returns raw userinfo subcomponent (or an empty string)
    /// the caller is responsible for caller-specific encoding
    const SBuf &userInfo() const {return userInfo_;}

    void host(const char *src);
    const char *host(void) const {return host_;}
    int hostIsNumeric(void) const {return hostIsNumeric_;}
    Ip::Address const & hostIP(void) const {return hostAddr_;}

    /// \returns the host subcomponent of the authority component
    /// If the host is an IPv6 address, returns that IP address without
    /// [brackets]! See RFC 3986 Section 3.2.2.
    SBuf hostOrIp() const;

    void port(unsigned short p) {port_=p; touch();}
    unsigned short port() const {return port_;}

    void path(const char *p) {path_=p; touch();}
    void path(const SBuf &p) {path_=p; touch();}
    const SBuf &path() const;

    /**
     * Merge a relative-path URL into the existing URI details.
     * Implements RFC 3986 section 5.2.3
     *
     * The caller must ensure relUrl is a valid relative-path.
     *
     * NP: absolute-path are also accepted, but path() method
     * should be used instead when possible.
     */
    void addRelativePath(const char *relUrl);

    /// the static '/' default URL-path
    static const SBuf &SlashPath();

    /// the static '*' pseudo-URI
    static const SBuf &Asterisk();

    /// %-encode characters in a buffer which do not conform to
    /// the provided set of expected characters.
    static SBuf Encode(const SBuf &, const CharacterSet &expected);

    /**
     * The authority-form URI for currently stored values.
     *
     * As defined by RFC 7230 section 5.3.3 this form omits the
     * userinfo@ field from RFC 3986 defined authority segment.
     *
     * \param requirePort when true the port will be included, otherwise
     *                    port will be elided when it is the default for
     *                    the current scheme.
     */
    SBuf &authority(bool requirePort = false) const;

    /**
     * The absolute-form URI for currently stored values.
     *
     * As defined by RFC 7230 section 5.3.3 this form omits the
     * userinfo@ field from RFC 3986 defined authority segments
     * when the protocol scheme is http: or https:.
     */
    SBuf &absolute() const;

private:
    void parseUrn(Parser::Tokenizer&);

    /**
     \par
     * The scheme of this URL. This has the 'type code' smell about it.
     * In future we may want to make the methods that dispatch based on
     * the scheme virtual and have a class per protocol.
     \par
     * On the other hand, having Protocol as an explicit concept is useful,
     * see for instance the ACLProtocol acl type. One way to represent this
     * is to have one prototype URL with no host etc for each scheme,
     * another is to have an explicit scheme class, and then each URL class
     * could be a subclass of the scheme. Another way is one instance of
     * a AnyP::UriScheme class instance for each URL scheme we support, and one
     * class for each manner of treating the scheme : a Hierarchical URL, a
     * non-hierarchical URL etc.
     \par
     * Deferring the decision, its a type code for now. RBC 20060507.
     \par
     * In order to make taking any of these routes easy, scheme is private,
     * only settable at construction time, or with explicit setter
     */
    AnyP::UriScheme scheme_;

    SBuf userInfo_; // aka 'URL-login'

    // XXX: uses char[] instead of SBUf to reduce performance regressions
    //      from c_str() since most code using this is not yet using SBuf
    char host_[SQUIDHOSTNAMELEN];   ///< string representation of the URI authority name or IP
    bool hostIsNumeric_;            ///< whether the authority 'host' is a raw-IP
    Ip::Address hostAddr_;          ///< binary representation of the URI authority if it is a raw-IP

    unsigned short port_;   ///< URL port

    // XXX: for now includes query-string.
    SBuf path_;     ///< URI path segment

    // pre-assembled URI forms
    mutable SBuf authorityHttp_;     ///< RFC 7230 section 5.3.3 authority, maybe without default-port
    mutable SBuf authorityWithPort_; ///< RFC 7230 section 5.3.3 authority with explicit port
    mutable SBuf absolute_;          ///< RFC 7230 section 5.3.2 absolute-URI
};

} // namespace AnyP

inline std::ostream &
operator <<(std::ostream &os, const AnyP::Uri &url)
{
    // none means explicit empty string for scheme.
    if (url.getScheme() != AnyP::PROTO_NONE)
        os << url.getScheme().image();
    os << ":";

    // no authority section on URN
    if (url.getScheme() != AnyP::PROTO_URN)
        os << "//" << url.authority();

    // path is what it is - including absent
    os << url.path();
    return os;
}

/* Deprecated functions for Legacy code handling URLs */

class HttpRequest;

void urlInitialize(void);
/// call HttpRequest::canonicalCleanUrl() instead if you have HttpRequest
/// \returns a pointer to a local static buffer containing request URI
/// that honors strip_query_terms and %-encodes unsafe URI characters
char *urlCanonicalCleanWithoutRequest(const SBuf &url, const HttpRequestMethod &, const AnyP::UriScheme &);
const char *urlCanonicalFakeHttps(const HttpRequest * request);
bool urlIsRelative(const char *);
char *urlRInternal(const char *host, unsigned short port, const char *dir, const char *name);
char *urlInternal(const char *dir, const char *name);
bool urlAppendDomain(char *host); ///< apply append_domain config to the given hostname

enum MatchDomainNameFlags {
    mdnNone = 0,
    mdnHonorWildcards = 1 << 0,
    mdnRejectSubsubDomains = 1 << 1
};

/**
 * matchDomainName() matches a hostname (usually extracted from traffic)
 * with a domainname when mdnNone or mdnRejectSubsubDomains flags are used
 * according to the following rules:
 *
 *    HOST      |   DOMAIN    |   mdnNone | mdnRejectSubsubDomains
 * -------------|-------------|-----------|-----------------------
 *      foo.com |   foo.com   |     YES   |   YES
 *     .foo.com |   foo.com   |     YES   |   YES
 *    x.foo.com |   foo.com   |     NO    |   NO
 *      foo.com |  .foo.com   |     YES   |   YES
 *     .foo.com |  .foo.com   |     YES   |   YES
 *    x.foo.com |  .foo.com   |     YES   |   YES
 *   .x.foo.com |  .foo.com   |     YES   |   NO
 *  y.x.foo.com |  .foo.com   |     YES   |   NO
 *
 * if mdnHonorWildcards flag is set then the matchDomainName() also accepts
 * optional wildcards on hostname:
 *
 *    HOST      |    DOMAIN    |  MATCH?
 * -------------|--------------|-------
 *    *.foo.com |   x.foo.com  |   YES
 *    *.foo.com |  .x.foo.com  |   YES
 *    *.foo.com |    .foo.com  |   YES
 *    *.foo.com |     foo.com  |   NO
 *
 * The combination of mdnHonorWildcards and mdnRejectSubsubDomains flags is
 * supported.
 *
 * \retval 0 means the host matches the domain
 * \retval 1 means the host is greater than the domain
 * \retval -1 means the host is less than the domain
 */
int matchDomainName(const char *host, const char *domain, uint8_t flags = mdnNone);
int urlCheckRequest(const HttpRequest *);
void urlExtMethodConfigure(void);

#endif /* SQUID_SRC_ANYP_URI_H */

