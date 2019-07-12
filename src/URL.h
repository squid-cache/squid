/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_URL_H
#define SQUID_SRC_URL_H

#include "anyp/UriScheme.h"
#include "MemPool.h"

/**
 \ingroup POD
 *
 * The URL class represents a Uniform Resource Location
 */
class URL
{
public:
    MEMPROXY_CLASS(URL);
    URL() : scheme_() {}
    URL(AnyP::UriScheme const &aScheme) : scheme_(aScheme) {}

    void clear() {
        scheme_=AnyP::PROTO_NONE;
    }

    AnyP::UriScheme const & getScheme() const {return scheme_;}

    /// convert the URL scheme to that given
    void setScheme(const AnyP::ProtocolType &p) {scheme_=p;}

private:
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
     * a AnyP::UriScheme class instance for each URL scheme we support, and one URL
     * class for each manner of treating the scheme : a Hierarchical URL, a
     * non-hierarchical URL etc.
     \par
     * Deferring the decision, its a type code for now. RBC 20060507.
     \par
     * In order to make taking any of these routes easy, scheme is private
     * and immutable, only settable at construction time,
     */
    AnyP::UriScheme scheme_;
};

MEMPROXY_CLASS_INLINE(URL);

class HttpRequest;
class HttpRequestMethod;

AnyP::ProtocolType urlParseProtocol(const char *, const char *e = NULL);
void urlInitialize(void);
HttpRequest *urlParse(const HttpRequestMethod&, char *, HttpRequest *request = NULL);
const char *urlCanonical(HttpRequest *);
char *urlCanonicalClean(const HttpRequest *);
const char *urlCanonicalFakeHttps(const HttpRequest * request);
bool urlIsRelative(const char *);
char *urlMakeAbsolute(const HttpRequest *, const char *);
char *urlRInternal(const char *host, unsigned short port, const char *dir, const char *name);
char *urlInternal(const char *dir, const char *name);

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
int matchDomainName(const char *host, const char *domain, uint flags = mdnNone);
int urlCheckRequest(const HttpRequest *);
int urlDefaultPort(AnyP::ProtocolType p);
bool urlAppendDomain(char *host);
char *urlHostname(const char *url);
void urlExtMethodConfigure(void);

#endif /* SQUID_SRC_URL_H_H */

