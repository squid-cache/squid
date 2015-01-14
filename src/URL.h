/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_URL_H
#define SQUID_SRC_URL_H

#include "anyp/UriScheme.h"
#include "SBuf.h"

/**
 * The URL class represents a Uniform Resource Location
 */
class URL
{
    MEMPROXY_CLASS(URL);

public:
    URL() : scheme_() {}
    URL(AnyP::UriScheme const &aScheme) : scheme_(aScheme) {}

    void clear() {
        scheme_=AnyP::PROTO_NONE;
    }

    AnyP::UriScheme const & getScheme() const {return scheme_;}

    /// convert the URL scheme to that given
    void setScheme(const AnyP::ProtocolType &p) {scheme_=p;}

    void userInfo(const SBuf &s) {userInfo_=s;}
    const SBuf &userInfo() const {return userInfo_;}

    /// the static '*' pseudo-URL
    static const SBuf &Asterisk();

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

    SBuf userInfo_; // aka 'URL-login'
};

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
int matchDomainName(const char *host, const char *domain);
int urlCheckRequest(const HttpRequest *);
int urlDefaultPort(AnyP::ProtocolType p);
char *urlHostname(const char *url);
void urlExtMethodConfigure(void);

#endif /* SQUID_SRC_URL_H_H */

