/*
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

#ifndef SQUID_SRC_URL_H
#define SQUID_SRC_URL_H

#include "anyp/ProtocolType.h"
#include "MemPool.h"
#include "URLScheme.h"

/**
 \ingroup POD
 *
 * The URL class represents a Uniform Resource Location
 */
class URL
{

public:

    MEMPROXY_CLASS(URL);
    URL();
    URL(URLScheme const &);
    URLScheme const & getScheme() const {return scheme; }

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
     * a URLScheme class instance for each URLScheme we support, and one URL
     * class for each manner of treating the scheme : a Hierarchical URL, a
     * non-hierarchical URL etc.
     \par
     * Deferring the decision, its a type code for now. RBC 20060507.
     \par
     * In order to make taking any of these routes easy, scheme is private
     * and immutable, only settable at construction time,
     */
    URLScheme const scheme;
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
int matchDomainName(const char *host, const char *domain);
int urlCheckRequest(const HttpRequest *);
int urlDefaultPort(AnyP::ProtocolType p);
char *urlHostname(const char *url);
void urlExtMethodConfigure(void);

#endif /* SQUID_SRC_URL_H_H */
