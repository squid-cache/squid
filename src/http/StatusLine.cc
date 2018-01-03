/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 57    HTTP Status-line */

#include "squid.h"
#include "base/Packable.h"
#include "Debug.h"
#include "http/StatusLine.h"

void
Http::StatusLine::init()
{
    set(Http::ProtocolVersion(), Http::scNone, NULL);
}

void
Http::StatusLine::clean()
{
    set(Http::ProtocolVersion(), Http::scInternalServerError, NULL);
}

/* set values */
void
Http::StatusLine::set(const AnyP::ProtocolVersion &newVersion, const Http::StatusCode newStatus, const char *newReason)
{
    protocol = AnyP::PROTO_HTTP;
    version = newVersion;
    status_ = newStatus;
    /* Note: no xstrdup for 'reason', assumes constant 'reasons' */
    reason_ = newReason;
}

const char *
Http::StatusLine::reason() const
{
    return reason_ ? reason_ : Http::StatusCodeString(status());
}

void
Http::StatusLine::packInto(Packable * p) const
{
    assert(p);

    /* local constants */
    /* AYJ: see bug 2469 - RFC2616 confirms stating 'SP characters' plural! */
    static const char *Http1StatusLineFormat = "HTTP/%d.%d %3d %s\r\n";
    static const char *IcyStatusLineFormat = "ICY %3d %s\r\n";

    /* handle ICY protocol status line specially. Pass on the bad format. */
    if (protocol == AnyP::PROTO_ICY) {
        debugs(57, 9, "packing sline " << this << " using " << p << ":");
        debugs(57, 9, "FORMAT=" << IcyStatusLineFormat );
        debugs(57, 9, "ICY " << status() << " " << reason());
        p->appendf(IcyStatusLineFormat, status(), reason());
        return;
    }

    debugs(57, 9, "packing sline " << this << " using " << p << ":");
    debugs(57, 9, "FORMAT=" << Http1StatusLineFormat );
    debugs(57, 9, "HTTP/" << version.major << "." << version.minor << " " << status() << " " << reason());
    p->appendf(Http1StatusLineFormat, version.major, version.minor, status(), reason());
}

/*
 * Parse character string.
 * XXX: Note 'end' currently unused, so NULL-termination assumed.
 */
bool
Http::StatusLine::parse(const String &protoPrefix, const char *start, const char * /*end*/)
{
    status_ = Http::scInvalidHeader;    /* Squid header parsing error */

    // XXX: HttpMsg::parse() has a similar check but is using
    // casesensitive comparison (which is required by HTTP errata?)

    if (protoPrefix.cmp("ICY", 3) == 0) {
        debugs(57, 3, "Invalid HTTP identifier. Detected ICY protocol istead.");
        protocol = AnyP::PROTO_ICY;
        start += protoPrefix.size();
    } else if (protoPrefix.caseCmp(start, protoPrefix.size()) == 0) {

        start += protoPrefix.size();

        if (!xisdigit(*start))
            return false;

        // XXX: HTTPbis have defined this to be single-digit version numbers. no need to sscanf()
        // XXX: furthermore, only HTTP/1 will be using ASCII format digits

        if (sscanf(start, "%d.%d", &version.major, &version.minor) != 2) {
            debugs(57, 7, "Invalid HTTP identifier.");
            return false;
        }
    } else
        return false;

    if (!(start = strchr(start, ' ')))
        return false;

    // XXX: should we be using xstrtoui() or xatoui() ?
    status_ = static_cast<Http::StatusCode>(atoi(++start));

    // XXX check if the given 'reason' is the default status string, if not save to reason_

    /* we ignore 'reason-phrase' */
    /* Should assert start < end ? */
    return true;            /* success */
}

