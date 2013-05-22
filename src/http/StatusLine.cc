/*
 * DEBUG: section 57    HTTP Status-line
 * AUTHOR: Alex Rousskov
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
#include "Debug.h"
#include "http/StatusLine.h"
#include "Packer.h"

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
Http::StatusLine::set(const Http::ProtocolVersion &newVersion, const Http::StatusCode newStatus, const char *newReason)
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
Http::StatusLine::packInto(Packer * p) const
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
        packerPrintf(p, IcyStatusLineFormat, status(), reason());
        return;
    }

    debugs(57, 9, "packing sline " << this << " using " << p << ":");
    debugs(57, 9, "FORMAT=" << Http1StatusLineFormat );
    debugs(57, 9, "HTTP/" << version.major << "." << version.minor << " " << status() << " " << reason());
    packerPrintf(p, Http1StatusLineFormat, version.major, version.minor, status(), reason());
}

/*
 * Parse character string.
 * XXX: Note 'end' currently unused, so NULL-termination assumed.
 */
bool
Http::StatusLine::parse(const String &protoPrefix, const char *start, const char *end)
{
    status_ = Http::scInvalidHeader;	/* Squid header parsing error */

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
    return true;			/* success */
}
