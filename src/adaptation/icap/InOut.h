
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

#ifndef SQUID_ICAPINOUT_H
#define SQUID_ICAPINOUT_H

#include "HttpMsg.h"
#include "HttpRequest.h"
#include "HttpReply.h"

// IcapInOut manages a pointer to the HTTP message being worked on.
// For HTTP responses, request header information is also available
// as the "cause". ICAP transactions use this class to store virgin
// and adapted HTTP messages.

namespace Adaptation
{
namespace Icap
{

class InOut
{

public:
    typedef HttpMsg Header;

    InOut(): header(0), cause(0) {}

    ~InOut() {
        HTTPMSGUNLOCK(cause);
        HTTPMSGUNLOCK(header);
    }

    void setCause(HttpRequest *r) {
        if (r) {
            HTTPMSGUNLOCK(cause);
            cause = HTTPMSGLOCK(r);
        } else {
            assert(!cause);
        }
    }

    void setHeader(Header *h) {
        HTTPMSGUNLOCK(header);
        header = HTTPMSGLOCK(h);
        body_pipe = header->body_pipe;
    }

public:
    // virgin or adapted message being worked on
    Header *header;   // parsed HTTP status/request line and headers

    // HTTP request header for HTTP responses (the cause of the response)
    HttpRequest *cause;

    // Copy of header->body_pipe, in case somebody moves the original.
    BodyPipe::Pointer body_pipe;
};

// TODO: s/Header/Message/i ?

} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_ICAPINOUT_H */
