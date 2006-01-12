
/*
 * $Id: MsgPipeData.h,v 1.4 2006/01/11 22:40:39 wessels Exp $
 *
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

#ifndef SQUID_MSGPIPEDATA_H
#define SQUID_MSGPIPEDATA_H

#include "HttpMsg.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "MemBuf.h"

// MsgPipeData contains information about the HTTP message being sent
// from the pipe source to the sink. Since the entire message body may be
// large, only partial information about the body is kept. For HTTP
// responses, request header information is also available as metadata.

class HttpRequest;

class MsgPipeData
{

public:
    MsgPipeData(): header(0), body(0), cause(0) {};

    ~MsgPipeData()
    {
        clearCause();
        clearHeader();

        if (body) {
            body->clean();
            delete body;
        }
    };

    void setCause(HttpRequest *r)
    {
        cause = requestLink(r);
    };

    void setHeader(HttpMsg *msg)
    {
        clearHeader();

        if (HttpRequest *req = dynamic_cast<HttpRequest*>(msg))
            header = requestLink(req);
        else if (HttpReply *rep = dynamic_cast<HttpReply*>(msg))
            header = rep;
    };

public:
    typedef HttpMsg Header;
    typedef MemBuf Body;

    // message being piped
    Header *header;   // parsed HTTP status/request line and headers
    Body *body;     // a buffer for decoded HTTP body piping

    // HTTP request header for piped responses (the cause of the response)
    HttpRequest *cause;

private:

    void clearCause()
    {
        requestUnlink(cause);
        cause = NULL;
    };

    void clearHeader()
    {
        if (HttpRequest *req = dynamic_cast<HttpRequest*>(header))
            requestUnlink(req);

        header = NULL;
    };

};

#endif /* SQUID_MSGPIPEDATA_H */
