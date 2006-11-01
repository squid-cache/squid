
/*
 * $Id: ICAPClientReqmodPrecache.h,v 1.4 2006/10/31 23:30:58 wessels Exp $
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

#ifndef SQUID_ICAPCLIENTREQMODPRECACHE_H
#define SQUID_ICAPCLIENTREQMODPRECACHE_H

#include "ICAPClientVector.h"

/*
 * ICAPClientReqmodPrecache implements the ICAP client-side pre-cache
 * vectoring point using ICAPClientVector as a parent.
 * ClientHttpRequest is the Owner of this vectoring point.
 */

class ClientRequestContext;

class ICAPClientReqmodPrecache: public ICAPClientVector
{

public:
    ICAPClientReqmodPrecache(ICAPServiceRep::Pointer);

    // synchronous calls called by ClientHttpRequest
    void startReqMod(ClientHttpRequest *, HttpRequest *);

    // pipe source methods; called by ICAP while receiving the virgin message


    // pipe sink methods; called by ICAP while sending the adapted message
    virtual void noteSourceStart(MsgPipe *p);
    virtual void noteSourceProgress(MsgPipe *p);

protected:
    // used by ICAPClientVector because it does not know Owner type
    virtual void tellSpaceAvailable();
    virtual void tellDoneAdapting();
    virtual void tellAbortAdapting();
    virtual void stop(Notify notify);

public:
    ClientHttpRequest *http;
    BodyReader::Pointer body_reader;

private:
    // Hooks to BodyReader so HttpStateData can get the
    // adapted request body
    static BodyReadFunc readBody;
    static BodyAbortFunc abortBody;
    static BodyKickFunc kickBody;

    CBDATA_CLASS2(ICAPClientReqmodPrecache);
};

#endif /* SQUID_ICAPCLIENTSIDEHOOK_H */
