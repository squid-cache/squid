
/*
 * $Id: ICAPClientRespmodPrecache.h,v 1.4 2006/10/31 23:30:58 wessels Exp $
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

#ifndef SQUID_ICAPCLIENTRESPMODPRECACHE_H
#define SQUID_ICAPCLIENTRESPMODPRECACHE_H

#include "ICAPClientVector.h"

/*
 * ICAPClientRespmodPrecache implements the server-side pre-cache ICAP
 * vectoring point using ICAPClientVector as a parent.
 * ServerStateData is the Owner of this vectoring point.
 */

class ServerStateData;

class ICAPClientRespmodPrecache: public ICAPClientVector
{

public:
    ICAPClientRespmodPrecache(ICAPServiceRep::Pointer);

    // synchronous calls called by ServerStateData
    void startRespMod(ServerStateData *anServerState, HttpRequest *request, HttpReply *reply);

    // pipe source methods; called by ICAP while receiving the virgin message

    // pipe sink methods; called by ICAP while sending the adapted message
    virtual void noteSourceStart(MsgPipe *p);
    virtual void noteSourceProgress(MsgPipe *p);

protected:
    virtual void tellSpaceAvailable();
    virtual void tellDoneAdapting(); // deletes us
    virtual void tellAbortAdapting(); // deletes us

public:
    ServerStateData *serverState;

private:
    CBDATA_CLASS2(ICAPClientRespmodPrecache);
};

#endif /* SQUID_ICAPCLIENTRESPMODPRECACHE_H */
