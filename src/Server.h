
/*
 * $Id: Server.h,v 1.2 2006/10/31 23:30:56 wessels Exp $
 *
 * AUTHOR: Duane Wessels
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

/*
 * ServerStateData is a class for common elements of Server-side modules
 * such as http.cc and ftp.cc.  It was invented to make ICAP code simpler.
 */

#ifndef SQUID_SERVER_H
#define SQUID_SERVER_H

#include "StoreIOBuffer.h"
#include "forward.h"

#if ICAP_CLIENT
#include "ICAP/ICAPServiceRep.h"

class ICAPClientRespmodPrecache;

class ICAPAccessCheck;
#endif

class ServerStateData
{

public:
    ServerStateData(FwdState *);
    virtual ~ServerStateData();

#if ICAP_CLIENT
    virtual bool takeAdaptedHeaders(HttpReply *) = 0;
    virtual bool takeAdaptedBody(MemBuf *) = 0;
    virtual void finishAdapting() = 0;
    virtual void abortAdapting() = 0;
    virtual void icapSpaceAvailable() = 0;
    virtual void icapAclCheckDone(ICAPServiceRep::Pointer) = 0;
#endif

public:
    // should be protected
    StoreEntry *entry;
    FwdState::Pointer fwd;
    HttpRequest *request;
    HttpReply *reply;

protected:
#if ICAP_CLIENT

    ICAPClientRespmodPrecache *icap;
    bool icapAccessCheckPending;
    bool startIcap(ICAPServiceRep::Pointer);
#endif

};

#endif /* SQUID_SERVER_H */
