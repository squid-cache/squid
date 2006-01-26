/*
 * $Id: Server.cc,v 1.2 2006/01/25 19:26:14 wessels Exp $
 *
 * DEBUG:
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

#include "squid.h"
#include "Server.h"
#include "Store.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#if ICAP_CLIENT
#include "ICAP/ICAPClientRespmodPrecache.h"
#endif

ServerStateData::ServerStateData(FwdState *theFwdState)
{
    fwd = theFwdState;
    entry = fwd->entry;
    storeLockObject(entry);
    request = requestLink(fwd->request);
}

ServerStateData::~ServerStateData()
{
    storeUnlockObject(entry);

    if (request)
        request->unlock();

    if (reply)
        reply->unlock();

    fwd = NULL; // refcounted

#if ICAP_CLIENT

    if (icap) {
        delete icap;
        cbdataReferenceDone(icap);
    }

#endif
}

#if ICAP_CLIENT
/*
 * Initiate an ICAP transaction.  Return 0 if all is well, or -1 upon error.
 * Caller will handle error condition by generating a Squid error message
 * or take other action.
 */
int
ServerStateData::doIcap(ICAPServiceRep::Pointer service)
{
    debug(11,5)("ServerStateData::doIcap() called\n");
    assert(NULL == icap);
    icap = new ICAPClientRespmodPrecache(service);
    (void) cbdataReference(icap);
    return 0;
}

#endif
