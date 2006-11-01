/*
 * $Id: Server.cc,v 1.7 2006/10/31 23:30:56 wessels Exp $
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

    entry->lock()

    ;
    request = HTTPMSGLOCK(fwd->request);
}

ServerStateData::~ServerStateData()
{
    entry->unlock();

    HTTPMSGUNLOCK(request);
    HTTPMSGUNLOCK(reply);

    fwd = NULL; // refcounted

#if ICAP_CLIENT
    if (icap) {
        debug(11,5)("ServerStateData destroying icap=%p\n", icap);
        icap->ownerAbort();
        delete icap;
    }
#endif
}

#if ICAP_CLIENT
/*
 * Initiate an ICAP transaction.  Return true on success.
 * Caller will handle error condition by generating a Squid error message
 * or take other action.
 */
bool
ServerStateData::startIcap(ICAPServiceRep::Pointer service)
{
    debug(11,5)("ServerStateData::startIcap() called\n");
    if (!service) {
        debug(11,3)("ServerStateData::startIcap fails: lack of service\n");
        return false;
    }
    if (service->broken()) {
        debug(11,3)("ServerStateData::startIcap fails: broken service\n");
        return false;
    }
    assert(NULL == icap);
    icap = new ICAPClientRespmodPrecache(service);
    return true;
}

#endif
