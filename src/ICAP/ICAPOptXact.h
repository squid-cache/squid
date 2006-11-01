/*
 * $Id: ICAPOptXact.h,v 1.4 2006/10/31 23:30:58 wessels Exp $
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

#ifndef SQUID_ICAPOPTXACT_H
#define SQUID_ICAPOPTXACT_H

#include "ICAPXaction.h"

class ICAPOptions;

/* ICAPOptXact sends an ICAP OPTIONS request to the ICAP service,
 * converts the response into ICAPOptions object, and notifies
 * the caller via the callback. NULL options objects means the
 * ICAP service could not be contacted or did not return any response */

class ICAPOptXact: public ICAPXaction
{

public:
    typedef void Callback(ICAPOptXact*, void *data);

    ICAPOptXact();
    virtual ~ICAPOptXact();

    void start(ICAPServiceRep::Pointer &aService, Callback *aCb, void *aCbData);

    ICAPOptions *options; // result for the caller to take/handle

protected:
    virtual void handleCommConnected();
    virtual void handleCommWrote(size_t size);
    virtual void handleCommRead(size_t size);
    virtual bool doneAll() const;

    void makeRequest(MemBuf &buf);
    bool parseResponse();

    void startReading();

    virtual void doStop();

private:
    Callback *cb;
    void *cbData;

    CBDATA_CLASS2(ICAPOptXact);
};

#endif /* SQUID_ICAPOPTXACT_H */
