
/*
 * $Id: ICAPInitiate.h,v 1.1 2007/05/08 16:32:11 rousskov Exp $
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

#ifndef SQUID_ICAPINITIATE_H
#define SQUID_ICAPINITIATE_H

#include "comm.h"
#include "MemBuf.h"
#include "ICAPServiceRep.h"
#include "AsyncJob.h"

class HttpMsg;
class ICAPInitiator;

/* Initiator holder associtates an initiator with its cbdata. It is used as
 * a temporary hack to make cbdata work with multiple inheritance */
class ICAPInitiatorHolder {
public:
    ICAPInitiatorHolder(ICAPInitiator *anInitiator);
    ICAPInitiatorHolder(const ICAPInitiatorHolder &anInitiator);
    ~ICAPInitiatorHolder();


    void clear();

    // to make comparison with NULL possible
    operator void*() { return ptr; }
    bool operator == (void *) const { return ptr == NULL; }
    bool operator != (void *) const { return ptr != NULL; }
    bool operator !() const { return !ptr; }

    ICAPInitiator *ptr;
    void *cbdata;

private:
    ICAPInitiatorHolder &operator =(const ICAPInitiatorHolder &anInitiator);
};

/*
 * The ICAP Initiate is a common base for ICAP queries or transactions
 * initiated by an ICAPInitiator. This interface exists to allow an ICAP
 * initiator to signal its "initiatees" that it is aborting and no longer
 * expecting an answer. The class is also handy for implementing common
 * initiate actions such as maintaining and notifying the initiator.
 *
 * ICAPInitiate implementations must cbdata-protect themselves.
 *
 * This class could have been named ICAPInitiatee.
 */
class ICAPInitiate: public AsyncJob
{

public:
    ICAPInitiate(const char *aTypeName, ICAPInitiator *anInitiator, ICAPServiceRep::Pointer &aService);
    virtual ~ICAPInitiate();

    // communication with the initiator
    virtual void noteInitiatorAborted() = 0;
    AsyncCallWrapper(93,3, ICAPInitiate, noteInitiatorAborted)

protected:
    ICAPServiceRep &service();

    void sendAnswer(HttpMsg *msg); // send to the initiator
    void tellQueryAborted(bool final); // tell initiator
    void clearInitiator(); // used by noteInitiatorAborted; TODO: make private

    virtual void swanSong(); // internal cleanup

    virtual const char *status() const; // for debugging

    ICAPInitiatorHolder theInitiator;
    ICAPServiceRep::Pointer theService;
};

#endif /* SQUID_ICAPINITIATE_H */
