
/*
 * $Id: ICAPLauncher.h,v 1.1 2007/05/08 16:32:11 rousskov Exp $
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

#ifndef SQUID_ICAPLAUNCHER_H
#define SQUID_ICAPLAUNCHER_H

#include "ICAP/ICAPInitiator.h"
#include "ICAP/ICAPInitiate.h"

/*
 * The ICAP Launcher starts an ICAP transaction. If the transaction fails
 * due to what looks like a persistent connection race condition, the launcher
 * starts a new ICAP transaction using a freshly opened connection.
 *
 * ICAPLauncher and one or more ICAP transactions initiated by it form an
 * ICAP "query".
 *
 * An ICAP Initiator deals with the ICAP Launcher and not an individual ICAP
 * transaction because the latter may disappear and be replaced by another
 * transaction.
 *
 * Specific ICAP launchers implement the createXaction() method to create
 * REQMOD, RESPMOD, or OPTIONS transaction from initiator-supplied data.
 *
 * TODO: This class might be the right place to initiate ICAP ACL checks or 
 * implement more sophisticated ICAP transaction handling like chaining of 
 * ICAP transactions.
 */

class ICAPXaction;

// Note: ICAPInitiate must be the first parent for cbdata to work. We use
// a temporary ICAPInitaitorHolder/toCbdata hacks and do not call cbdata
// operations on the initiator directly.
class ICAPLauncher: public ICAPInitiate, public ICAPInitiator
{
public:
    ICAPLauncher(const char *aTypeName, ICAPInitiator *anInitiator, ICAPServiceRep::Pointer &aService);
    virtual ~ICAPLauncher();

    // ICAPInitiate: asynchronous communication with the initiator
    void noteInitiatorAborted();

    // ICAPInitiator: asynchronous communication with the current transaction
    virtual void noteIcapAnswer(HttpMsg *message);
    virtual void noteIcapQueryAbort(bool final);

    // a temporary cbdata-for-multiple inheritance hack, see ICAPInitiator.cc
    virtual void *toCbdata() { return this; }

protected:
    // ICAPInitiate API implementation
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();

    // creates the right ICAP transaction using stored configuration params
    virtual ICAPXaction *createXaction() = 0;

    void launchXaction(bool final);

    ICAPInitiate *theXaction; // current ICAP transaction
    int theLaunches; // the number of transaction launches
};

#endif /* SQUID_ICAPLAUNCHER_H */
