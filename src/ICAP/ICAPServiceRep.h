
/*
 * $Id: ICAPServiceRep.h,v 1.1 2005/11/21 23:32:59 wessels Exp $
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
 *  sinks; see the CREDITS file for full details.
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

#ifndef SQUID_ICAPSERVICEREP_H
#define SQUID_ICAPSERVICEREP_H

#include "ICAPElements.h"

class ICAPOptions;

class ICAPOptXact;

/* The ICAP service representative maintains information about a single ICAP
   service that Squid communicates with. The representative initiates OPTIONS
   requests to the service to keep cached options fresh. One ICAP server may
   host many ICAP services */

class ICAPServiceRep : public RefCountable
{

public:
    typedef RefCount<ICAPServiceRep> Pointer;

public:
    ICAPServiceRep();
    virtual ~ICAPServiceRep();

    bool configure(Pointer &aSelf); // needs self pointer for ICAPOptXact
    void invalidate(); // call when the service is no longer needed or valid

    const char *methodStr() const;
    const char *vectPointStr() const;

    bool up() const;

    /* Service is "up" iff there is a fresh cached OPTIONS response. To
       get an OPTIONS response, ICAPServiceRep does an OPTIONS
       transaction.  Failed transaction results in a "down" service. The
       Callback is called if/once the service is in a steady ("up" or
       "down") state. */
    typedef void Callback(void *data, Pointer &service);
    void callWhenReady(Callback *cb, void *data);


    // the methods below can only be called on an up() service

    bool wantsPreview(size_t &wantedSize) const;
    bool allows204() const;

public:
    String key;
    ICAP::Method method;
    ICAP::VectPoint point;
    String uri;    // service URI

    // URI components
    String host;
    int port;
    String resource;

    // non-options flags; TODO: check that both are used.
    bool bypass;
    bool unreachable;

public: // treat these as private, they are for callbacks only
    void noteTimeToUpdate();
    void noteTimeToNotify();
    void noteNewOptions(ICAPOptXact *x);

private:
    // stores Prepare() callback info

    struct Client
    {
        Pointer service; // one for each client to preserve service
        Callback *callback;
        void *data;
    };

    typedef Vector<Client> Clients;
    Clients theClients; // all clients waiting for a call back

    ICAPOptions *theOptions;

    typedef enum { stateInit, stateWait, stateUp, stateDown } State;
    State theState;
    bool notifying; // may be true in any state except for the initial

private:
    ICAP::Method parseMethod(const char *) const;
    ICAP::VectPoint parseVectPoint(const char *) const;

    bool waiting() const;
    bool needNewOptions() const;

    void scheduleNotification();
    void changeOptions(ICAPOptions *newOptions);
    void startGettingOptions();
    void scheduleUpdate();

    const char *status() const;

    Pointer self;
    CBDATA_CLASS2(ICAPServiceRep);
};


#endif /* SQUID_ICAPSERVICEREP_H */
