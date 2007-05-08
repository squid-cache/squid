
/*
 * $Id: ICAPInitiator.h,v 1.2 2007/05/08 16:32:11 rousskov Exp $
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

#ifndef SQUID_ICAPINITIATOR_H
#define SQUID_ICAPINITIATOR_H

/*
 * The ICAP Initiator is an ICAP vectoring point that initates ICAP
 * transactions. This interface exists to allow ICAP transactions to
 * signal their initiators that they have the answer from the ICAP server
 * or that the ICAP query has aborted and there will be no answer. It
 * is also handy for implementing common initiator actions such as starting
 * or aborting an ICAP transaction.
 */

class HttpMsg;
class ICAPInitiate;

class ICAPInitiator
{
public:
    virtual ~ICAPInitiator() {}

    // called when ICAP response headers are successfully interpreted
    virtual void noteIcapAnswer(HttpMsg *message) = 0;

    // called when valid ICAP response headers are no longer expected
    // the final parameter is set to disable bypass or retries
    virtual void noteIcapQueryAbort(bool final) = 0;

    // a temporary cbdata-for-multiple inheritance hack, see ICAPInitiator.cc
    virtual void *toCbdata() { return this; }

protected:
    ICAPInitiate *initiateIcap(ICAPInitiate *x); // locks and returns x

    // done with x (and not calling announceInitiatorAbort)
    void clearIcap(ICAPInitiate *&x); // unlocks x

    // inform the transaction about abnormal termination and clear it
    void announceInitiatorAbort(ICAPInitiate *&x); // unlocks x
};

#endif /* SQUID_ICAPINITIATOR_H */
