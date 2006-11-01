
/*
 * $Id: ICAPClientVector.h,v 1.1 2006/10/31 23:30:58 wessels Exp $
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

#ifndef SQUID_ICAPVECTOR_H
#define SQUID_ICAPVECTOR_H

#include "MsgPipe.h"
#include "MsgPipeSource.h"
#include "MsgPipeSink.h"
#include "ICAPServiceRep.h"

/*
 * The ICAP Vector helps its Owner to talk to the ICAP transaction, which
 * implements asynchronous communication with the ICAP server. The Owner
 * is either the HTTP client side (ClientHttpRequest) or the HTTP server
 * side (ServerStateData). The Vector marshals the incoming/virgin HTTP
 * message to the ICAP transaction, via the MsgPipe interface. The same
 * interface is used to get the adapted HTTP message back.
 *
 * ICAPClientReqmodPrecache and ICAPClientRespmodPrecache classes use
 * ICAPVector as a base and cover specifics of their vectoring point.
 */

class ICAPClientVector: public MsgPipeSource, public MsgPipeSink
{

public:
    ICAPClientVector(ICAPServiceRep::Pointer, const char *aPoint);
    virtual ~ICAPClientVector();

    // synchronous calls called by Owner
    void sendMoreData(StoreIOBuffer buf);
    void doneSending();
    void ownerAbort();
    int potentialSpaceSize();	/* how much data can we accept? */

    // pipe source methods; called by ICAP while receiving the virgin message
    virtual void noteSinkNeed(MsgPipe *p);
    virtual void noteSinkAbort(MsgPipe *p);

    // pipe sink methods; called by ICAP while sending the adapted message
    virtual void noteSourceStart(MsgPipe *p) = 0;
    virtual void noteSourceProgress(MsgPipe *p) = 0;
    virtual void noteSourceFinish(MsgPipe *p);
    virtual void noteSourceAbort(MsgPipe *p);

protected:
    typedef enum { notifyNone, notifyOwner, notifyIcap } Notify;

    // implemented by kids because we do not have a common Owner parent
    virtual void tellSpaceAvailable() = 0;
    virtual void tellDoneAdapting() = 0; // may delete us
    virtual void tellAbortAdapting() = 0; // may delete us
    virtual void stop(Notify notify); // may delete us

    void startMod(void *anOwner, HttpRequest *cause, HttpMsg *header);
    void clean(Notify notify, bool cleanAdapted = true);

private:
    void checkDoneAdapting();

public:
    void *theOwner;
    const char *vPoint; // unmanaged vectoring point name for debugging

    ICAPServiceRep::Pointer service;
    MsgPipe::Pointer virgin;
    MsgPipe::Pointer adapted;
};

#endif /* SQUID_ICAPVECTOR_H */
