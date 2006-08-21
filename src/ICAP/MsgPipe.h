
/*
 * $Id: MsgPipe.h,v 1.5 2006/08/21 00:50:45 robertc Exp $
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

#ifndef SQUID_MSGPIPE_H
#define SQUID_MSGPIPE_H

#include "cbdata.h"
#include "event.h"

// MsgPipe is a unidirectional communication channel for asynchronously
// transmitting potentially large messages. It aggregates the message
// being piped and pointers to the message sender and recepient.
// MsgPipe also provides convenience wrappers for asynchronous calls to
// recepient's and sender's note*() methods.

class MsgPipeData;

class MsgPipeEnd;

class MsgPipeSource;

class MsgPipeSink;

class MsgPipe : public RefCountable
{

public:
    typedef RefCount<MsgPipe> Pointer;

    MsgPipe(const char *aName = "anonym");
    ~MsgPipe();

    // the pipe source calls these to notify the sink
    void sendSourceStart();
    void sendSourceProgress();
    void sendSourceFinish();
    void sendSourceAbort();

    // the pipe sink calls these to notify the source
    void sendSinkNeed();
    void sendSinkAbort();

    // private method exposed for the event handler only
    bool canSend(MsgPipeEnd *destination, const char *callName, bool future);

public:
    const char *name; // unmanaged pointer used for debugging only

    MsgPipeData *data;
    MsgPipeSource *source;
    MsgPipeSink *sink;

private:
    void sendLater(const char *callName, EVH * handler, MsgPipeEnd *destination);

    CBDATA_CLASS2(MsgPipe);
};

#endif /* SQUID_MSGPIPE_H */
