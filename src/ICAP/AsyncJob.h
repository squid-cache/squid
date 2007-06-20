
/*
 * $Id: AsyncJob.h,v 1.2 2007/06/19 21:00:11 rousskov Exp $
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

#ifndef SQUID_ASYNC_JOB_H
#define SQUID_ASYNC_JOB_H

#include "AsyncCall.h"

/*
 * AsyncJob is an API and a base for a class that implements a stand-alone
 * "job", "task", or "logical processing thread" which receives asynchronous
 * calls.
 *
 * Implementations should wrap each method receiving an asynchronous call in 
 * a pair of macros: AsyncCallEnter and AsyncCallExit. These macros:
 *   - provide call debugging
 *   - trap exceptions and terminate the task if an exception occurs
 *   - ensure that only one asynchronous call is active per object
 * Most of the work is done by AsyncJob class methods. Macros just provide
 * an enter/try/catch/exit framework.
 *
 * Eventually, the macros can and perhaps should be replaced with call/event
 * processing code so that individual job classes do not have to wrap all
 * asynchronous calls.
 */

class TextException;

class AsyncJob
{

public:
    static AsyncJob *AsyncStart(AsyncJob *job); // use this to start jobs

    AsyncJob(const char *aTypeName);
    virtual ~AsyncJob();

    void noteStart(); // calls virtual start
    AsyncCallWrapper(93,3, AsyncJob, noteStart);

protected:
    void mustStop(const char *aReason); // force done() for a reason

    bool done() const; // the job is destroyed in callEnd() when done()

    virtual void start() = 0;
    virtual bool doneAll() const = 0; // return true when done
    virtual void swanSong() = 0; // perform internal cleanup
    virtual const char *status() const = 0; // for debugging

    // asynchronous call maintenance
    bool callStart(const char *methodName);
    virtual void callException(const TextException &e);
    virtual void callEnd();

    const char *stopReason; // reason for forcing done() to be true
    const char *typeName; // kid (leaf) class name, for debugging
    const char *inCall; // name of the asynchronous call being executed, if any
};


// call guards for all "asynchronous" note*() methods
// TODO: Move to core.

// asynchronous call entry:
// - open the try clause;
// - call callStart().
#define AsyncCallEnter(method) \
    try { \
        if (!callStart(#method)) \
            return;

// asynchronous call exit:
// - close the try clause;
// - catch exceptions;
// - let callEnd() handle transaction termination conditions
#define AsyncCallExit() \
    } \
    catch (const TextException &e) { \
        callException(e); \
    } \
    callEnd();


#endif /* SQUID_ASYNC_JOB_H */
