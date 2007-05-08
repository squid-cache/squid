
/*
 * $Id: AsyncCall.h,v 1.2 2007/05/08 16:15:50 rousskov Exp $
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

#ifndef SQUID_ASYNCCALL_H
#define SQUID_ASYNCCALL_H

//#include "cbdata.h"
#include "event.h"

// A call is asynchronous if the caller proceeds after the call is made,
// and the callee receives the call during the next main loop iteration.
// Asynchronous calls help avoid nasty call-me-when-I-call-you loops
// that humans often have trouble understanding or implementing correctly.

// Asynchronous calls are currently implemented via Squid events. The call
// event stores the pointer to the callback function and cbdata-protected
// callback data. To call a method of an object, the method is wrapped
// in a method-specific, static callback function and the pointer to the
// object is passed to the wrapper. For the method call to be safe, the 
// class must be cbdata-enabled.

// You do not have to use the macros below to make or receive asynchronous
// method calls, but they give you a uniform interface and handy call 
// debugging.

// See AsyncCall.cc for a usage sketch.


// Make an asynchronous object->callName() call.
#define AsyncCall(debugSection, debugLevel, objectPtr, callName) \
    scheduleAsyncCall((debugSection), (debugLevel), __FILE__, __LINE__, \
        (objectPtr), #callName, \
        &(callName ## Wrapper))

// Declare and define a wrapper for an asynchronous call handler method
#define AsyncCallWrapper(debugSection, debugLevel, ClassName, callName) \
static \
void callName ## Wrapper(void *data) { \
    ClassName *objectPtr = static_cast<ClassName*>(data); \
    if (enterAsyncCallWrapper((debugSection), (debugLevel), data, #ClassName, #callName)) { \
        objectPtr->callName(); \
        exitAsyncCallWrapper((debugSection), (debugLevel), data, #ClassName, #callName); \
    } \
}


// Hint: to customize debugging of asynchronous messages in a class, provide
// class method called scheduleAsyncCall, enterAsyncCallWrapper, and/or
// exitAsyncCallWrapper. Class method will take priority over these globals.

extern void scheduleAsyncCall(int debugSection, int debugLevel,
    const char *fileName, int fileLine, void *objectPtr, const char *callName,
    EVH *wrapper, bool cbdataProtected = true);

extern bool enterAsyncCallWrapper(int debugSection, int debugLevel,
    void *objectPtr, const char *className, const char *methodName);

extern void exitAsyncCallWrapper(int debugSection, int debugLevel,
    void *objectPtr, const char *className, const char *methodName);


#endif /* SQUID_ASYNCCALL_H */
