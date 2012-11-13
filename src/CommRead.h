/*
 * DEBUG: section 05    Comm
 * AUTHOR: Robert Collins <robertc@squid-cache.org>
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */
#ifndef COMMREAD_H
#define COMMREAD_H

#include "comm.h"
#include "CommCalls.h"
#include "comm/forward.h"
#include "CbDataList.h"

class CommRead
{

public:
    CommRead();
    CommRead(const Comm::ConnectionPointer &c, char *buf, int len, AsyncCall::Pointer &callback);
    Comm::ConnectionPointer conn;
    char *buf;
    int len;
    AsyncCall::Pointer callback;
};

class DeferredRead
{

public:
    typedef void DeferrableRead(void *context, CommRead const &);
    DeferredRead ();
    DeferredRead (DeferrableRead *, void *, CommRead const &);
    void markCancelled();
    DeferrableRead *theReader;
    void *theContext;
    CommRead theRead;
    bool cancelled;
    AsyncCall::Pointer closer; ///< internal close handler used by Comm

private:
};

class DeferredReadManager
{

public:
    ~DeferredReadManager();
    void delayRead(DeferredRead const &);
    void kickReads(int const count);

private:
    static CLCB CloseHandler;
    static DeferredRead popHead(CbDataListContainer<DeferredRead> &deferredReads);
    void kickARead(DeferredRead const &);
    void flushReads();
    CbDataListContainer<DeferredRead> deferredReads;
};

#endif /* COMMREAD_H */
