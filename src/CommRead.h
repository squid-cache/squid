/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Comm */

#ifndef COMMREAD_H
#define COMMREAD_H

#include "CbDataList.h"
#include "comm.h"
#include "comm/forward.h"
#include "CommCalls.h"

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

