
/*
 * $Id: CommRead.h,v 1.7 2006/08/07 02:28:22 robertc Exp $
 *
 * DEBUG: section 5    Comms
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

#include "config.h"

#ifndef COMMREAD_H
#define COMMREAD_H

#include "squid.h"
#include "comm.h"
#include "List.h"

template<class C>

class CallBack
{

public:
    CallBack() : handler(NULL), data(NULL){}

    CallBack(C *aHandler, void *someData) : handler(aHandler), data (NULL)
    {
        if (someData)
            data = cbdataReference(someData);
    }

    CallBack(CallBack const &old) : handler(old.handler)
    {
        if (old.data)
            data = cbdataReference (old.data);
        else
            data = NULL;
    }

    ~CallBack()
    {
        replaceData (NULL);
    }

    CallBack &operator = (CallBack const & rhs)
    {
        handler = rhs.handler;

        replaceData (rhs.data);

        return *this;
    }

    bool dataValid()
    {
        return cbdataReferenceValid(data);
    }

    bool operator == (CallBack const &rhs) { return handler==rhs.handler && data==rhs.data;}

#if 0
    // twould be nice - RBC 20030307
    C callback;
#endif

    C *handler;
    void *data;

private:
    void replaceData(void *someData)
    {
        void *temp = NULL;

        if (someData)
            temp = cbdataReference(someData);

        if (data)
            cbdataReferenceDone(data);

        data = temp;
    }
};

#if 0
// twould be nice - RBC 20030307
void
CallBack<IOCB>::callback(int fd, char *buf, size_t size , comm_err_t errcode, int xerrno, void *tempData)
{
    assert (tempData == data);
    handler (fd, buf, size , errcode, xerrno, data);
    *this = CallBack();
}

#endif

class CommRead
{

public:
    CommRead ();
    CommRead (int fd, char *buf, int len, IOCB *handler, void *data);
    void queueCallback(size_t retval, comm_err_t errcode, int xerrno);
    bool hasCallback() const;
    void hasCallbackInvariant() const;
    void hasNoCallbackInvariant() const;
    void tryReading();
    void read();
    void initiateActualRead();
    void nullCallback();
    void doCallback(comm_err_t errcode, int xerrno);
    int fd;
    char *buf;
    int len;
    CallBack<IOCB> callback;
    static void ReadTry(int fd, void *data);
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

private:
};

class DeferredReadManager
{

public:
    ~DeferredReadManager();
    void delayRead(DeferredRead const &);
    void kickReads(int const count);

private:
    static PF CloseHandler;
    static DeferredRead popHead(ListContainer<DeferredRead> &deferredReads);
    void kickARead(DeferredRead const &);
    void flushReads();
    ListContainer<DeferredRead> deferredReads;
};


#endif /* COMMREAD_H */
