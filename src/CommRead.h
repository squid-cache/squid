
/*
 * $Id: CommRead.h,v 1.1 2003/03/04 02:57:50 robertc Exp $
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
#include "List.h"

class CommRead
{

public:
    CommRead ();
    CommRead (int fd, char *buf, int len, IOCB *handler, void *data);
    int fd;
    char *buf;
    int len;
    IOCB *handler;
    void *data;
};

class DeferredRead
{

public:
    typedef void DeferrableRead(void *context, CommRead const &);
    void * operator new(size_t);
    void operator delete (void *);
    DeferredRead ();
    DeferredRead (DeferrableRead *, void *, CommRead const &);
    void markCancelled();
    DeferrableRead *theReader;
    void *theContext;
    CommRead theRead;
    bool cancelled;

private:
    CBDATA_CLASS(DeferredRead);
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
