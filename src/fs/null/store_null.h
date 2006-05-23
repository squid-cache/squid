
/*
 * $Id: store_null.h,v 1.3 2006/05/23 00:48:13 wessels Exp $
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_STORE_NULL_H
#define SQUID_STORE_NULL_H

#include "squid.h"
#include "SwapDir.h"
#include "StoreSearch.h"

class NullSwapDir : public SwapDir
{

public:
    NullSwapDir();
    virtual void init();
    virtual int canStore(StoreEntry const &)const;
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual void parse(int, char*);
    virtual void reconfigure (int, char *);
    virtual StoreSearch *search(String const url, HttpRequest *);
};

class StoreSearchNull : public StoreSearch
{

public:
    StoreSearchNull();
    StoreSearchNull(StoreSearchNull const &);
    ~StoreSearchNull();
    /* Iterator API - garh, wrong place */
    /* callback the client when a new StoreEntry is available
     * or an error occurs 
     */
    virtual void next(void (callback)(void *cbdata), void *cbdata);
    /* return true if a new StoreEntry is immediately available */
    virtual bool next();
    virtual bool error() const;
    virtual bool isDone() const;
    virtual StoreEntry *currentItem();

private:
    CBDATA_CLASS2(StoreSearchNull);
};

#endif /* SQUID_STORE_NULL_H */
