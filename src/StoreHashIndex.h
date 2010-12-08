
/*
 * $Id$
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

#ifndef SQUID_STOREHASHINDEX_H
#define SQUID_STOREHASHINDEX_H

#include "Store.h"
#include "StoreSearch.h"

/* A summary store that indexs all its children
 * into a memory hash
 */

class StoreSearch;

class StoreHashIndex : public Store
{

public:
    StoreHashIndex();
    StoreHashIndex(StoreHashIndex const &); /* to cause link failures */
    virtual ~StoreHashIndex();
    virtual int callback();
    virtual void create();

    virtual StoreEntry * get
    (const cache_key *);

    virtual void get
    (String const, STOREGETCLIENT, void * cbdata);

    virtual void init();

    virtual void sync();

    virtual uint64_t maxSize() const;

    virtual uint64_t minSize() const;

    virtual void stat(StoreEntry&) const;

    virtual void reference(StoreEntry&);

    virtual void dereference(StoreEntry&);

    virtual void maintain();

    virtual void updateSize(int64_t, int);

    virtual StoreSearch *search(String const url, HttpRequest *);

private:
    /* migration logic */
    StorePointer store(int const x) const;
};

class StoreHashIndexEntry : public StoreEntry
    {};

class StoreSearchHashIndex : public StoreSearch
{

public:
    StoreSearchHashIndex(RefCount<StoreHashIndex> sd);
    StoreSearchHashIndex(StoreSearchHashIndex const &);
    virtual ~StoreSearchHashIndex();
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

    RefCount<StoreHashIndex> sd;

private:
    void copyBucket();
    void (*callback)(void *cbdata);
    void *cbdata;
    bool _done;
    int bucket;
    Vector<StoreEntry *> entries;

    // keep this last. it plays with private/public
    CBDATA_CLASS2(StoreSearchHashIndex);
};

#endif /* SQUID_STOREHASHINDEX_H */
