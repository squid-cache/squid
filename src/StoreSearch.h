
/*
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

#ifndef SQUID_STORESEARCH_H
#define SQUID_STORESEARCH_H

#include "RefCount.h"
#include "Store.h"

class StoreSearch : public RefCountable
{

public:
    StoreSearch() {}

    StoreSearch(StoreSearch const &); /* no implementation - trigger link failures */
    virtual ~StoreSearch() {}

    /* not ready yet
    void asList(void (*) (CbDataList<StoreEntryPointer), void *cbdata);
    */
    /* callback the client when a new StoreEntry is available
     * or an error occurs
     */
    virtual void next(void (callback)(void *cbdata), void *cbdata) = 0;
    /* return true if a new StoreEntry is immediately available
     * ???- not decided - if false, trigger making a new one available
     * this would be for sync api users that will schedule their own callback
     * to try again later. so if that next() has to allow multiple
     * calls being made to it without error
     */
    virtual bool next() = 0;
    virtual bool error() const = 0;
    virtual bool isDone() const = 0;
    virtual StoreEntry *currentItem() = 0;
};

typedef RefCount<StoreSearch> StoreSearchPointer;

#endif /* SQUID_STORESEARCH_H */
