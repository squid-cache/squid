/*
 * DEBUG: section 47    Store Directory Routines
 * AUTHOR: Robert Collins
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

#include "squid.h"
#include "cbdata.h"
#include "StoreSearchUFS.h"
#include "UFSSwapDir.h"

CBDATA_NAMESPACED_CLASS_INIT(Fs::Ufs,StoreSearchUFS);

Fs::Ufs::StoreSearchUFS::StoreSearchUFS(RefCount<UFSSwapDir> aSwapDir) :
        sd(aSwapDir), walker (sd->repl->WalkInit(sd->repl)),
        current (NULL), _done (false)
{}

Fs::Ufs::StoreSearchUFS::~StoreSearchUFS()
{
    walker->Done(walker);
    walker = NULL;
}

void
Fs::Ufs::StoreSearchUFS::next(void (aCallback)(void *cbdata), void *aCallbackArgs)
{
    next();
    aCallback(aCallbackArgs);
}

bool
Fs::Ufs::StoreSearchUFS::next()
{
    /* the walker API doesn't make sense. the store entries referred to are already readwrite
     * from their hash table entries
     */

    if (walker)
        current = const_cast<StoreEntry *>(walker->Next(walker));

    if (current == NULL)
        _done = true;

    return current != NULL;
}

bool
Fs::Ufs::StoreSearchUFS::error() const
{
    return false;
}

bool
Fs::Ufs::StoreSearchUFS::isDone() const
{
    return _done;
}

StoreEntry *
Fs::Ufs::StoreSearchUFS::currentItem()
{
    return current;
}
