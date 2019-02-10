/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#include "squid.h"
#include "cbdata.h"
#include "StoreSearchUFS.h"
#include "UFSSwapDir.h"

CBDATA_NAMESPACED_CLASS_INIT(Fs::Ufs,StoreSearchUFS);

Fs::Ufs::StoreSearchUFS::StoreSearchUFS(RefCount<UFSSwapDir> aSwapDir) :
    sd(aSwapDir),
    walker(sd->repl->WalkInit(sd->repl)),
    cbdata(NULL),
    current(NULL),
    _done(false)
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

