
/*
 * DEBUG: section 92    Storage File System
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "StoreFileSystem.h"

Vector<StoreFileSystem*> *StoreFileSystem::_FileSystems = NULL;

void
StoreFileSystem::RegisterAllFsWithCacheManager(void)
{
    for (iterator i = GetFileSystems().begin(); i != GetFileSystems().end(); ++i)
        (*i)->registerWithCacheManager();
}

void
StoreFileSystem::SetupAllFs()
{
    for (iterator i = GetFileSystems().begin(); i != GetFileSystems().end(); ++i)
        /* Call the FS to set up capabilities and initialize the FS driver */
        (*i)->setup();
}

void
StoreFileSystem::FsAdd(StoreFileSystem &instance)
{
    iterator i = GetFileSystems().begin();

    while (i != GetFileSystems().end()) {
        assert(strcmp((*i)->type(), instance.type()) != 0);
        ++i;
    }

    GetFileSystems().push_back (&instance);
}

Vector<StoreFileSystem *> const &
StoreFileSystem::FileSystems()
{
    return GetFileSystems();
}

Vector<StoreFileSystem*> &
StoreFileSystem::GetFileSystems()
{
    if (!_FileSystems)
        _FileSystems = new Vector<StoreFileSystem *>;

    return *_FileSystems;
}

/*
 * called when a graceful shutdown is to occur
 * of each fs module.
 */
void
StoreFileSystem::FreeAllFs()
{
    while (GetFileSystems().size()) {
        StoreFileSystem *fs = GetFileSystems().back();
        GetFileSystems().pop_back();
        fs->done();
    }
}

/* no filesystem is required to export statistics */
void
StoreFileSystem::registerWithCacheManager(void)
{}
