/*
 *
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
#include "DiskIOModule.h"

Vector<DiskIOModule*> *DiskIOModule::_Modules = NULL;

//DiskIOModule() : initialised (false) {}

DiskIOModule::DiskIOModule()
{
    /** We cannot call ModuleAdd(*this)
     * here as the virtual methods are not yet available.
     * We leave that to PokeAllModules() later.
     */
}

void
DiskIOModule::SetupAllModules()
{
    DiskIOModule::PokeAllModules();

    for (iterator i = GetModules().begin(); i != GetModules().end(); ++i)
        /* Call the FS to set up capabilities and initialize the FS driver */
        (*i)->init();
}

void
DiskIOModule::ModuleAdd(DiskIOModule &instance)
{
    iterator i = GetModules().begin();

    while (i != GetModules().end()) {
        assert(strcmp((*i)->type(), instance.type()) != 0);
        ++i;
    }

    GetModules().push_back (&instance);
}

Vector<DiskIOModule *> const &
DiskIOModule::Modules()
{
    return GetModules();
}

Vector<DiskIOModule*> &
DiskIOModule::GetModules()
{
    if (!_Modules)
        _Modules = new Vector<DiskIOModule *>;

    return *_Modules;
}

/**
 * Called when a graceful shutdown is to occur
 * of each fs module.
 */
void
DiskIOModule::FreeAllModules()
{
    while (GetModules().size()) {
        DiskIOModule *fs = GetModules().back();
        GetModules().pop_back();
        fs->shutdown();
    }
}

DiskIOModule *
DiskIOModule::Find(char const *type)
{
    for (iterator i = GetModules().begin(); i != GetModules().end(); ++i)
        if (strcasecmp(type, (*i)->type()) == 0)
            return *i;

    return NULL;
}

DiskIOModule *
DiskIOModule::FindDefault()
{
    /** Best IO options are in order: */
    DiskIOModule * result;
    result = Find("DiskThreads");
    if (NULL == result)
        result = Find("DiskDaemon");
    if (NULL == result)
        result = Find("AIO");
    if (NULL == result)
        result = Find("Blocking");
    return result;
}
