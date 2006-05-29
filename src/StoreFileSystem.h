
/*
 * $Id: StoreFileSystem.h,v 1.2 2006/05/29 00:15:01 robertc Exp $
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

#ifndef SQUID_STOREFILESYSTEM_H
#define SQUID_STOREFILESYSTEM_H

#include "squid.h"
#include "Array.h"

/* forward decls */

class CacheManager;

class StoreFileSystem
{

public:
    static void RegisterAllFsWithCacheManager(CacheManager & manager);
    static void SetupAllFs();
    static void FsAdd(StoreFileSystem &);
    static void FreeAllFs();
    static Vector<StoreFileSystem*> const &FileSystems();
    typedef Vector<StoreFileSystem*>::iterator iterator;
    typedef Vector<StoreFileSystem*>::const_iterator const_iterator;
    StoreFileSystem() : initialised (false) {}

    virtual ~StoreFileSystem(){}

    virtual char const *type () const = 0;
    virtual SwapDir *createSwapDir() = 0;
    virtual void done() = 0;
    virtual void registerWithCacheManager(CacheManager & manager);
    virtual void setup() = 0;
    // Not implemented
    StoreFileSystem(StoreFileSystem const &);
    StoreFileSystem &operator=(StoreFileSystem const&);

protected:
    bool initialised;

private:
    static Vector<StoreFileSystem*> &GetFileSystems();
    static Vector<StoreFileSystem*> *_FileSystems;
};

typedef StoreFileSystem storefs_entry_t;


#endif /* SQUID_STOREFILESYSTEM_H */
