
/*
 * $Id: DiskIOModule.h,v 1.3 2006/09/14 00:51:10 robertc Exp $
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

#ifndef SQUID_DISKIOMODULE_H
#define SQUID_DISKIOMODULE_H

#include "squid.h"
#include "Array.h"

/* forward decls */

class CacheManager;

class DiskIOStrategy;

class DiskIOModule
{

public:
    static void RegisterAllModulesWithCacheManager(CacheManager & manager);
    static void SetupAllModules();
    static void ModuleAdd(DiskIOModule &);
    static void FreeAllModules();
    static DiskIOModule *Find(char const *type);
    /* find *any* usable disk module. This will look for the 'best' 
     * available module for this system.
     */
    static DiskIOModule *FindDefault();
    static Vector<DiskIOModule*> const &Modules();
    typedef Vector<DiskIOModule*>::iterator iterator;
    typedef Vector<DiskIOModule*>::const_iterator const_iterator;
    DiskIOModule();
    virtual ~DiskIOModule(){}

    virtual void init() = 0;
    virtual void registerWithCacheManager(CacheManager & manager);
    virtual void shutdown() = 0;
    virtual DiskIOStrategy *createStrategy() = 0;

    virtual char const *type () const = 0;
    // Not implemented
    DiskIOModule(DiskIOModule const &);
    DiskIOModule &operator=(DiskIOModule const&);

protected:
    //bool initialised;

private:
    static Vector<DiskIOModule*> &GetModules();
    static Vector<DiskIOModule*> *_Modules;
};


#endif /* SQUID_DISKIOMODULE_H */
