/*
 * $Id$
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
#ifndef SQUID_STOREFSUFS_H
#define SQUID_STOREFSUFS_H

/**
 \defgroup UFS	UFS Storage Filesystem
 \ingroup FileSystems
 */

class DiskIOModule;

#include "StoreFileSystem.h"

/**
 \ingroup UFS, FileSystems
 *
 * Core UFS class. This template provides compile time aliases for
 * ufs/aufs/diskd to ease configuration conversion - each becomes a
 * StoreFS module whose createSwapDir method parameterises the common
 * UFSSwapDir with an IO module instance.
 */
template <class TheSwapDir>
class StoreFSufs : public StoreFileSystem
{

public:
    static StoreFileSystem &GetInstance();
    StoreFSufs(char const *DefaultModuleType, char const *label);
    virtual ~StoreFSufs() {}

    virtual char const *type() const;
    virtual SwapDir *createSwapDir();
    virtual void done();
    virtual void setup();
    /** Not implemented */
    StoreFSufs (StoreFSufs const &);
    StoreFSufs &operator=(StoreFSufs const &);

protected:
    DiskIOModule *IO;
    char const *moduleName;
    char const *label;
};

template <class C>
StoreFSufs<C>::StoreFSufs(char const *defaultModuleName, char const *aLabel) : IO(NULL), moduleName(defaultModuleName), label(aLabel)
{
    FsAdd(*this);
}

template <class C>
char const *
StoreFSufs<C>::type() const
{
    return label;
}

template <class C>
SwapDir *
StoreFSufs<C>::createSwapDir()
{
    C *result = new C(type(), moduleName);
    return result;
}

template <class C>
void
StoreFSufs<C>::done()
{
    initialised = false;
}

template <class C>
void
StoreFSufs<C>::setup()
{
    assert(!initialised);
    initialised = true;
}

#endif /* SQUID_STOREFSUFS_H */
