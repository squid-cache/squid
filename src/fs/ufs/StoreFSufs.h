
/*
 * $Id: StoreFSufs.h,v 1.1 2003/07/22 15:23:14 robertc Exp $
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

#include "squid.h"

class IOModule;

template <class TheSwapDir>

class StoreFSufs : public StoreFileSystem
{

public:
    static StoreFileSystem &GetInstance();
    StoreFSufs(IOModule &, char const *label);
    virtual ~StoreFSufs() {}

    virtual char const *type() const;
    virtual SwapDir *createSwapDir();
    virtual void done();
    virtual void setup();
    /* Not implemented */
    StoreFSufs (StoreFSufs const &);
    StoreFSufs &operator=(StoreFSufs const &);

protected:
    IOModule &IO;
    char const *label;
};

template <class C>
StoreFSufs<C>::StoreFSufs(IOModule &anIO, char const *aLabel) : IO(anIO), label(aLabel)
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
    C *result = new C(type());
    result->IO = IO.createSwapDirIOStrategy();
    return result;
}

template <class C>
void
StoreFSufs<C>::done()
{
    IO.shutdown();
    initialised = false;
}

template <class C>
void
StoreFSufs<C>::setup()
{
    assert(!initialised);
    initialised = true;
    IO.init();
}

#endif /* SQUID_STOREFSUFS_H */
