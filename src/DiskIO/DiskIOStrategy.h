
/*
 * $Id: DiskIOStrategy.h,v 1.1 2004/12/20 16:30:38 robertc Exp $
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
 * Copyright (c) 2003 Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_DISKIOSTRATEGY_H
#define SQUID_DISKIOSTRATEGY_H

#include "squid.h"

#include "RefCount.h"

class DiskFile;

class ConfigOption;

class DiskIOStrategy
{

public:
    virtual ~DiskIOStrategy(){}

    /* Can the IO Strategy handle more requests ? */
    virtual bool shedLoad() = 0;
    /* What is the current load? 999 = 99.9% */
    virtual int load() = 0;
    /* Return a handle for performing IO operations */
    virtual RefCount<DiskFile> newFile (char const *path) = 0;
    /* flush all IO operations  */
    virtual void sync() {}

    /* unlink a file by path */
    virtual void unlinkFile (char const *) = 0;

    /* perform any pending callbacks */
    virtual int callback() { return 0; }

    /* Init per-instance logic */
    virtual void init() {}

    /* cachemgr output on the IO instance stats */
    virtual void statfs(StoreEntry & sentry)const {}

    /* module specific options */
    virtual ConfigOption *getOptionTree() const { return NULL;}
};

/* Because we need the DiskFile definition for newFile. */
#include "DiskFile.h"

class SingletonIOStrategy : public DiskIOStrategy
{

public:
    SingletonIOStrategy(DiskIOStrategy *anIO) : io(anIO){}

    virtual bool shedLoad() { return io->shedLoad(); }

    virtual int load() { return io->load(); }

    virtual RefCount<DiskFile> newFile (char const *path) {return io->newFile(path); }

    virtual void sync() { io->sync(); }

    virtual void unlinkFile (char const *path) { io->unlinkFile(path); }

    virtual int callback() { return io->callback(); }

    virtual void init() { io->init(); }

    virtual void statfs(StoreEntry & sentry)const { io->statfs(sentry); }

    virtual ConfigOption *getOptionTree() const { return io->getOptionTree(); }

private:
    DiskIOStrategy *io;
};

#endif /* SQUID_DISKIOSTRATEGY_H */
