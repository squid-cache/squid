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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_AIODISKIOSTRATEGY_H
#define SQUID_AIODISKIOSTRATEGY_H

#if USE_DISKIO_AIO

#include "DiskIO/DiskIOStrategy.h"
#include "async_io.h"

class AIODiskIOStrategy : public DiskIOStrategy
{

public:
    AIODiskIOStrategy();
    virtual ~AIODiskIOStrategy();

    virtual bool shedLoad();
    /* What is the current load? 999 = 99.9% */
    virtual int load();
    /* Return a handle for performing IO operations */
    virtual RefCount<DiskFile> newFile (char const *path);
    /* flush all IO operations  */
    virtual void sync();
    /** whether the IO Strategy can use unlinkd */
    virtual bool unlinkdUseful() const;
    /* unlink a file by path */
    virtual void unlinkFile (char const *);

    /* perform any pending callbacks */
    virtual int callback();

    /* Init per-instance logic */
    virtual void init();

    /* cachemgr output on the IO instance stats */
    virtual void statfs(StoreEntry & sentry)const;
    /* module specific options */
    virtual ConfigOption *getOptionTree() const;
    /* a file descriptor */
    int fd;
    /* queue of requests */
    async_queue_t aq;

    int findSlot();
};

#endif /* USE_DISKIO_AIO */
#endif /* SQUID_AIODISKIOSTRATEGY_H */
