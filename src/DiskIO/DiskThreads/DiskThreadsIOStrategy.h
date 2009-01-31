
/*
 * $Id$
 *
 * DEBUG: section 79    Squid-side Disk I/O functions.
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

#ifndef __STORE_DISKTHREADEDIOSTRATEGY_H__
#define __STORE_DISKTHREADEDIOSTRATEGY_H__

#define _AIO_OPEN	0
#define _AIO_READ	1
#define _AIO_WRITE	2
#define _AIO_CLOSE	3
#define _AIO_UNLINK	4
#define _AIO_OPENDIR	5
#define _AIO_STAT	6
#include "DiskIO/DiskIOStrategy.h"

class DiskThreadsIOStrategy : public DiskIOStrategy
{

public:
    DiskThreadsIOStrategy();
    virtual bool shedLoad();
    virtual int load();
    virtual RefCount<DiskFile> newFile(char const *path);
    virtual void unlinkFile (char const *);
    virtual int callback();
    virtual void sync();
    virtual void init();
    void done();
    /* Todo: add access limitations */
    bool initialised;
    static DiskThreadsIOStrategy Instance;
    MemAllocator *squidaio_ctrl_pool;

private:
    static void aioStats(StoreEntry * sentry);
    void registerWithCacheManager(void);
};

#endif
