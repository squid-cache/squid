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
#ifndef SQUID_STOREFSCOSS_H
#define SQUID_STOREFSCOSS_H

class StoreEntry;

/**
 \defgroup COSS COSS Storage Filesystem
 \ingroup FileSystems
 */

/// \ingroup COSS
class CossStats
{

public:
    void stat(StoreEntry * sentry);
    int stripes;

    struct {
        int alloc;
        int realloc;
        int collisions;
    } alloc;
    int disk_overflows;
    int stripe_overflows;
    int open_mem_hits;
    int open_mem_misses;

    struct {
        int ops;
        int success;
        int fail;
    }

    open, create, close, unlink, read, write, stripe_write;
};

class CacheManager;

#include "StoreFileSystem.h"

/// \ingroup COSS, FileSystems
class StoreFScoss : public StoreFileSystem
{

public:
    static StoreFScoss &GetInstance();
    static void Stats(StoreEntry * sentry);
    StoreFScoss();
    virtual ~StoreFScoss() {}

    virtual char const *type() const;
    virtual SwapDir *createSwapDir();
    virtual void done();
    virtual void registerWithCacheManager(void);
    virtual void setup();
    /* Not implemented */
    StoreFScoss (StoreFScoss const &);
    StoreFScoss &operator=(StoreFScoss const &);
    void stat(StoreEntry * sentry);
    CossStats stats;

private:
    static StoreFScoss _instance;
};

#endif /* SQUID_STOREFSCOSS_H */
