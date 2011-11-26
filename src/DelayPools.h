/*
 * $Id$
 *
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */
#ifndef SQUID_DELAYPOOLS_H
#define SQUID_DELAYPOOLS_H

/**
 \defgroup DelayPoolsAPI Delay Pools API
 \ingroup Components
 */

/// \ingroup DelayPoolsAPI
class Updateable
{

public:
    virtual ~Updateable() {}

    virtual void update(int) = 0;
};

/* forward decls */
class DelayPool;
class Updateable;
class StoreEntry;

/* for Vector<> */
#include "Array.h"

/// \ingroup DelayPoolsAPI
class DelayPools
{

public:
    static void Init();
    static void Update(void *);
    static unsigned short pools();
    static void pools(unsigned short pools);
    static void FreePools();
    static unsigned char *DelayClasses();
    static void registerForUpdates(Updateable *);
    static void deregisterForUpdates (Updateable *);
    static long MemoryUsed;
    static DelayPool *delay_data;

private:
    static void Stats(StoreEntry *);
    static void InitDelayData();
    static time_t LastUpdate;
    static unsigned short pools_;
    static void FreeDelayData ();
    static Vector<Updateable *> toUpdate;
    static void RegisterWithCacheManager(void);
};

#endif /* SQUID_DELAYPOOLS_H */
