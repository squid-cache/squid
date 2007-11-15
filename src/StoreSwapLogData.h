
/*
 * $Id: StoreSwapLogData.h,v 1.5 2007/11/15 16:47:35 wessels Exp $
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

#ifndef SQUID_STORESWAPLOGDATA_H
#define SQUID_STORESWAPLOGDATA_H

#include "squid.h"

/*
 * Do we need to have the dirn in here? I don't think so, since we already
 * know the dirn .. 
 */
/* Binary format on disk.
 * DO NOT randomly alter.
 * DO NOT add ANY virtual's.
 */

class StoreSwapLogData
{

public:
    MEMPROXY_CLASS(StoreSwapLogData);
    StoreSwapLogData();
    char op;
    sfileno swap_filen;
    time_t timestamp;
    time_t lastref;
    time_t expires;
    time_t lastmod;
    uint64_t swap_file_sz;
    u_short refcount;
    u_short flags;
    unsigned char key[SQUID_MD5_DIGEST_LENGTH];
};

MEMPROXY_CLASS_INLINE(StoreSwapLogData)

class StoreSwapLogHeader
{
public:
     StoreSwapLogHeader();
     char op;
     int version;
     int record_size;
};


#endif /* SQUID_STORESWAPLOGDATA_H */
